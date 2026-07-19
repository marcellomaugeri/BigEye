"""Bounded, repeatable startup probes for prepared fuzz targets."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import PurePosixPath
from typing import Protocol

from backend.fuzzing.docker.container_runner import ContainerTimedOut


_RESULT_PREFIX = "BIGEYE_PROBE_RESULT="
_INPUT_ROLES = frozenset({"empty", "minimum", "seed"})
_SHELL_NAMES = frozenset({"sh", "bash", "dash", "zsh", "env"})
_MAX_COMMAND_PARTS = 64
_MAX_COMMAND_PART_CHARS = 4_096
_MAX_SANITIZER_CHARS = 32_768
_SANITIZER_MARKERS = (
    "AddressSanitizer", "UndefinedBehaviorSanitizer", "MemorySanitizer",
    "ThreadSanitizer", "LeakSanitizer", "runtime error:",
)


@dataclass(frozen=True)
class ProbeInvocation:
    """One application-owned argv invocation for a contained probe input."""

    name: str
    role: str
    command: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 500:
            raise ValueError("probe input name is invalid")
        if self.role not in _INPUT_ROLES:
            raise ValueError("probe input role is invalid")
        if (
            not isinstance(self.command, tuple)
            or not 1 <= len(self.command) <= _MAX_COMMAND_PARTS
            or any(
                not isinstance(part, str) or not part or "\x00" in part or len(part) > _MAX_COMMAND_PART_CHARS
                for part in self.command
            )
        ):
            raise ValueError("probe command is invalid")
        executable = PurePosixPath(self.command[0])
        if (
            not executable.is_absolute()
            or executable.name.casefold() in _SHELL_NAMES
            or any(part in {"", ".", ".."} for part in executable.parts)
            or executable.parts[:3] != ("/", "opt", "bigeye")
        ):
            raise ValueError("probe executable must be a contained BigEye target")


@dataclass(frozen=True)
class ProbeInputEvidence:
    """Exact supervised evidence retained for one logical input."""

    name: str
    role: str
    exit_code: int | None
    alive: bool
    accepts_input: bool
    deterministic: bool
    project_lines: int
    harness_lines: int
    startup_lines: int
    immediate_crash: bool
    timed_out: bool
    sanitizer_output: str
    invalid_api_use: bool
    replayed_immediate_crash: bool

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or len(self.name) > 500:
            raise ValueError("probe evidence name is invalid")
        if self.role not in _INPUT_ROLES:
            raise ValueError("probe evidence role is invalid")
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise ValueError("probe exit code is invalid")
        for field in (
            "alive", "accepts_input", "deterministic", "immediate_crash", "timed_out",
            "invalid_api_use", "replayed_immediate_crash",
        ):
            if type(getattr(self, field)) is not bool:
                raise ValueError(f"probe {field} evidence is invalid")
        for field in ("project_lines", "harness_lines", "startup_lines"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"probe {field} evidence is invalid")
        if not isinstance(self.sanitizer_output, str) or len(self.sanitizer_output) > _MAX_SANITIZER_CHARS:
            raise ValueError("probe sanitizer output is invalid")


@dataclass(frozen=True)
class ProbeEvidence:
    """Aggregate facts used by the deterministic startup gate."""

    inputs: tuple[ProbeInputEvidence, ...]
    exit_codes: tuple[int | None, ...]
    alive: bool
    accepts_input: bool
    deterministic: bool
    project_lines: int
    harness_lines: int
    startup_lines: int
    immediate_crash: bool
    timed_out: bool
    sanitizer_output: str
    replayed_immediate_crash: bool
    seed_independent_crash: bool
    invalid_api_use: bool

    @classmethod
    def from_inputs(cls, inputs) -> "ProbeEvidence":
        values = tuple(inputs)
        if not values or any(not isinstance(item, ProbeInputEvidence) for item in values):
            raise ValueError("probe evidence requires input results")
        sanitizer = "\n".join(
            value for value in dict.fromkeys(item.sanitizer_output for item in values) if value
        )[:_MAX_SANITIZER_CHARS]
        crashes = tuple(item for item in values if item.immediate_crash)
        seeds = tuple(item for item in values if item.role == "seed")
        return cls(
            inputs=values,
            exit_codes=tuple(item.exit_code for item in values),
            alive=all(item.alive for item in values),
            accepts_input=bool(seeds) and any(item.accepts_input for item in seeds),
            deterministic=all(item.deterministic for item in values),
            project_lines=max(item.project_lines for item in values),
            harness_lines=max(item.harness_lines for item in values),
            startup_lines=max(item.startup_lines for item in values),
            immediate_crash=bool(crashes),
            timed_out=any(item.timed_out for item in values),
            sanitizer_output=sanitizer,
            replayed_immediate_crash=bool(crashes) and all(item.replayed_immediate_crash for item in crashes),
            seed_independent_crash=any(item.immediate_crash and item.role != "seed" for item in values),
            invalid_api_use=any(item.invalid_api_use for item in values),
        )


@dataclass(frozen=True)
class ProbeAcceptance:
    accepted: bool
    reason: str


class ProbePolicy:
    """Accept only a deterministic target that reaches real project code."""

    @staticmethod
    def accept(evidence: ProbeEvidence) -> ProbeAcceptance:
        if not isinstance(evidence, ProbeEvidence):
            raise TypeError("probe policy requires ProbeEvidence")
        if evidence.timed_out:
            return ProbeAcceptance(False, "the supervised probe timed out")
        if not evidence.alive:
            return ProbeAcceptance(False, "the target did not remain healthy through supervised startup")
        if not evidence.accepts_input:
            return ProbeAcceptance(False, "the target did not accept a real seed input")
        if not evidence.deterministic:
            return ProbeAcceptance(False, "the target did not produce deterministic probe evidence")
        if evidence.invalid_api_use:
            return ProbeAcceptance(False, "the harness violates the observed API contract")
        accepted_seeds = tuple(
            item for item in evidence.inputs if item.role == "seed" and item.accepts_input
        )
        if not any(item.project_lines > 0 for item in accepted_seeds):
            return ProbeAcceptance(False, "the accepted real seed did not reach project code")
        if any(item.exit_code != 0 and not item.immediate_crash for item in evidence.inputs):
            return ProbeAcceptance(False, "a noncrashing probe input returned a failing exit code")
        if evidence.sanitizer_output:
            return ProbeAcceptance(False, "the supervised probe produced sanitizer output")
        if evidence.project_lines <= 0:
            return ProbeAcceptance(False, "the probe reached harness or startup code but no project code")
        if evidence.immediate_crash and not evidence.replayed_immediate_crash:
            return ProbeAcceptance(False, "an immediate crash must be replayed before the target can be accepted")
        if evidence.seed_independent_crash:
            return ProbeAcceptance(False, "the target has a seed-independent harness or startup crash")
        return ProbeAcceptance(True, "the target accepts a real seed and reaches project code reproducibly")


class _PreparedTarget(Protocol):
    image: str
    probe_invocations: tuple[ProbeInvocation, ...]


class ProbeService:
    """Run every input twice through the existing bounded container runner."""

    def __init__(self, runner, timeout_seconds: float = 10.0, sink=None):
        if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 60:
            raise ValueError("probe timeout must be a float between 0 and 60 seconds")
        self._runner = runner
        self._timeout = timeout_seconds
        self._sink = sink or (lambda _text: None)

    async def run(self, prepared_target: _PreparedTarget) -> ProbeEvidence:
        image = getattr(prepared_target, "image", None)
        invocations = getattr(prepared_target, "probe_invocations", None)
        if (
            not isinstance(image, str)
            or not image.startswith("sha256:")
            or len(image) != 71
            or any(character not in "0123456789abcdef" for character in image[7:])
            or not isinstance(invocations, tuple)
        ):
            raise ValueError("prepared target probe contract is invalid")
        if any(not isinstance(item, ProbeInvocation) for item in invocations):
            raise ValueError("prepared target contains an invalid probe invocation")
        roles = {item.role for item in invocations}
        if not {"empty", "minimum", "seed"}.issubset(roles):
            raise ValueError("prepared target requires empty, minimum, and real seed probes")
        if len(invocations) > 34 or len({item.name for item in invocations}) != len(invocations):
            raise ValueError("prepared target probe inputs are outside their bound")

        evidence = []
        for invocation in invocations:
            first = await self._run_once(image, invocation)
            replay = await self._run_once(image, invocation)
            deterministic = self._signature(first) == self._signature(replay)
            replayed_crash = first.immediate_crash and deterministic and replay.immediate_crash
            evidence.append(replace(
                first,
                deterministic=deterministic,
                replayed_immediate_crash=replayed_crash,
            ))
        return ProbeEvidence.from_inputs(evidence)

    async def _run_once(self, image: str, invocation: ProbeInvocation) -> ProbeInputEvidence:
        try:
            result = await self._runner.run(
                image, list(invocation.command), self._timeout, self._sink,
            )
        except ContainerTimedOut:
            return ProbeInputEvidence(
                invocation.name, invocation.role, None, False, False, True,
                0, 0, 0, False, True, "", False, False,
            )
        return self._parse(invocation, result.exit_code, result.output)

    @staticmethod
    def _parse(invocation: ProbeInvocation, exit_code: int, output: str) -> ProbeInputEvidence:
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError("bounded probe returned an invalid exit code")
        if not isinstance(output, str):
            raise ValueError("bounded probe returned non-text output")
        records = [line[len(_RESULT_PREFIX):] for line in output.splitlines() if line.startswith(_RESULT_PREFIX)]
        if len(records) != 1:
            sanitizer = output[-_MAX_SANITIZER_CHARS:]
            return ProbeInputEvidence(
                invocation.name, invocation.role, exit_code, False, False, True,
                0, 0, 0, exit_code != 0, False, sanitizer, False, False,
            )
        try:
            value = json.loads(records[0])
        except json.JSONDecodeError as error:
            raise ValueError("probe result record is invalid JSON") from error
        if not isinstance(value, dict) or set(value) != {
            "alive", "accepted_input", "project_lines", "harness_lines", "startup_lines",
            "immediate_crash", "invalid_api_use", "sanitizer_output",
        }:
            raise ValueError("probe result record has an invalid shape")
        for field in ("alive", "accepted_input", "immediate_crash", "invalid_api_use"):
            if type(value[field]) is not bool:
                raise ValueError(f"probe result {field} is invalid")
        for field in ("project_lines", "harness_lines", "startup_lines"):
            if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] < 0:
                raise ValueError(f"probe result {field} is invalid")
        sanitizer = value["sanitizer_output"]
        if not isinstance(sanitizer, str) or len(sanitizer) > _MAX_SANITIZER_CHARS:
            raise ValueError("probe result sanitizer output is invalid")
        external_sanitizer = "\n".join(
            line for line in output.splitlines()
            if not line.startswith(_RESULT_PREFIX) and any(marker in line for marker in _SANITIZER_MARKERS)
        )
        sanitizer = "\n".join(
            part for part in dict.fromkeys((sanitizer, external_sanitizer)) if part
        )[:_MAX_SANITIZER_CHARS]
        return ProbeInputEvidence(
            invocation.name,
            invocation.role,
            exit_code,
            value["alive"],
            value["accepted_input"],
            True,
            value["project_lines"],
            value["harness_lines"],
            value["startup_lines"],
            value["immediate_crash"],
            False,
            sanitizer,
            value["invalid_api_use"],
            False,
        )

    @staticmethod
    def _signature(value: ProbeInputEvidence) -> tuple:
        return (
            value.exit_code, value.alive, value.accepts_input, value.project_lines,
            value.harness_lines, value.startup_lines, value.immediate_crash,
            value.timed_out, value.sanitizer_output, value.invalid_api_use,
        )
