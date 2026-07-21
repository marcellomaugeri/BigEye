"""Application-observed target probes joined to attested clean coverage."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Protocol

from backend.fuzzing.campaigns.coverage_contract import valid_replay_environment
from backend.fuzzing.docker.container_runner import ContainerTimedOut


_INPUT_ROLES = frozenset({"empty", "minimum", "seed"})
_SHELL_NAMES = frozenset({"sh", "bash", "dash", "zsh", "env"})
_SANITIZER_MARKERS = (
    "AddressSanitizer", "UndefinedBehaviorSanitizer", "MemorySanitizer",
    "ThreadSanitizer", "LeakSanitizer", "runtime error:",
)
_SIGNAL_EXIT_CODES = frozenset({128 + value for value in range(1, 32)})
_MAX_COMMAND_PARTS = 64
_MAX_COMMAND_PART_CHARS = 4_096
_MAX_TESTCASE_BYTES = 16 * 1024 * 1024
_MAX_SANITIZER_CHARS = 32_768
_MAX_COVERAGE_LINES = 1_000_000


def _exact_image_id(value: str, name: str) -> str:
    if (
        not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{name} is not an exact image ID")
    return value


def _hex(value: str, lengths: set[int], name: str) -> str:
    if not isinstance(value, str) or len(value) not in lengths or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(f"{name} is invalid")
    return value


@dataclass(frozen=True)
class ProbeInvocation:
    """One application-owned argv invocation for a contained probe input."""

    name: str
    role: str
    command: tuple[str, ...]
    testcase_bytes: bytes = field(repr=False)
    testcase_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 500:
            raise ValueError("probe input name is invalid")
        if self.role not in _INPUT_ROLES:
            raise ValueError("probe input role is invalid")
        if (
            not isinstance(self.command, tuple) or not 1 <= len(self.command) <= _MAX_COMMAND_PARTS
            or any(
                not isinstance(part, str) or not part or "\x00" in part or len(part) > _MAX_COMMAND_PART_CHARS
                for part in self.command
            )
        ):
            raise ValueError("probe command is invalid")
        markers = self.command.count("{input}") + self.command.count("{stdin}")
        if (
            markers > 1
            or any(
                marker in part and part != marker
                for part in self.command for marker in ("{input}", "{stdin}")
            )
            or ("{stdin}" in self.command and self.command[-1] != "{stdin}")
        ):
            raise ValueError("probe command input marker is invalid")
        executable = PurePosixPath(self.command[0])
        if (
            not executable.is_absolute() or executable.name.casefold() in _SHELL_NAMES
            or any(part in {"", ".", ".."} for part in executable.parts)
            or executable.parts[:3] != ("/", "opt", "bigeye")
        ):
            raise ValueError("probe executable must be a contained BigEye target")
        if not isinstance(self.testcase_bytes, bytes) or len(self.testcase_bytes) > _MAX_TESTCASE_BYTES:
            raise ValueError("probe testcase bytes are invalid")
        object.__setattr__(self, "testcase_sha256", sha256(self.testcase_bytes).hexdigest())


def _probe_file_input_path(invocation: ProbeInvocation) -> str:
    if invocation.role == "empty":
        if invocation.name != "empty":
            raise ValueError("probe file input path is invalid")
        return "/bigeye/target/probe/empty.txt"
    if invocation.role == "minimum":
        if invocation.name != "minimum":
            raise ValueError("probe file input path is invalid")
        return "/bigeye/target/probe/minimum.txt"
    prefix = "seed:"
    if not invocation.name.startswith(prefix):
        raise ValueError("probe file input path is invalid")
    relative = invocation.name[len(prefix):]
    path = PurePosixPath(relative)
    if (
        not relative or "\\" in relative or path.is_absolute()
        or path.as_posix() != relative
        or any(part in {"", ".", ".."} or part.casefold() == ".git" for part in path.parts)
    ):
        raise ValueError("probe file input path is invalid")
    return f"/src/{relative}"


def canonical_probe_replay_command(invocation: ProbeInvocation) -> tuple[str, ...]:
    """Return one durable replay command from an exact application-owned probe input."""

    if not isinstance(invocation, ProbeInvocation):
        raise TypeError("probe replay contract requires a ProbeInvocation")
    command = invocation.command
    if "{stdin}" in command:
        return command
    input_path = _probe_file_input_path(invocation)
    occurrences = command.count(input_path)
    if command.count("{input}") == 1:
        if occurrences:
            raise ValueError("probe replay contract contains duplicate application input paths")
        return command
    if occurrences != 1:
        raise ValueError("probe replay contract requires one exact application input path")
    return tuple("{input}" if part == input_path else part for part in command)


@dataclass(frozen=True)
class CleanCoverageProvenance:
    """Application-attested identity for one exact clean replay."""

    project_id: int
    commit_sha: str
    clean_image_id: str
    testcase_sha256: str

    def __post_init__(self) -> None:
        if type(self.project_id) is not int or self.project_id <= 0:
            raise ValueError("coverage provenance project ID is invalid")
        _hex(self.commit_sha, {40, 64}, "coverage provenance commit")
        _exact_image_id(self.clean_image_id, "coverage provenance image")
        _hex(self.testcase_sha256, {64}, "coverage provenance testcase")


def _coverage_set(values, name: str) -> frozenset[str]:
    if not isinstance(values, frozenset) or len(values) > _MAX_COVERAGE_LINES or any(
        not isinstance(value, str) or not value or len(value) > 2_000 for value in values
    ):
        raise ValueError(f"{name} coverage is invalid")
    return values


@dataclass(frozen=True)
class AttestedCoverage:
    """Coverage measured by BigEye's clean replay, never by generated target output."""

    project_lines: frozenset[str]
    harness_lines: frozenset[str]
    startup_lines: frozenset[str]
    contract_valid: bool
    provenance: CleanCoverageProvenance

    def __post_init__(self) -> None:
        _coverage_set(self.project_lines, "project")
        _coverage_set(self.harness_lines, "harness")
        _coverage_set(self.startup_lines, "startup")
        if type(self.contract_valid) is not bool:
            raise ValueError("clean replay contract evidence is invalid")
        if not isinstance(self.provenance, CleanCoverageProvenance):
            raise ValueError("clean replay provenance is invalid")


@dataclass(frozen=True)
class ProbeProcessObservation:
    """Facts derived from the bounded container result and inspected state."""

    exit_code: int | None
    alive: bool
    timed_out: bool
    immediate_crash: bool
    sanitizer_output: str

    def __post_init__(self) -> None:
        if self.exit_code is not None and (type(self.exit_code) is not int):
            raise ValueError("probe process exit code is invalid")
        for name in ("alive", "timed_out", "immediate_crash"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"probe process {name} is invalid")
        if not isinstance(self.sanitizer_output, str) or len(self.sanitizer_output) > _MAX_SANITIZER_CHARS:
            raise ValueError("probe process sanitizer output is invalid")


class ProbeRunner:
    """Convert bounded Docker outcomes into application-owned process evidence."""

    def __init__(self, bounded_runner):
        self._bounded_runner = bounded_runner

    async def run(
        self,
        image_id: str,
        invocation: ProbeInvocation,
        timeout: float,
        sink,
        replay_environment: tuple[tuple[str, str], ...],
    ) -> ProbeProcessObservation:
        _exact_image_id(image_id, "probe image")
        if not valid_replay_environment(replay_environment):
            raise ValueError("probe replay environment is invalid")
        environment = dict(replay_environment)
        try:
            if "{stdin}" in invocation.command:
                command = [part for part in invocation.command if part != "{stdin}"]
                result = await self._bounded_runner.run(
                    image_id, command, timeout, sink,
                    stdin_bytes=invocation.testcase_bytes,
                    environment=environment,
                )
            elif "{input}" in invocation.command:
                command = [
                    _probe_file_input_path(invocation) if part == "{input}" else part
                    for part in canonical_probe_replay_command(invocation)
                ]
                result = await self._bounded_runner.run(
                    image_id, command, timeout, sink,
                    environment=environment,
                )
            else:
                result = await self._bounded_runner.run(
                    image_id, list(invocation.command), timeout, sink,
                    environment=environment,
                )
        except ContainerTimedOut:
            return ProbeProcessObservation(None, False, True, False, "")
        exit_code = getattr(result, "exit_code", None)
        if type(exit_code) is not int:
            raise ValueError("bounded probe returned an invalid exit code")
        output = getattr(result, "output", None)
        if not isinstance(output, str):
            raise ValueError("bounded probe returned non-text output")
        sanitizer = "\n".join(
            line for line in output.splitlines()
            if any(marker in line for marker in _SANITIZER_MARKERS)
        )[:_MAX_SANITIZER_CHARS]
        oom_killed = getattr(result, "oom_killed", False)
        if type(oom_killed) is not bool:
            raise ValueError("bounded probe returned invalid OOM state")
        state = getattr(result, "state", "exited")
        if not isinstance(state, str):
            raise ValueError("bounded probe returned invalid container state")
        immediate_crash = bool(sanitizer) or oom_killed or exit_code < 0 or exit_code in _SIGNAL_EXIT_CODES
        alive = not immediate_crash and state not in {"dead", "removing"}
        return ProbeProcessObservation(exit_code, alive, False, immediate_crash, sanitizer)


class CleanCoverageCollector(Protocol):
    """Task 14 boundary for replaying one exact input in the verified clean image."""

    async def collect(
        self,
        prepared_target,
        invocation: ProbeInvocation,
        process: ProbeProcessObservation,
    ) -> AttestedCoverage: ...


class ProbeEvidenceMismatch(RuntimeError):
    """Clean replay evidence does not belong to the exact supervised testcase."""


class ProbeInputExecutionFailed(ValueError):
    """Retain which exact fixed-argv input failed deterministic clean replay."""

    def __init__(self, invocation: ProbeInvocation, phase: str, message: str):
        super().__init__(message)
        self.invocation = invocation
        self.phase = phase


@dataclass(frozen=True)
class ProbeExecutionEvidence:
    process: ProbeProcessObservation
    coverage: AttestedCoverage
    accepted_input: bool

    def __post_init__(self) -> None:
        if not isinstance(self.process, ProbeProcessObservation) or not isinstance(self.coverage, AttestedCoverage):
            raise ValueError("probe execution evidence is invalid")
        if type(self.accepted_input) is not bool:
            raise ValueError("probe input acceptance evidence is invalid")

    @property
    def exit_code(self):
        return self.process.exit_code

    @property
    def alive(self):
        return self.process.alive

    @property
    def timed_out(self):
        return self.process.timed_out

    @property
    def immediate_crash(self):
        return self.process.immediate_crash

    @property
    def sanitizer_output(self):
        return self.process.sanitizer_output


@dataclass(frozen=True)
class ProbeInputEvidence:
    """Both executions retained for one logical startup input."""

    name: str
    role: str
    first: ProbeExecutionEvidence
    replay: ProbeExecutionEvidence
    deterministic: bool

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or len(self.name) > 500:
            raise ValueError("probe evidence name is invalid")
        if self.role not in _INPUT_ROLES:
            raise ValueError("probe evidence role is invalid")
        if not isinstance(self.first, ProbeExecutionEvidence) or not isinstance(self.replay, ProbeExecutionEvidence):
            raise ValueError("probe execution pair is invalid")
        if type(self.deterministic) is not bool:
            raise ValueError("probe determinism evidence is invalid")

    @property
    def executions(self) -> tuple[ProbeExecutionEvidence, ProbeExecutionEvidence]:
        return self.first, self.replay


@dataclass(frozen=True)
class RejectedProbeInput:
    """An input deterministically rejected without a crash by one fixed target argv."""

    name: str
    role: str
    command: tuple[str, ...]
    testcase_sha256: str
    first: ProbeProcessObservation
    replay: ProbeProcessObservation
    deterministic: bool
    reason: str

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 500 or self.role not in _INPUT_ROLES:
            raise ValueError("rejected probe input identity is invalid")
        if not isinstance(self.command, tuple) or not self.command:
            raise ValueError("rejected probe input command is invalid")
        _hex(self.testcase_sha256, {64}, "rejected probe input testcase")
        if not isinstance(self.first, ProbeProcessObservation) or not isinstance(
            self.replay, ProbeProcessObservation,
        ):
            raise ValueError("rejected probe input process evidence is invalid")
        if type(self.deterministic) is not bool:
            raise ValueError("rejected probe input determinism is invalid")
        if not isinstance(self.reason, str) or not self.reason or len(self.reason) > 2_000:
            raise ValueError("rejected probe input reason is invalid")


@dataclass(frozen=True)
class ProbeEvidence:
    """All supervised evidence, including rejected crash replay facts."""

    inputs: tuple[ProbeInputEvidence, ...]
    rejected_inputs: tuple[RejectedProbeInput, ...] = ()

    @classmethod
    def from_inputs(cls, inputs, rejected_inputs=()) -> "ProbeEvidence":
        values = tuple(inputs)
        if not values or any(not isinstance(item, ProbeInputEvidence) for item in values):
            raise ValueError("probe evidence requires input results")
        rejected = tuple(rejected_inputs)
        if any(not isinstance(item, RejectedProbeInput) for item in rejected):
            raise ValueError("probe evidence rejected inputs are invalid")
        names = tuple(item.name for item in (*values, *rejected))
        if len(names) != len(set(names)):
            raise ValueError("probe evidence input names must be unique")
        return cls(values, rejected)

    @property
    def executions(self) -> tuple[ProbeExecutionEvidence, ...]:
        return tuple(execution for item in self.inputs for execution in item.executions)

    @property
    def exit_codes(self) -> tuple[int | None, ...]:
        return tuple(value.exit_code for value in self.executions)

    @property
    def alive(self) -> bool:
        return all(value.alive for value in self.executions)

    @property
    def accepts_input(self) -> bool:
        seeds = tuple(item for item in self.inputs if item.role == "seed")
        return bool(seeds) and any(
            item.first.accepted_input and item.replay.accepted_input for item in seeds
        )

    @property
    def deterministic(self) -> bool:
        return all(item.deterministic for item in self.inputs) and all(
            item.deterministic for item in self.rejected_inputs
        )

    @property
    def accepted_seed_names(self) -> frozenset[str]:
        return frozenset(
            item.name for item in self.inputs
            if item.role == "seed" and item.first.accepted_input and item.replay.accepted_input
        )

    @property
    def rejected_input_names(self) -> frozenset[str]:
        return frozenset(item.name for item in self.rejected_inputs)

    @property
    def rejected_seeds(self) -> tuple[RejectedProbeInput, ...]:
        return tuple(item for item in self.rejected_inputs if item.role == "seed")

    @property
    def project_lines(self) -> frozenset[str]:
        return frozenset(line for value in self.executions for line in value.coverage.project_lines)

    @property
    def harness_lines(self) -> frozenset[str]:
        return frozenset(line for value in self.executions for line in value.coverage.harness_lines)

    @property
    def startup_lines(self) -> frozenset[str]:
        return frozenset(line for value in self.executions for line in value.coverage.startup_lines)

    @property
    def immediate_crash(self) -> bool:
        return any(value.immediate_crash for value in self.executions)

    @property
    def timed_out(self) -> bool:
        return any(value.timed_out for value in self.executions)

    @property
    def sanitizer_output(self) -> str:
        return "\n".join(
            value for value in dict.fromkeys(item.sanitizer_output for item in self.executions) if value
        )[:_MAX_SANITIZER_CHARS]

    @property
    def invalid_api_use(self) -> bool:
        return any(not value.coverage.contract_valid for value in self.executions)

    @property
    def seed_independent_crash(self) -> bool:
        return any(
            value.immediate_crash for item in self.inputs if item.role != "seed" for value in item.executions
        )


@dataclass(frozen=True)
class ProbeAcceptance:
    accepted: bool
    reason: str


class ProbePolicy:
    """Accept only a healthy target whose real seed reaches attested project code twice."""

    @staticmethod
    def accept(evidence: ProbeEvidence) -> ProbeAcceptance:
        if not isinstance(evidence, ProbeEvidence):
            raise TypeError("probe policy requires ProbeEvidence")
        if evidence.timed_out:
            return ProbeAcceptance(False, "the supervised probe timed out")
        if evidence.immediate_crash:
            return ProbeAcceptance(False, "an immediate crash was preserved for crash triage")
        if evidence.sanitizer_output:
            return ProbeAcceptance(False, "the supervised probe produced sanitizer output for crash triage")
        if not evidence.alive:
            return ProbeAcceptance(False, "the target did not remain healthy through supervised startup")
        if any(value.exit_code != 0 for value in evidence.executions):
            return ProbeAcceptance(False, "a supervised probe returned a failing exit code")
        if not evidence.deterministic:
            return ProbeAcceptance(False, "the target did not reproduce deterministic process and clean coverage evidence")
        if evidence.invalid_api_use:
            return ProbeAcceptance(False, "the harness violates the clean replay API contract")
        seeds = tuple(item for item in evidence.inputs if item.role == "seed")
        if not any(
            item.first.accepted_input and item.replay.accepted_input
            and item.first.coverage.project_lines and item.replay.coverage.project_lines
            for item in seeds
        ):
            return ProbeAcceptance(False, "the accepted real seed did not reproducibly reach project code")
        if not evidence.project_lines:
            return ProbeAcceptance(False, "the probe reached harness or startup code but no project code")
        reason = "the target accepts a real seed and reaches attested project code reproducibly"
        if evidence.rejected_inputs:
            names = ", ".join(
                item.name.removeprefix("seed:") for item in evidence.rejected_inputs
            )
            reason += f"; quarantined deterministic non-crash input rejections: {names}"
        return ProbeAcceptance(True, reason)


class ProbeService:
    """Repeat each input and join process evidence with an exact clean replay."""

    def __init__(self, runner: ProbeRunner, clean_coverage: CleanCoverageCollector, timeout_seconds: float = 10.0, sink=None):
        if not isinstance(runner, ProbeRunner):
            raise TypeError("probe service requires the application ProbeRunner")
        if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 60:
            raise ValueError("probe timeout must be a float between 0 and 60 seconds")
        self._runner = runner
        self._clean_coverage = clean_coverage
        self._timeout = timeout_seconds
        self._sink = sink or (lambda _text: None)

    async def run(self, prepared_target) -> ProbeEvidence:
        self._validate_target(prepared_target)
        invocations = prepared_target.probe_invocations
        roles = tuple(item.role for item in invocations)
        if roles.count("empty") != 1 or roles.count("minimum") != 1 or roles.count("seed") < 1:
            raise ValueError("prepared target requires empty, minimum, and real seed probes")
        if len(invocations) > 34 or len({item.name for item in invocations}) != len(invocations):
            raise ValueError("prepared target probe inputs are outside their bound")
        evidence = []
        rejected_inputs = []
        for invocation in invocations:
            first_process = await self._process(prepared_target, invocation)
            if self._configuration_incompatible(first_process):
                replay_process = await self._process(prepared_target, invocation)
                deterministic = first_process == replay_process
                rejected_inputs.append(RejectedProbeInput(
                    invocation.name,
                    invocation.role,
                    invocation.command,
                    invocation.testcase_sha256,
                    first_process,
                    replay_process,
                    deterministic,
                    (
                        "fixed target argv rejected this repository seed twice "
                        f"with exit code {first_process.exit_code}"
                    ),
                ))
                continue
            first = await self._execution(prepared_target, invocation, first_process)
            replay = await self._execution(prepared_target, invocation)
            evidence.append(ProbeInputEvidence(
                invocation.name,
                invocation.role,
                first,
                replay,
                self._signature(first) == self._signature(replay),
            ))
        return ProbeEvidence.from_inputs(evidence, rejected_inputs)

    async def _process(self, target, invocation: ProbeInvocation) -> ProbeProcessObservation:
        return await self._runner.run(
            target.image,
            invocation,
            self._timeout,
            self._sink,
            target.replay_environment,
        )

    async def _execution(
        self, target, invocation: ProbeInvocation,
        process: ProbeProcessObservation | None = None,
    ) -> ProbeExecutionEvidence:
        if process is None:
            process = await self._process(target, invocation)
        try:
            coverage = await self._clean_coverage.collect(target, invocation, process)
        except ValueError as error:
            raise ProbeInputExecutionFailed(
                invocation, "clean-coverage", str(error)[:2_000] or type(error).__name__,
            ) from error
        if not isinstance(coverage, AttestedCoverage):
            raise ValueError("clean coverage collector returned invalid evidence")
        provenance = coverage.provenance
        if (
            provenance.project_id != target.project_id
            or provenance.commit_sha != target.commit_sha
            or provenance.clean_image_id != target.coverage_image_id
            or provenance.testcase_sha256 != invocation.testcase_sha256
        ):
            raise ProbeEvidenceMismatch(
                "clean coverage provenance does not match the prepared target or exact testcase",
            )
        accepted = (
            process.alive and not process.timed_out and not process.immediate_crash
            and process.exit_code == 0 and coverage.contract_valid
            and bool(coverage.project_lines or coverage.harness_lines or coverage.startup_lines)
        )
        return ProbeExecutionEvidence(process, coverage, accepted)

    @staticmethod
    def _configuration_incompatible(process: ProbeProcessObservation) -> bool:
        return (
            process.exit_code not in {None, 0}
            and process.alive
            and not process.timed_out
            and not process.immediate_crash
            and not process.sanitizer_output
        )

    @staticmethod
    def _signature(value: ProbeExecutionEvidence) -> tuple:
        return (
            value.process,
            value.coverage.project_lines,
            value.coverage.harness_lines,
            value.coverage.startup_lines,
            value.coverage.contract_valid,
            value.coverage.provenance,
            value.accepted_input,
        )

    @staticmethod
    def _validate_target(target) -> None:
        if type(getattr(target, "project_id", None)) is not int or target.project_id <= 0:
            raise ValueError("prepared target project ID is invalid")
        _hex(getattr(target, "commit_sha", None), {40, 64}, "prepared target commit")
        _exact_image_id(getattr(target, "image", None), "prepared target image")
        _exact_image_id(getattr(target, "coverage_image_id", None), "prepared coverage image")
        if not valid_replay_environment(getattr(target, "replay_environment", None)):
            raise ValueError("prepared target replay environment is invalid")
        invocations = getattr(target, "probe_invocations", None)
        if not isinstance(invocations, tuple) or any(not isinstance(item, ProbeInvocation) for item in invocations):
            raise ValueError("prepared target contains invalid probe invocations")
