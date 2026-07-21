"""Stable crash signatures and grouping fingerprints."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Mapping

from backend.fuzzing.crashes.replay import ReplayResult


_ADDRESS = re.compile(r"\b0x[0-9a-fA-F]+\b")
_WHITESPACE = re.compile(r"\s+")
_PROJECT_SOURCE = re.compile(
    r"(?<![/A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|rs|swift|m|mm):\d+(?::\d+)?"
)
_SYMBOL = re.compile(r"(?:\bin\s+|!)([^\s(]+)")
_MODULE = re.compile(r"\(([^()\s]+)\)")
_OFFSET = re.compile(r"\+0x[0-9a-fA-F]+\Z")
_RUNTIME_FUNCTION = re.compile(
    r"^(?:__libc_start_main|abort|raise|start_thread|pthread_[A-Za-z0-9_]+|"
    r"__asan_[A-Za-z0-9_]+|__ubsan_[A-Za-z0-9_]+|__msan_[A-Za-z0-9_]+|"
    r"__tsan_[A-Za-z0-9_]+)$",
    re.IGNORECASE,
)
_RUNTIME_MODULE = re.compile(
    r"^(?:libc(?:\.|-)|libpthread(?:\.|-)|libasan(?:\.|-)|libubsan(?:\.|-)|"
    r"libmsan(?:\.|-)|libtsan(?:\.|-)|ld-linux|libsystem)",
    re.IGNORECASE,
)
_HARNESS_BOUNDARY = re.compile(
    r"^(?:llvmfuzzertestoneinput|fuzzer::|afl_|__afl_)", re.IGNORECASE,
)
_SOURCE_LINE = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+"
    r"\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|rs|swift|m|mm)):(?P<line>[1-9][0-9]*)"
    r"(?::[1-9][0-9]*)?\Z"
)


@dataclass(frozen=True)
class ProjectCrashFrame:
    function: str
    source_location: str | None


@dataclass(frozen=True)
class CrashGroupIdentity:
    commit_sha: str
    failure_class: str
    reproducible: bool
    minimisation_accepted: bool
    minimised_sha256: str
    harness_misuse: bool
    frames: tuple[ProjectCrashFrame, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "version": 1,
            "commit_sha": self.commit_sha,
            "failure_class": self.failure_class,
            "reproducible": self.reproducible,
            "minimisation_accepted": self.minimisation_accepted,
            "minimised_sha256": self.minimised_sha256,
            "harness_misuse": self.harness_misuse,
            "frames": [
                {"function": frame.function, "source_location": frame.source_location}
                for frame in self.frames
            ],
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "CrashGroupIdentity":
        if not isinstance(value, Mapping) or set(value) != {
            "version", "commit_sha", "failure_class", "reproducible",
            "minimisation_accepted", "minimised_sha256", "harness_misuse", "frames",
        } or value.get("version") != 1:
            raise ValueError("crash grouping identity is invalid")
        commit_sha = value.get("commit_sha")
        failure_class = value.get("failure_class")
        reproducible = value.get("reproducible")
        accepted = value.get("minimisation_accepted")
        digest = value.get("minimised_sha256")
        harness_misuse = value.get("harness_misuse")
        raw_frames = value.get("frames")
        if not isinstance(commit_sha, str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit_sha) is None:
            raise ValueError("crash grouping commit is invalid")
        if not isinstance(failure_class, str) or not failure_class or len(failure_class) > 200:
            raise ValueError("crash grouping failure class is invalid")
        if any(type(item) is not bool for item in (reproducible, accepted, harness_misuse)):
            raise ValueError("crash grouping evidence flags are invalid")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("crash grouping testcase digest is invalid")
        if not isinstance(raw_frames, list) or not 1 <= len(raw_frames) <= 64:
            raise ValueError("crash grouping frames are invalid")
        frames = []
        for raw in raw_frames:
            if not isinstance(raw, Mapping) or set(raw) != {"function", "source_location"}:
                raise ValueError("crash grouping frame is invalid")
            function = raw.get("function")
            location = raw.get("source_location")
            if not isinstance(function, str) or not function or len(function) > 500:
                raise ValueError("crash grouping function is invalid")
            if location is not None and (
                not isinstance(location, str) or _SOURCE_LINE.fullmatch(location) is None
            ):
                raise ValueError("crash grouping source location is invalid")
            frames.append(ProjectCrashFrame(function, location))
        return cls(
            commit_sha, failure_class, reproducible, accepted, digest,
            harness_misuse, tuple(frames),
        )


def _text(value: str | None) -> str:
    return _WHITESPACE.sub(" ", (value or "").strip()).casefold()


def normalise_stack(stack: str) -> tuple[str, ...]:
    frames = []
    for raw in stack.splitlines()[:64]:
        source = _PROJECT_SOURCE.search(raw)
        symbol_match = _SYMBOL.search(raw)
        if symbol_match is None:
            continue
        function = _OFFSET.sub("", symbol_match.group(1)).casefold()
        module_match = _MODULE.search(raw)
        module = ""
        if module_match is not None:
            module_value = _OFFSET.sub("", _ADDRESS.sub("", module_match.group(1)))
            module = PurePosixPath(module_value).name.casefold()
        if _RUNTIME_FUNCTION.fullmatch(function) or module and _RUNTIME_MODULE.match(module):
            continue
        location = source.group(0).casefold() if source is not None else module
        value = f"{function}@{location}" if location else function
        if value and value not in frames:
            frames.append(value)
    return tuple(frames)


def _source_line(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().lstrip("/")
    match = _SOURCE_LINE.search(candidate)
    if match is None:
        return None
    parts = PurePosixPath(match.group("path")).parts
    # Container roots differ, but the project-relative suffix after /src is stable.
    if "src" in parts[:-1]:
        parts = parts[parts.index("src") + 1:]
    return f"{'/'.join(part.casefold() for part in parts)}:{match.group('line')}"


def project_crash_frames(result: ReplayResult) -> tuple[ProjectCrashFrame, ...]:
    """Extract a bounded project-frame sequence while treating absent lines as unknown."""
    frames = []
    for raw in result.stack.splitlines()[:64]:
        symbol_match = _SYMBOL.search(raw)
        if symbol_match is None:
            continue
        function = _OFFSET.sub("", symbol_match.group(1)).casefold()
        if _RUNTIME_FUNCTION.fullmatch(function):
            continue
        if _HARNESS_BOUNDARY.match(function):
            break
        source = _PROJECT_SOURCE.search(raw)
        location = _source_line(source.group(0)) if source is not None else None
        frame = ProjectCrashFrame(function, location)
        if frame not in frames:
            frames.append(frame)
    if not frames:
        fallback = normalise_stack(result.stack)
        frames = [ProjectCrashFrame(value.split("@", 1)[0], None) for value in fallback]
    if frames and frames[0].source_location is None:
        top_location = _source_line(result.source_location)
        if top_location is not None:
            frames[0] = ProjectCrashFrame(frames[0].function, top_location)
    return tuple(frames[:64])


def crash_group_identity(
    result: ReplayResult, *, commit_sha: str, reproducible: bool,
    minimised_testcase: bytes, minimisation_accepted: bool, harness_misuse: bool,
) -> CrashGroupIdentity:
    if not isinstance(commit_sha, str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit_sha) is None:
        raise ValueError("crash grouping commit is invalid")
    if type(reproducible) is not bool or type(minimisation_accepted) is not bool or type(harness_misuse) is not bool:
        raise ValueError("crash grouping evidence flags are invalid")
    if not isinstance(minimised_testcase, bytes):
        raise ValueError("crash grouping testcase is invalid")
    failure_class = _text(result.sanitizer)
    if failure_class in {"", "none"}:
        failure_class = _text(result.signal) or "crash"
    frames = project_crash_frames(result)
    if not frames:
        raise ValueError("crash grouping requires one normalized project frame")
    return CrashGroupIdentity(
        commit_sha=commit_sha,
        failure_class=failure_class,
        reproducible=reproducible,
        minimisation_accepted=minimisation_accepted,
        minimised_sha256=sha256(minimised_testcase).hexdigest(),
        harness_misuse=harness_misuse,
        frames=frames,
    )


def compatible_crash_groups(left: CrashGroupIdentity, right: CrashGroupIdentity) -> bool:
    """Conservatively match the same defect across engines with partial symbols."""
    if not isinstance(left, CrashGroupIdentity) or not isinstance(right, CrashGroupIdentity):
        raise ValueError("crash grouping compatibility requires validated identities")
    if (
        left.commit_sha != right.commit_sha
        or left.failure_class != right.failure_class
        or not left.reproducible or not right.reproducible
        or not left.minimisation_accepted or not right.minimisation_accepted
        or left.harness_misuse != right.harness_misuse
        or not left.frames or not right.frames
    ):
        return False
    overlap = min(len(left.frames), len(right.frames))
    for index in range(overlap):
        left_frame = left.frames[index]
        right_frame = right.frames[index]
        if left_frame.function != right_frame.function:
            return False
        if (
            left_frame.source_location is not None
            and right_frame.source_location is not None
            and left_frame.source_location != right_frame.source_location
        ):
            return False
    # The minimised-input guard is needed only when the primary project frame
    # cannot identify the source site. Secondary frames may legitimately be
    # unsymbolised in one or both engine builds without weakening a known,
    # matching primary location.
    if left.frames[0].source_location is None or right.frames[0].source_location is None:
        return left.minimised_sha256 == right.minimised_sha256
    return True


def _hash(payload: dict[str, object]) -> str:
    value = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(value).hexdigest()


def failure_signature(result: ReplayResult) -> str:
    """The failure identity minimisation must preserve (coverage is not required)."""
    return _hash({
        "signal": _text(result.signal),
        "sanitizer": _text(result.sanitizer),
        "source_location": _text(result.source_location),
        "stack": normalise_stack(result.stack),
    })


def crash_fingerprint(result: ReplayResult) -> str:
    """Group by stable failure identity; full coverage remains evidence, not identity."""
    return failure_signature(result)
