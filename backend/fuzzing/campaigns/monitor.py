"""Bounded engine statistics and immutable artifact observations."""

from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
from hashlib import sha256
import math
import os
from pathlib import PurePosixPath
import re
import stat


_MAX_STATS_BYTES = 64 * 1024
_MAX_LOG_BYTES = 256 * 1024
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 100_000
_MAX_OBSERVED_ARTIFACTS = 512
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LIBFUZZER_PROGRESS = re.compile(
    rb"#(?P<executions>[0-9]+)\s+[^\r\n]*?\bcorp:\s*[0-9]+/[0-9]+[A-Za-z]*"
    rb"[^\r\n]*?\bexec/s:\s*(?P<rate>[0-9]+(?:\.[0-9]+)?)"
)


@dataclass(frozen=True, order=True)
class CampaignArtifactObservation:
    """A regular campaign output bound to its relative path and content hash."""

    kind: str
    relative_path: str
    content_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        path = PurePosixPath(self.relative_path)
        if (
            self.kind not in {"corpus", "crash"}
            or not isinstance(self.relative_path, str)
            or not path.parts
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or not isinstance(self.content_sha256, str)
            or _SHA256.fullmatch(self.content_sha256) is None
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("campaign artifact observation is invalid")


@dataclass(frozen=True)
class CampaignEngineSample:
    executions: int
    executions_per_second: float
    queue_files: int
    crash_files: int
    artifacts: tuple[CampaignArtifactObservation, ...]
    next_artifact_cursors: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.executions) is not int or self.executions < 0
            or isinstance(self.executions_per_second, bool)
            or not isinstance(self.executions_per_second, (int, float))
            or not math.isfinite(self.executions_per_second)
            or self.executions_per_second < 0
            or type(self.queue_files) is not int or not 0 <= self.queue_files <= _MAX_DIRECTORY_ENTRIES
            or type(self.crash_files) is not int or not 0 <= self.crash_files <= _MAX_DIRECTORY_ENTRIES
            or not isinstance(self.artifacts, tuple)
            or len(self.artifacts) > _MAX_OBSERVED_ARTIFACTS * 2
            or any(not isinstance(item, CampaignArtifactObservation) for item in self.artifacts)
            or len({(item.kind, item.relative_path) for item in self.artifacts}) != len(self.artifacts)
            or not isinstance(self.next_artifact_cursors, tuple)
            or any(
                not isinstance(item, tuple) or len(item) != 2
                or not all(isinstance(value, str) and value for value in item)
                for item in self.next_artifact_cursors
            )
        ):
            raise ValueError("campaign engine sample is invalid")


def collect_campaign_sample(
    root_descriptor: int,
    engine: str,
    logs: bytes | str = b"",
    artifact_cursors: dict[str, str] | None = None,
) -> CampaignEngineSample:
    """Collect one engine sample without following links or trusting container output."""

    cursors = artifact_cursors or {}
    if engine == "afl":
        statistics = _afl_statistics(root_descriptor)
        queue_count, queue, queue_cursor = _artifacts(
            root_descriptor, ("output", "main", "queue"), "corpus",
            after=cursors.get("queue"),
        )
        crash_count, crashes, crash_cursor = _artifacts(
            root_descriptor, ("output", "main", "crashes"), "crash",
            ignored=frozenset({"README.txt"}),
            after=cursors.get("crashes"),
        )
        executions = _integer(statistics, "execs_done")
        rate = _number(statistics, "execs_per_sec")
    elif engine == "libfuzzer":
        queue_count, queue, queue_cursor = _artifacts(
            root_descriptor, ("corpus",), "corpus", after=cursors.get("queue"),
        )
        crash_count, crashes, crash_cursor = _artifacts(
            root_descriptor, ("output",), "crash", after=cursors.get("crashes"),
            accepted_prefixes=("crash-", "leak-", "timeout-", "oom-", "slow-unit-"),
        )
        executions, rate = _libfuzzer_statistics(logs)
    else:
        raise ValueError("unsupported campaign engine")
    return CampaignEngineSample(
        executions=executions,
        executions_per_second=rate,
        queue_files=queue_count,
        crash_files=crash_count,
        artifacts=tuple(sorted(
            (*queue, *crashes),
            key=lambda item: (0 if item.kind == "crash" else 1, item.relative_path),
        )),
        next_artifact_cursors=tuple(
            (name, value)
            for name, value in (("queue", queue_cursor), ("crashes", crash_cursor))
            if value is not None
        ),
    )


def _afl_statistics(root_descriptor: int) -> dict[str, str]:
    try:
        content = _read_relative(
            root_descriptor, ("output", "main", "fuzzer_stats"), _MAX_STATS_BYTES,
        )
    except FileNotFoundError:
        return {}
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("AFL++ stats file is not ASCII") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _libfuzzer_statistics(logs: bytes | str) -> tuple[int, float]:
    if isinstance(logs, str):
        logs = logs.encode("utf-8", errors="replace")
    if not isinstance(logs, bytes):
        raise ValueError("libFuzzer logs must be bounded bytes or text")
    if len(logs) > _MAX_LOG_BYTES:
        logs = logs[-_MAX_LOG_BYTES:]
    matches = tuple(_LIBFUZZER_PROGRESS.finditer(logs))
    if not matches:
        return 0, 0.0
    latest = matches[-1]
    return int(latest.group("executions")), float(latest.group("rate"))


def _integer(values: dict[str, str], key: str) -> int:
    value = values.get(key)
    if value is None:
        return 0
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"AFL++ {key} statistic is invalid") from error
    if parsed < 0:
        raise ValueError(f"AFL++ {key} statistic is invalid")
    return parsed


def _number(values: dict[str, str], key: str) -> float:
    value = values.get(key)
    if value is None:
        return 0.0
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValueError(f"AFL++ {key} statistic is invalid") from error
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"AFL++ {key} statistic is invalid")
    return parsed


def _artifacts(
    root_descriptor: int,
    parts: tuple[str, ...],
    kind: str,
    *,
    ignored: frozenset[str] = frozenset(),
    after: str | None = None,
    accepted_prefixes: tuple[str, ...] | None = None,
) -> tuple[int, tuple[CampaignArtifactObservation, ...], str | None]:
    directory = _open_relative_directory(root_descriptor, parts)
    if directory is None:
        return 0, (), after
    try:
        names: list[str] = []
        for index, name in enumerate(os.listdir(directory), start=1):
            if index > _MAX_DIRECTORY_ENTRIES:
                raise OverflowError("campaign output file count exceeds its bound")
            if name in ignored:
                continue
            if accepted_prefixes is not None and not name.startswith(accepted_prefixes):
                continue
            details = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("campaign output contains an unsafe entry")
            names.append(name)
        names.sort()
        start = bisect_right(names, after) if after is not None else 0
        selected = names[start:start + _MAX_OBSERVED_ARTIFACTS]
        if not selected and names:
            selected = names[:_MAX_OBSERVED_ARTIFACTS]
        observations = []
        for name in selected:
            content = _read_at(directory, name, _MAX_ARTIFACT_BYTES)
            observations.append(CampaignArtifactObservation(
                kind=kind,
                relative_path=PurePosixPath(*parts, name).as_posix(),
                content_sha256=sha256(content).hexdigest(),
                size_bytes=len(content),
            ))
        return len(names), tuple(observations), selected[-1] if selected else after
    finally:
        os.close(directory)


def _read_relative(root_descriptor: int, parts: tuple[str, ...], limit: int) -> bytes:
    parent = _open_relative_directory(root_descriptor, parts[:-1])
    if parent is None:
        raise FileNotFoundError(parts[-1])
    try:
        return _read_at(parent, parts[-1], limit)
    finally:
        os.close(parent)


def _read_at(parent_descriptor: int, name: str, limit: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("campaign output contains an unsafe entry")
        if before.st_size > limit:
            noun = "stats file" if limit == _MAX_STATS_BYTES else "artifact"
            raise OverflowError(f"campaign {noun} exceeds its size bound")
        content = os.read(descriptor, limit + 1)
        after = os.fstat(descriptor)
        if len(content) > limit:
            raise OverflowError("campaign artifact exceeds its size bound")
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise ValueError("campaign artifact changed during observation")
        return content
    finally:
        os.close(descriptor)


def _open_relative_directory(root_descriptor: int, parts: tuple[str, ...]) -> int | None:
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.close(descriptor)
                return None
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise
