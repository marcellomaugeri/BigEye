"""Deterministic discovery and admission of useful clean corpus inputs."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Callable, Iterable


SEED_DIRECTORY_NAMES = frozenset({
    "test", "tests", "example", "examples", "fixture", "fixtures",
    "sample", "samples", "seed", "seeds",
})
FileIdentity = tuple[int, int, int, int]
_DURABLE_SEAL = object()


@dataclass(frozen=True)
class CorpusCandidate:
    path: Path
    provenance: str
    evidence_ids: tuple[str, ...] = ()
    expected_sha256: str | None = None
    source_identity: FileIdentity | None = None


@dataclass(frozen=True)
class PreparedCandidate:
    content: bytes
    content_sha256: str
    provenance: str
    evidence_ids: tuple[str, ...]
    source_identity: FileIdentity


@dataclass(frozen=True)
class ExecutionEvidence:
    executed: bool
    ok: bool
    clean: bool
    clean_line_delta: frozenset[str] = frozenset()
    clean_behaviour_delta: frozenset[str] = frozenset()
    content_sha256: str = ""
    target_contract: str = ""


@dataclass(frozen=True)
class AdmissionResult:
    admitted: bool
    reason: str
    provenance: str
    content_sha256: str
    first_clean_delta: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()
    source_identity: FileIdentity | None = None
    target_contract: str = ""
    _validation_seal: object | None = field(default=None, repr=False, compare=False)

    @property
    def durable(self) -> bool:
        return self._validation_seal is _DURABLE_SEAL


class SeedCollector:
    """Find a bounded set of contained seeds without following repository links."""

    def __init__(
        self,
        max_candidates: int = 256,
        max_candidate_bytes: int = 1_048_576,
        max_total_bytes: int = 32 * 1_048_576,
        max_entries: int = 20_000,
        max_directories: int = 4_096,
        max_depth: int = 32,
    ):
        limits = (max_candidates, max_candidate_bytes, max_total_bytes, max_entries, max_directories, max_depth)
        if any(isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 for limit in limits):
            raise ValueError("seed collection limits must be positive integers")
        self._max_candidates = max_candidates
        self._max_candidate_bytes = max_candidate_bytes
        self._max_total_bytes = max_total_bytes
        self._max_entries = max_entries
        self._max_directories = max_directories
        self._max_depth = max_depth

    def collect(
        self,
        repository_root: Path,
        cited_proposals: Iterable[CorpusCandidate] = (),
    ) -> tuple[CorpusCandidate, ...]:
        root = Path(os.path.abspath(repository_root))
        root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_identity = _directory_identity(root_descriptor)
        collected: list[CorpusCandidate] = []
        seen: set[tuple[str, ...]] = set()
        total_bytes = 0
        inspected = 0
        try:
            for proposal in cited_proposals:
                if inspected >= self._max_entries:
                    break
                inspected += 1
                if not _nonblank(proposal.evidence_ids):
                    continue
                try:
                    relative = Path(os.path.abspath(proposal.path)).relative_to(root)
                except ValueError:
                    continue
                if not relative.parts or ".git" in relative.parts or len(relative.parts) > self._max_depth + 1:
                    continue
                try:
                    content, identity = self._read_relative(root_descriptor, relative.parts)
                except (OSError, ValueError):
                    continue
                if total_bytes + len(content) > self._max_total_bytes:
                    break
                total_bytes += len(content)
                seen.add(relative.parts)
                collected.append(CorpusCandidate(
                    root / relative,
                    proposal.provenance,
                    proposal.evidence_ids,
                    sha256(content).hexdigest(),
                    identity,
                ))
                if len(collected) == self._max_candidates:
                    break

            if len(collected) < self._max_candidates and total_bytes < self._max_total_bytes:
                budget = {"entries": inspected, "directories": 0, "bytes": total_bytes, "stop": False}
                self._walk(root_descriptor, root, (), 0, collected, seen, budget)
            if not _same_directory_path(root, root_identity):
                raise ValueError("repository root changed during seed collection")
            return tuple(collected)
        finally:
            os.close(root_descriptor)

    def _walk(self, descriptor, root, parts, depth, collected, seen, budget) -> None:
        if budget["stop"] or budget["directories"] >= self._max_directories:
            budget["stop"] = True
            return
        budget["directories"] += 1
        names: list[str] = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if budget["entries"] >= self._max_entries:
                    budget["stop"] = True
                    break
                budget["entries"] += 1
                names.append(entry.name)
        for name in sorted(names):
            if budget["stop"] or len(collected) >= self._max_candidates:
                return
            if not name or name in {".", ".."}:
                continue
            source_stat = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            relative_parts = (*parts, name)
            if stat.S_ISDIR(source_stat.st_mode):
                if name == ".git" or depth >= self._max_depth:
                    continue
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    self._walk(child, root, relative_parts, depth + 1, collected, seen, budget)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(source_stat.st_mode) or relative_parts in seen:
                continue
            if not any(part.lower() in SEED_DIRECTORY_NAMES for part in parts):
                continue
            if source_stat.st_size > self._max_candidate_bytes:
                continue
            if budget["bytes"] + source_stat.st_size > self._max_total_bytes:
                budget["stop"] = True
                return
            content, identity = _read_regular_at(descriptor, name, self._max_candidate_bytes)
            if identity != _file_identity(source_stat):
                raise ValueError("seed changed during collection")
            budget["bytes"] += len(content)
            seen.add(relative_parts)
            relative = Path(*relative_parts)
            collected.append(CorpusCandidate(
                root / relative,
                relative.as_posix(),
                (),
                sha256(content).hexdigest(),
                identity,
            ))

    def _read_relative(self, root_descriptor: int, parts: tuple[str, ...]) -> tuple[bytes, FileIdentity]:
        descriptor = os.dup(root_descriptor)
        try:
            for component in parts[:-1]:
                if component == ".git":
                    raise ValueError("Git internals are not seed inputs")
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return _read_regular_at(descriptor, parts[-1], self._max_candidate_bytes)
        finally:
            os.close(descriptor)


class CorpusAdmission:
    """Execute held candidate bytes and bind evidence to their target contract."""

    def __init__(
        self,
        executor: Callable[[PreparedCandidate, object], ExecutionEvidence] | None = None,
        max_candidate_bytes: int = 1_048_576,
    ):
        if max_candidate_bytes < 1:
            raise ValueError("candidate byte limit must be positive")
        self._executor = executor
        self._max_candidate_bytes = max_candidate_bytes

    def validate(
        self,
        candidate: CorpusCandidate,
        target: object,
        known_hashes: set[str] | frozenset[str] = frozenset(),
    ) -> AdmissionResult:
        if self._executor is None:
            raise RuntimeError("corpus validation requires a target executor")
        target_contract = _target_contract(target)
        parent = Path(os.path.abspath(candidate.path)).parent
        name = Path(candidate.path).name
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_identity = _directory_identity(parent_descriptor)
        file_descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("corpus candidate must be a regular file")
            identity = _file_identity(before)
            content = _read_descriptor(file_descriptor, self._max_candidate_bytes)
            digest = sha256(content).hexdigest()
            if candidate.source_identity is not None and candidate.source_identity != identity:
                raise ValueError("candidate changed since discovery")
            if candidate.expected_sha256 is not None and candidate.expected_sha256 != digest:
                raise ValueError("candidate changed since discovery")
            prepared = PreparedCandidate(content, digest, candidate.provenance, candidate.evidence_ids, identity)
            if digest in known_hashes:
                return self._rejected(prepared, target_contract, "candidate content is already present")
            if not candidate.provenance.strip():
                return self._rejected(prepared, target_contract, "candidate has no provenance")
            if candidate.evidence_ids and not _nonblank(candidate.evidence_ids):
                return self._rejected(prepared, target_contract, "candidate has blank evidence identifiers")

            execution = self._executor(prepared, target)
            self._revalidate_candidate(parent, parent_descriptor, parent_identity, name, file_descriptor, identity, digest)
            return self._decide(prepared, execution, target_contract)
        finally:
            os.close(file_descriptor)
            os.close(parent_descriptor)

    def admit(
        self,
        candidate: CorpusCandidate,
        _execution: ExecutionEvidence,
        _known_hashes: set[str] | frozenset[str] = frozenset(),
    ) -> AdmissionResult:
        """Evaluate no caller evidence as durable; validation must execute held bytes."""
        return AdmissionResult(
            False,
            "caller-supplied evidence is not durable; use validate",
            candidate.provenance,
            candidate.expected_sha256 or "",
            (),
            candidate.evidence_ids,
        )

    @staticmethod
    def _rejected(prepared: PreparedCandidate, target_contract: str, reason: str) -> AdmissionResult:
        return AdmissionResult(
            False, reason, prepared.provenance, prepared.content_sha256, (), prepared.evidence_ids,
            prepared.source_identity, target_contract,
        )

    def _decide(
        self,
        prepared: PreparedCandidate,
        execution: ExecutionEvidence,
        target_contract: str,
    ) -> AdmissionResult:
        rejected = lambda reason: self._rejected(prepared, target_contract, reason)
        if execution.content_sha256 != prepared.content_sha256:
            return rejected("execution evidence does not match candidate content")
        if execution.target_contract != target_contract:
            return rejected("execution evidence does not match target contract")
        if not execution.executed:
            return rejected("candidate was not executed")
        if not execution.ok:
            return rejected("candidate is invalid for the target")
        if not execution.clean:
            return rejected("candidate has no clean execution evidence")
        if not _nonblank(execution.clean_line_delta) or not _nonblank(execution.clean_behaviour_delta):
            return rejected("execution evidence contains blank identifiers")
        delta = tuple(sorted(f"line:{line}" for line in execution.clean_line_delta))
        delta += tuple(sorted(f"behaviour:{item}" for item in execution.clean_behaviour_delta))
        if not delta:
            return rejected("candidate adds no clean coverage or behaviour")
        return AdmissionResult(
            True,
            "candidate adds useful clean evidence",
            prepared.provenance,
            prepared.content_sha256,
            delta,
            prepared.evidence_ids,
            prepared.source_identity,
            target_contract,
            _DURABLE_SEAL,
        )

    def _revalidate_candidate(
        self,
        parent: Path,
        parent_descriptor: int,
        parent_identity: tuple[int, int],
        name: str,
        file_descriptor: int,
        identity: FileIdentity,
        digest: str,
    ) -> None:
        if not _same_directory_path(parent, parent_identity):
            raise ValueError("candidate changed during execution")
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or _file_identity(current) != identity:
            raise ValueError("candidate changed during execution")
        if _file_identity(os.fstat(file_descriptor)) != identity:
            raise ValueError("candidate changed during execution")
        if sha256(_read_descriptor(file_descriptor, self._max_candidate_bytes)).hexdigest() != digest:
            raise ValueError("candidate changed during execution")


def _target_contract(target: object) -> str:
    if isinstance(target, str):
        value = target
    else:
        value = getattr(target, "contract_hash", None) or getattr(target, "identifier", None)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target must expose a nonblank stable contract")
    return value


def _nonblank(values: Iterable[str]) -> bool:
    return all(isinstance(value, str) and bool(value.strip()) for value in values)


def _file_identity(source_stat) -> FileIdentity:
    return source_stat.st_dev, source_stat.st_ino, source_stat.st_size, source_stat.st_mtime_ns


def _directory_identity(descriptor: int) -> tuple[int, int]:
    source_stat = os.fstat(descriptor)
    if not stat.S_ISDIR(source_stat.st_mode):
        raise ValueError("path must be a regular directory")
    return source_stat.st_dev, source_stat.st_ino


def _same_directory_path(path: Path, identity: tuple[int, int]) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        return _directory_identity(descriptor) == identity
    finally:
        os.close(descriptor)


def _read_regular_at(parent_descriptor: int, name: str, limit: int) -> tuple[bytes, FileIdentity]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
    try:
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("seed candidate must be a regular file")
        return _read_descriptor(descriptor, limit), _file_identity(source_stat)
    finally:
        os.close(descriptor)


def _read_descriptor(descriptor: int, limit: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = limit + 1
    blocks: list[bytes] = []
    while remaining:
        block = os.read(descriptor, min(1_048_576, remaining))
        if not block:
            break
        blocks.append(block)
        remaining -= len(block)
    content = b"".join(blocks)
    if len(content) > limit:
        raise ValueError("corpus candidate exceeds its byte limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return content
