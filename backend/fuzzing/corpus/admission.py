"""Deterministic discovery and admission of useful clean corpus inputs."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable, Iterable


SEED_DIRECTORY_NAMES = frozenset({
    "test", "tests", "example", "examples", "fixture", "fixtures",
    "sample", "samples", "seed", "seeds",
})


@dataclass(frozen=True)
class CorpusCandidate:
    path: Path
    provenance: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionEvidence:
    executed: bool
    ok: bool
    clean: bool
    clean_line_delta: frozenset[str] = frozenset()
    clean_behaviour_delta: frozenset[str] = frozenset()


@dataclass(frozen=True)
class AdmissionResult:
    admitted: bool
    reason: str
    provenance: str
    content_sha256: str
    first_clean_delta: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()


class SeedCollector:
    """Find bounded repository seeds and include only cited agent proposals."""

    def __init__(self, max_candidates: int = 256, max_candidate_bytes: int = 1_048_576):
        if max_candidates < 1 or max_candidate_bytes < 1:
            raise ValueError("seed collection limits must be positive")
        self._max_candidates = max_candidates
        self._max_candidate_bytes = max_candidate_bytes

    def collect(
        self,
        repository_root: Path,
        cited_proposals: Iterable[CorpusCandidate] = (),
    ) -> tuple[CorpusCandidate, ...]:
        root = repository_root.resolve(strict=True)
        if not root.is_dir() or repository_root.is_symlink():
            raise ValueError("repository root must be a regular directory")

        collected: list[CorpusCandidate] = []
        seen: set[Path] = set()

        for proposal in cited_proposals:
            if not proposal.evidence_ids:
                continue
            self._append_if_safe(root, proposal.path, proposal.evidence_ids, collected, seen)
            if len(collected) == self._max_candidates:
                return tuple(collected)

        paths = sorted(
            (path for path in root.rglob("*") if any(part.lower() in SEED_DIRECTORY_NAMES for part in path.relative_to(root).parts[:-1])),
            key=lambda path: path.relative_to(root).as_posix(),
        )
        for path in paths:
            self._append_if_safe(root, path, (), collected, seen)
            if len(collected) == self._max_candidates:
                break
        return tuple(collected)

    def _append_if_safe(
        self,
        root: Path,
        path: Path,
        evidence_ids: tuple[str, ...],
        collected: list[CorpusCandidate],
        seen: set[Path],
    ) -> None:
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            return
        if path.is_symlink() or not resolved.is_relative_to(root) or resolved in seen:
            return
        relative = resolved.relative_to(root)
        if ".git" in relative.parts or not resolved.is_file():
            return
        try:
            size = resolved.stat().st_size
        except OSError:
            return
        if size > self._max_candidate_bytes:
            return
        seen.add(resolved)
        collected.append(CorpusCandidate(resolved, relative.as_posix(), tuple(evidence_ids)))


class CorpusAdmission:
    """Admit a candidate only after target execution produces useful clean evidence."""

    def __init__(self, executor: Callable[[CorpusCandidate, object], ExecutionEvidence] | None = None):
        self._executor = executor

    def validate(
        self,
        candidate: CorpusCandidate,
        target: object,
        known_hashes: set[str] | frozenset[str] = frozenset(),
    ) -> AdmissionResult:
        if self._executor is None:
            raise RuntimeError("corpus validation requires a target executor")
        execution = self._executor(candidate, target)
        return self.admit(candidate, execution, known_hashes)

    def admit(
        self,
        candidate: CorpusCandidate,
        execution: ExecutionEvidence,
        known_hashes: set[str] | frozenset[str] = frozenset(),
    ) -> AdmissionResult:
        content_hash = self._candidate_hash(candidate.path)
        rejected = lambda reason: AdmissionResult(
            False, reason, candidate.provenance, content_hash, (), candidate.evidence_ids,
        )
        if not candidate.provenance.strip():
            return rejected("candidate has no provenance")
        if content_hash in known_hashes:
            return rejected("candidate content is already present")
        if not execution.executed:
            return rejected("candidate was not executed")
        if not execution.ok:
            return rejected("candidate is invalid for the target")
        if not execution.clean:
            return rejected("candidate has no clean execution evidence")

        delta = tuple(sorted(
            (f"line:{line}" for line in execution.clean_line_delta),
        )) + tuple(sorted(
            (f"behaviour:{behaviour}" for behaviour in execution.clean_behaviour_delta),
        ))
        if not delta:
            return rejected("candidate adds no clean coverage or behaviour")
        return AdmissionResult(
            True,
            "candidate adds useful clean evidence",
            candidate.provenance,
            content_hash,
            delta,
            candidate.evidence_ids,
        )

    @staticmethod
    def _candidate_hash(path: Path) -> str:
        if path.is_symlink() or not path.is_file():
            raise ValueError("corpus candidate must be a regular file")
        digest = sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
