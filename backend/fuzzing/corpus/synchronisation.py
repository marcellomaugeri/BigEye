"""Synchronise only corpus inputs with the same execution contract."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable

from backend.fuzzing.corpus.admission import AdmissionResult


@dataclass(frozen=True)
class CorpusContract:
    target_hash: str
    input_contract: str
    configuration_hash: str


@dataclass(frozen=True)
class SynchronisationResult:
    transferred_hashes: tuple[str, ...]
    rejected_hashes: tuple[str, ...]
    reason: str


class CorpusSynchroniser:
    def synchronise(
        self,
        source: Path,
        destination: Path,
        source_contract: CorpusContract,
        destination_contract: CorpusContract,
        validate: Callable[[Path], AdmissionResult],
    ) -> SynchronisationResult:
        if source_contract != destination_contract:
            return SynchronisationResult((), (), "campaign contracts are incompatible")
        if source.is_symlink() or not source.is_dir():
            raise ValueError("source corpus must be a regular directory")
        destination.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink() or not destination.is_dir():
            raise ValueError("destination corpus must be a regular directory")

        entries = tuple(sorted(source.rglob("*"), key=lambda path: path.relative_to(source).as_posix()))
        if any(entry.is_symlink() for entry in entries):
            raise ValueError("source corpus cannot contain symlinks")

        transferred: list[str] = []
        rejected: list[str] = []
        for path in (entry for entry in entries if entry.is_file()):
            result = validate(path)
            content = path.read_bytes()
            digest = sha256(content).hexdigest()
            if not result.admitted or result.content_sha256 != digest:
                rejected.append(digest)
                continue
            target = destination / digest
            if not target.exists():
                temporary = destination / f".{digest}.staging"
                temporary.write_bytes(content)
                temporary.replace(target)
                transferred.append(digest)
        return SynchronisationResult(tuple(transferred), tuple(rejected), "synchronised compatible corpus")
