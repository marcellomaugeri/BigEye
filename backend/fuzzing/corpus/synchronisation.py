"""Synchronise corpus inputs through held, compatible campaign contracts."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable
from uuid import uuid4

from backend.fuzzing.corpus.admission import (
    AdmissionResult,
    _directory_identity,
    _file_identity,
    _read_descriptor,
    _same_directory_path,
)


@dataclass(frozen=True)
class CorpusContract:
    target_hash: str
    input_contract: str
    configuration_hash: str

    @property
    def identifier(self) -> str:
        digest = sha256()
        for value in (self.target_hash, self.input_contract, self.configuration_hash):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.hexdigest()


@dataclass(frozen=True)
class SynchronisationResult:
    transferred_hashes: tuple[str, ...]
    rejected_hashes: tuple[str, ...]
    reason: str


class CorpusSynchroniser:
    def __init__(
        self,
        max_entries: int = 20_000,
        max_directories: int = 4_096,
        max_depth: int = 32,
        max_file_bytes: int = 1_048_576,
        max_total_bytes: int = 256 * 1_048_576,
    ):
        limits = (max_entries, max_directories, max_depth, max_file_bytes, max_total_bytes)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in limits):
            raise ValueError("corpus synchronisation limits must be positive integers")
        self._max_entries = max_entries
        self._max_directories = max_directories
        self._max_depth = max_depth
        self._max_file_bytes = max_file_bytes
        self._max_total_bytes = max_total_bytes

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
        source_path = Path(os.path.abspath(source))
        destination_path = Path(os.path.abspath(destination))
        source_descriptor = os.open(source_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        source_identity = _directory_identity(source_descriptor)
        destination_parent = os.open(destination_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                os.mkdir(destination_path.name, 0o700, dir_fd=destination_parent)
                os.fsync(destination_parent)
            except FileExistsError:
                pass
            destination_descriptor = os.open(
                destination_path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=destination_parent,
            )
            destination_identity = _directory_identity(destination_descriptor)
            try:
                self._after_directories_opened(source_descriptor, destination_descriptor)
                self._require_canonical(source_path, source_identity, "source")
                self._require_canonical(destination_path, destination_identity, "destination")
                files = self._bounded_files(source_descriptor)
                self._after_traversal(source_descriptor)
                transferred: list[str] = []
                rejected: list[str] = []
                for parts, discovered_identity in files:
                    self._require_canonical(source_path, source_identity, "source")
                    self._require_canonical(destination_path, destination_identity, "destination")
                    file_descriptor = self._open_file(source_descriptor, parts)
                    try:
                        source_stat = os.fstat(file_descriptor)
                        identity = _file_identity(source_stat)
                        if identity != discovered_identity:
                            raise ValueError("source corpus entry changed after traversal")
                        content = _read_descriptor(file_descriptor, self._max_file_bytes)
                        digest = sha256(content).hexdigest()
                        result = validate(source_path.joinpath(*parts))
                        self._revalidate_source(
                            source_path, source_identity, source_descriptor, parts,
                            file_descriptor, identity, digest,
                        )
                        if (
                            not isinstance(result, AdmissionResult)
                            or not result.admitted
                            or not result.durable
                            or result.content_sha256 != digest
                            or result.source_identity != identity
                            or result.target_contract != destination_contract.identifier
                        ):
                            rejected.append(digest)
                            continue
                        if self._existing_entry(destination_descriptor, digest, digest):
                            continue
                        published = self._publish(
                            destination_path,
                            destination_descriptor,
                            destination_identity,
                            digest,
                            content,
                        )
                        if published:
                            transferred.append(digest)
                    finally:
                        os.close(file_descriptor)
                self._require_canonical(source_path, source_identity, "source")
                self._require_canonical(destination_path, destination_identity, "destination")
                return SynchronisationResult(tuple(transferred), tuple(rejected), "synchronised compatible corpus")
            finally:
                os.close(destination_descriptor)
        finally:
            os.close(destination_parent)
            os.close(source_descriptor)

    def _bounded_files(self, root_descriptor: int) -> tuple[tuple[tuple[str, ...], tuple[int, int, int, int]], ...]:
        budget = {"entries": 0, "directories": 0, "bytes": 0}
        files: list[tuple[tuple[str, ...], tuple[int, int, int, int]]] = []

        def walk(descriptor: int, parts: tuple[str, ...], depth: int) -> None:
            budget["directories"] += 1
            if budget["directories"] > self._max_directories:
                raise ValueError("corpus directory limit exceeded")
            names: list[str] = []
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    budget["entries"] += 1
                    if budget["entries"] > self._max_entries:
                        raise ValueError("corpus entry limit exceeded")
                    names.append(entry.name)
            for name in sorted(names):
                if not name or name in {".", ".."}:
                    raise ValueError("unsafe corpus entry name")
                source_stat = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                relative = (*parts, name)
                if stat.S_ISDIR(source_stat.st_mode):
                    if name == ".git":
                        raise ValueError("Git internals cannot be synchronised")
                    if depth >= self._max_depth:
                        raise ValueError("corpus depth limit exceeded")
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        walk(child, relative, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(source_stat.st_mode):
                    if source_stat.st_size > self._max_file_bytes:
                        raise ValueError("corpus file byte limit exceeded")
                    budget["bytes"] += source_stat.st_size
                    if budget["bytes"] > self._max_total_bytes:
                        raise ValueError("corpus aggregate byte limit exceeded")
                    files.append((relative, _file_identity(source_stat)))
                else:
                    raise ValueError("corpus entries must be regular files or directories")

        walk(root_descriptor, (), 0)
        return tuple(files)

    @staticmethod
    def _open_file(root_descriptor: int, parts: tuple[str, ...]) -> int:
        descriptor = os.dup(root_descriptor)
        try:
            for component in parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            source_stat = os.fstat(file_descriptor)
            if not stat.S_ISREG(source_stat.st_mode):
                os.close(file_descriptor)
                raise ValueError("corpus source must remain a regular file")
            return file_descriptor
        finally:
            os.close(descriptor)

    def _revalidate_source(
        self,
        source_path,
        source_identity,
        source_descriptor,
        parts,
        held_descriptor,
        identity,
        digest,
    ) -> None:
        self._require_canonical(source_path, source_identity, "source")
        current = self._open_file(source_descriptor, parts)
        try:
            if _file_identity(os.fstat(current)) != identity:
                raise ValueError("source corpus entry changed during validation")
        finally:
            os.close(current)
        if _file_identity(os.fstat(held_descriptor)) != identity:
            raise ValueError("source corpus entry changed during validation")
        if sha256(_read_descriptor(held_descriptor, self._max_file_bytes)).hexdigest() != digest:
            raise ValueError("source corpus entry changed during validation")

    def _publish(self, destination_path, descriptor, directory_identity, digest, content) -> bool:
        staging_name = f".{digest}.staging-{uuid4().hex}"
        staging_descriptor = os.open(
            staging_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        published = False
        try:
            view = memoryview(content)
            while view:
                written = os.write(staging_descriptor, view)
                view = view[written:]
            os.fchmod(staging_descriptor, 0o400)
            os.fsync(staging_descriptor)
            staging_identity = _file_identity(os.fstat(staging_descriptor))
            self._after_staging_written(descriptor, staging_name)
            current = os.stat(staging_name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or _file_identity(current) != staging_identity:
                raise ValueError("staging entry changed before publication")
            staged_input = os.open(staging_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                if sha256(_read_descriptor(staged_input, self._max_file_bytes)).hexdigest() != digest:
                    raise ValueError("staging entry changed before publication")
            finally:
                os.close(staged_input)
            self._require_canonical(destination_path, directory_identity, "destination")
            try:
                os.link(
                    staging_name,
                    digest,
                    src_dir_fd=descriptor,
                    dst_dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                if not self._existing_entry(descriptor, digest, digest):
                    raise ValueError("unsafe existing corpus entry") from error
            else:
                published = True
            os.unlink(staging_name, dir_fd=descriptor)
            self._existing_entry(descriptor, digest, digest)
            os.fsync(descriptor)
            if not _same_directory_path(destination_path, directory_identity):
                if published:
                    os.unlink(digest, dir_fd=descriptor)
                    os.fsync(descriptor)
                raise ValueError("destination corpus directory changed during publication")
            return published
        finally:
            os.close(staging_descriptor)
            try:
                os.unlink(staging_name, dir_fd=descriptor)
            except FileNotFoundError:
                pass
            os.fsync(descriptor)

    def _existing_entry(self, descriptor: int, name: str, expected_digest: str) -> bool:
        try:
            source_stat = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_nlink != 1
            or source_stat.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("unsafe existing corpus entry")
        existing = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            if sha256(_read_descriptor(existing, self._max_file_bytes)).hexdigest() != expected_digest:
                raise ValueError("unsafe existing corpus entry")
        finally:
            os.close(existing)
        return True

    @staticmethod
    def _require_canonical(path, identity, label) -> None:
        if not _same_directory_path(path, identity):
            raise ValueError(f"{label} corpus directory changed")

    @staticmethod
    def _after_directories_opened(_source_descriptor: int, _destination_descriptor: int) -> None:
        """Test seam after both canonical corpus directories are held."""

    @staticmethod
    def _after_traversal(_source_descriptor: int) -> None:
        """Test seam after source identities have been bounded and recorded."""

    @staticmethod
    def _after_staging_written(_descriptor: int, _staging_name: str) -> None:
        """Test seam before descriptor-relative publication."""
