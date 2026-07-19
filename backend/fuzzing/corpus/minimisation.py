"""Engine-native corpus minimisation with locked, recoverable publication."""

from __future__ import annotations

import fcntl
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from uuid import uuid4

from backend.fuzzing.corpus.admission import _directory_identity, _same_directory_path


@dataclass(frozen=True)
class CorpusCampaign:
    engine: str
    corpus_dir: Path
    target_command: tuple[str, ...]


@dataclass(frozen=True)
class CorpusResult:
    replaced: bool
    reason: str
    before_count: int
    after_count: int
    commands: tuple[tuple[str, ...], ...]


class NativeCorpusRunner(Protocol):
    def run(self, campaign: CorpusCampaign, command: tuple[str, ...], output: Path) -> None: ...


class CorpusMinimiser:
    def __init__(
        self,
        runner: NativeCorpusRunner,
        clean_coverage_probe: Callable[[CorpusCampaign, Path], frozenset[str]],
        max_entries: int = 20_000,
        max_directories: int = 4_096,
        max_depth: int = 32,
        max_file_bytes: int = 1_048_576,
        max_total_bytes: int = 256 * 1_048_576,
    ):
        limits = (max_entries, max_directories, max_depth, max_file_bytes, max_total_bytes)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in limits):
            raise ValueError("corpus minimisation limits must be positive integers")
        self._runner = runner
        self._clean_coverage_probe = clean_coverage_probe
        self._max_entries = max_entries
        self._max_directories = max_directories
        self._max_depth = max_depth
        self._max_file_bytes = max_file_bytes
        self._max_total_bytes = max_total_bytes

    def minimise(self, campaign: CorpusCampaign) -> CorpusResult:
        corpus = Path(os.path.abspath(campaign.corpus_dir))
        if "build-contexts" in corpus.parts:
            raise ValueError("corpus content cannot be stored in an image build context")
        if not campaign.target_command:
            raise ValueError("target command cannot be empty")
        parent_path = corpus.parent
        parent_descriptor = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_identity = _directory_identity(parent_descriptor)
        lock_name = f".{corpus.name}.lock"
        lock_descriptor = self._open_lock(parent_descriptor, lock_name)
        try:
            if not stat.S_ISREG(os.fstat(lock_descriptor).st_mode):
                raise ValueError("corpus lock must be a regular file")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            self._require_parent(parent_path, parent_identity)
            self._recover_interrupted_publication(parent_descriptor, corpus.name)
            return self._minimise_locked(
                campaign,
                corpus,
                parent_path,
                parent_descriptor,
                parent_identity,
            )
        finally:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock_descriptor)
                os.close(parent_descriptor)

    def _minimise_locked(
        self,
        campaign,
        corpus,
        parent_path,
        parent_descriptor,
        parent_identity,
    ) -> CorpusResult:
        corpus_descriptor = os.open(
            corpus.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        corpus_identity = _directory_identity(corpus_descriptor)
        token = uuid4().hex
        staging_name = f".{corpus.name}.minimising-{token}"
        tmin_name = f".{corpus.name}.tmin-{token}"
        commands: list[tuple[str, ...]] = []
        candidate_name = staging_name
        candidate_descriptor: int | None = None
        try:
            before_files = self._bounded_files(corpus_descriptor)
            before_coverage = self._clean_coverage_probe(campaign, corpus)
            self._require_held_directory(corpus, corpus_descriptor, corpus_identity, "corpus")
            self._create_directory(parent_descriptor, staging_name)
            staging_descriptor = os.open(
                staging_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
            staging_identity = _directory_identity(staging_descriptor)
            try:
                staging_path = parent_path / staging_name
                if campaign.engine == "afl++":
                    cmin = (
                        "afl-cmin", "-i", "/campaign/corpus", "-o", "/campaign/minimised",
                        "--", *campaign.target_command,
                    )
                    commands.append(cmin)
                    self._runner.run(campaign, cmin, staging_path)
                    self._require_held_directory(staging_path, staging_descriptor, staging_identity, "native output")
                    selected = self._bounded_files(staging_descriptor)
                    self._create_directory(parent_descriptor, tmin_name)
                    tmin_descriptor = os.open(
                        tmin_name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent_descriptor,
                    )
                    try:
                        for relative in selected:
                            self._ensure_directories(tmin_descriptor, relative[:-1])
                            output = parent_path.joinpath(tmin_name, *relative)
                            command = (
                                "afl-tmin", "-i", f"/campaign/minimised/{'/'.join(relative)}",
                                "-o", f"/campaign/tmin/{'/'.join(relative)}", "--", *campaign.target_command,
                            )
                            commands.append(command)
                            self._runner.run(campaign, command, output)
                        candidate_name = tmin_name
                        candidate_descriptor = os.dup(tmin_descriptor)
                    finally:
                        os.close(tmin_descriptor)
                elif campaign.engine == "libfuzzer":
                    command = (
                        *campaign.target_command, "-merge=1", "/campaign/minimised", "/campaign/corpus",
                    )
                    commands.append(command)
                    self._runner.run(campaign, command, staging_path)
                    self._require_held_directory(staging_path, staging_descriptor, staging_identity, "native output")
                    candidate_descriptor = os.dup(staging_descriptor)
                else:
                    raise ValueError(f"unsupported corpus engine: {campaign.engine}")
            finally:
                os.close(staging_descriptor)

            self._require_held_directory(corpus, corpus_descriptor, corpus_identity, "corpus")
            if candidate_descriptor is None:
                raise RuntimeError("native minimiser produced no candidate corpus")
            candidate_path = parent_path / candidate_name
            candidate_identity = _directory_identity(candidate_descriptor)
            self._require_held_directory(candidate_path, candidate_descriptor, candidate_identity, "native output")
            candidate_files = self._bounded_files(candidate_descriptor)
            if not candidate_files:
                return CorpusResult(False, "native minimiser produced an empty corpus", len(before_files), 0, tuple(commands))
            candidate_coverage = self._clean_coverage_probe(campaign, candidate_path)
            self._require_held_directory(candidate_path, candidate_descriptor, candidate_identity, "native output")
            self._require_held_directory(corpus, corpus_descriptor, corpus_identity, "corpus")
            if not before_coverage.issubset(candidate_coverage):
                return CorpusResult(
                    False,
                    "minimised corpus did not preserve clean coverage",
                    len(before_files),
                    len(candidate_files),
                    tuple(commands),
                )
            self._publish_candidate(
                parent_path,
                parent_descriptor,
                parent_identity,
                corpus.name,
                corpus_descriptor,
                corpus_identity,
                candidate_name,
                candidate_descriptor,
                candidate_identity,
            )
            published_descriptor = os.open(
                corpus.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
            try:
                after_count = len(self._bounded_files(published_descriptor))
            finally:
                os.close(published_descriptor)
            return CorpusResult(True, "clean coverage preserved", len(before_files), after_count, tuple(commands))
        finally:
            if candidate_descriptor is not None:
                os.close(candidate_descriptor)
            os.close(corpus_descriptor)
            for temporary in (staging_name, tmin_name):
                self._remove_entry_at(parent_descriptor, temporary)

    def _publish_candidate(
        self,
        parent_path,
        parent_descriptor,
        parent_identity,
        corpus_name,
        corpus_descriptor,
        corpus_identity,
        candidate_name,
        candidate_descriptor,
        candidate_identity,
    ) -> None:
        self._require_parent(parent_path, parent_identity)
        self._require_named_directory(parent_descriptor, corpus_name, corpus_descriptor, corpus_identity, "corpus")
        self._require_named_directory(parent_descriptor, candidate_name, candidate_descriptor, candidate_identity, "native output")
        backup_name = f".{corpus_name}.before-minimisation"
        try:
            os.stat(backup_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("stale corpus backup must be recovered before minimisation")

        os.replace(corpus_name, backup_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        try:
            os.replace(candidate_name, corpus_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        except BaseException:
            os.replace(backup_name, corpus_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
            raise

        verified = False
        try:
            published = os.open(
                corpus_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
            try:
                verified = _directory_identity(published) == candidate_identity
            finally:
                os.close(published)
            verified = verified and _same_directory_path(parent_path / corpus_name, candidate_identity)
            verified = verified and _same_directory_path(parent_path, parent_identity)
        finally:
            if not verified:
                failed_name = f".{corpus_name}.failed-{uuid4().hex}"
                try:
                    os.replace(corpus_name, failed_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
                finally:
                    os.replace(backup_name, corpus_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                self._remove_entry_at(parent_descriptor, failed_name)
        if not verified:
            raise ValueError("candidate corpus publication could not be verified")
        retired_name = f".{corpus_name}.retired-{uuid4().hex}"
        os.replace(backup_name, retired_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        self._remove_entry_at(parent_descriptor, retired_name)
        os.fsync(parent_descriptor)

    def _recover_interrupted_publication(self, parent_descriptor: int, corpus_name: str) -> None:
        backup = f".{corpus_name}.before-minimisation"
        corpus_exists = self._entry_exists(parent_descriptor, corpus_name)
        backup_exists = self._entry_exists(parent_descriptor, backup)
        if backup_exists and not corpus_exists:
            os.replace(backup, corpus_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        elif backup_exists and corpus_exists:
            self._require_regular_directory_at(parent_descriptor, corpus_name)
            self._require_regular_directory_at(parent_descriptor, backup)
            interrupted = f".{corpus_name}.interrupted-{uuid4().hex}"
            os.replace(corpus_name, interrupted, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            try:
                os.replace(backup, corpus_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            except BaseException:
                os.replace(interrupted, corpus_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
                raise
            os.fsync(parent_descriptor)
            self._remove_entry_at(parent_descriptor, interrupted)

    def _bounded_files(self, root_descriptor: int) -> tuple[tuple[str, ...], ...]:
        budget = {"entries": 0, "directories": 0, "bytes": 0}
        files: list[tuple[str, ...]] = []

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
                source_stat = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                relative = (*parts, name)
                if stat.S_ISDIR(source_stat.st_mode):
                    if name == ".git":
                        raise ValueError("Git internals cannot be corpus inputs")
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
                    files.append(relative)
                else:
                    raise ValueError("corpus entries must be regular files or directories")

        walk(root_descriptor, (), 0)
        return tuple(files)

    @staticmethod
    def _create_directory(parent_descriptor: int, name: str) -> None:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)

    @staticmethod
    def _open_lock(parent_descriptor: int, name: str) -> int:
        try:
            return os.open(name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        except FileNotFoundError:
            try:
                return os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                return os.open(name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent_descriptor)

    @staticmethod
    def _ensure_directories(root_descriptor: int, parts: tuple[str, ...]) -> None:
        descriptor = os.dup(root_descriptor)
        try:
            for name in parts:
                try:
                    os.mkdir(name, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
        finally:
            os.close(descriptor)

    @staticmethod
    def _entry_exists(parent_descriptor: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    @staticmethod
    def _require_regular_directory_at(parent_descriptor: int, name: str) -> None:
        source_stat = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(source_stat.st_mode):
            raise ValueError("corpus publication entry must be a regular directory")

    @staticmethod
    def _require_parent(parent_path: Path, parent_identity: tuple[int, int]) -> None:
        if not _same_directory_path(parent_path, parent_identity):
            raise ValueError("corpus parent directory changed")

    @staticmethod
    def _require_held_directory(path, descriptor, identity, label) -> None:
        if _directory_identity(descriptor) != identity or not _same_directory_path(path, identity):
            raise ValueError(f"{label} directory changed")

    @staticmethod
    def _require_named_directory(parent_descriptor, name, descriptor, identity, label) -> None:
        try:
            current = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        except OSError as error:
            raise ValueError(f"{label} directory changed") from error
        try:
            if _directory_identity(current) != identity or _directory_identity(descriptor) != identity:
                raise ValueError(f"{label} directory changed")
        finally:
            os.close(current)

    def _remove_entry_at(self, parent_descriptor: int, name: str, depth: int = 0) -> None:
        try:
            source_stat = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(source_stat.st_mode):
            os.unlink(name, dir_fd=parent_descriptor)
            return
        if depth > self._max_depth + 1:
            raise ValueError("corpus cleanup depth limit exceeded")
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        try:
            names: list[str] = []
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if len(names) >= self._max_entries:
                        raise ValueError("corpus cleanup entry limit exceeded")
                    names.append(entry.name)
            for child in names:
                self._remove_entry_at(descriptor, child, depth + 1)
        finally:
            os.close(descriptor)
        os.rmdir(name, dir_fd=parent_descriptor)
