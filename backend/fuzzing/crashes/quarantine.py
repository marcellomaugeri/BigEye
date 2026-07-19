"""Descriptor-contained storage for bounded raw crash observations."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath


DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ENGINE_OUTPUT_CHARS = 256 * 1024
MAX_STACK_CHARS = 128 * 1024
MAX_COMMAND_ITEMS = 256
MAX_COMMAND_ITEM_CHARS = 4_096
MAX_COVERAGE_ITEMS = 65_536
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_COMPATIBLE_VARIANTS = 16
MAX_HARNESS_EVIDENCE_IDS = 16
_IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _positive_id(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")


def _bounded_text(value: object, label: str, maximum: int, *, empty: bool = True) -> None:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{label} is invalid or exceeds its bound")
    if not empty and not value:
        raise ValueError(f"{label} must not be empty")


def _source_reference(value: str | None, label: str) -> None:
    if value is None:
        return
    _bounded_text(value, label, 2_000, empty=False)
    source = value.rsplit(":", 1)[0]
    path = PurePosixPath(source)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or part.casefold() == ".git" for part in path.parts):
        raise ValueError(f"{label} must be project-relative")


@dataclass(frozen=True)
class CrashObservation:
    """One engine observation with the exact immutable campaign provenance."""

    project_id: int
    campaign_id: int
    commit_sha: str
    engine: str
    image_id: str
    target_asset_id: int
    sanitizer: str
    command: tuple[str, ...]
    input_bytes: bytes
    configuration_asset_id: int | None = None
    engine_output: str = ""
    stack: str = ""
    signal: str = ""
    source_location: str | None = None
    coverage: tuple[str, ...] = ()
    compatible_sanitizer_variants: tuple[tuple[str, str], ...] = ()
    clean_image_id: str | None = None
    harness_misuse_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _positive_id(self.project_id, "project ID")
        _positive_id(self.campaign_id, "campaign ID")
        _positive_id(self.target_asset_id, "target asset ID")
        if self.configuration_asset_id is not None:
            _positive_id(self.configuration_asset_id, "configuration asset ID")
        if not isinstance(self.commit_sha, str) or not _COMMIT_PATTERN.fullmatch(self.commit_sha):
            raise ValueError("commit SHA must be one exact hexadecimal object ID")
        if self.engine not in {"afl", "libfuzzer"}:
            raise ValueError("crash engine must be afl or libfuzzer")
        if not isinstance(self.image_id, str) or not _IMAGE_PATTERN.fullmatch(self.image_id):
            raise ValueError("crash image ID must be an exact sha256 image ID")
        if self.clean_image_id is not None and not _IMAGE_PATTERN.fullmatch(self.clean_image_id):
            raise ValueError("clean image ID must be an exact sha256 image ID")
        _bounded_text(self.sanitizer, "sanitizer", 100, empty=False)
        _bounded_text(self.engine_output, "engine output", MAX_ENGINE_OUTPUT_CHARS)
        _bounded_text(self.stack, "stack", MAX_STACK_CHARS)
        _bounded_text(self.signal, "signal", 100)
        if not isinstance(self.command, tuple) or not 1 <= len(self.command) <= MAX_COMMAND_ITEMS:
            raise ValueError("crash command is empty or exceeds its bound")
        for item in self.command:
            _bounded_text(item, "command item", MAX_COMMAND_ITEM_CHARS, empty=False)
            if "\n" in item or "\r" in item:
                raise ValueError("crash command items must be single-line strings")
        if not isinstance(self.input_bytes, bytes):
            raise ValueError("crash input must be bytes")
        _source_reference(self.source_location, "source location")
        if not isinstance(self.coverage, tuple) or len(self.coverage) > MAX_COVERAGE_ITEMS:
            raise ValueError("coverage evidence exceeds its bound")
        for value in self.coverage:
            _source_reference(value, "coverage location")
        if (
            not isinstance(self.compatible_sanitizer_variants, tuple)
            or len(self.compatible_sanitizer_variants) > MAX_COMPATIBLE_VARIANTS
        ):
            raise ValueError("sanitizer variants exceed their bound")
        variant_names = set()
        for value in self.compatible_sanitizer_variants:
            if not isinstance(value, tuple) or len(value) != 2:
                raise ValueError("sanitizer variants require a name and exact image ID")
            name, image_id = value
            _bounded_text(name, "sanitizer variant", 100, empty=False)
            if name in variant_names or not _IMAGE_PATTERN.fullmatch(image_id):
                raise ValueError("sanitizer variant names and image IDs must be unique and exact")
            variant_names.add(name)
        if (
            not isinstance(self.harness_misuse_evidence, tuple)
            or len(self.harness_misuse_evidence) > MAX_HARNESS_EVIDENCE_IDS
        ):
            raise ValueError("harness evidence exceeds its bound")
        for value in self.harness_misuse_evidence:
            _bounded_text(value, "harness evidence", 2_000, empty=False)
            if value.startswith("/") or ".." in value or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", value):
                raise ValueError("harness evidence must be a bounded identifier, not a path or text payload")

    def provenance(self) -> dict[str, object]:
        """Return bounded JSON data; the input remains a separate binary artefact."""
        return {
            "project_id": self.project_id,
            "campaign_id": self.campaign_id,
            "commit_sha": self.commit_sha,
            "engine": self.engine,
            "image_id": self.image_id,
            "clean_image_id": self.clean_image_id,
            "target_asset_id": self.target_asset_id,
            "configuration_asset_id": self.configuration_asset_id,
            "sanitizer": self.sanitizer,
            "command": list(self.command),
            "engine_output": self.engine_output,
            "stack": self.stack,
            "signal": self.signal,
            "source_location": self.source_location,
            "coverage": list(self.coverage),
            "compatible_sanitizer_variants": [
                {"sanitizer": sanitizer, "image_id": image_id}
                for sanitizer, image_id in self.compatible_sanitizer_variants
            ],
            "harness_misuse_evidence": list(self.harness_misuse_evidence),
            "input_sha256": sha256(self.input_bytes).hexdigest(),
            "input_size": len(self.input_bytes),
        }


@dataclass(frozen=True)
class QuarantinedCrash:
    project_id: int
    group_key: str
    occurrence: int
    input_sha256: str
    input_size: int

    @property
    def relative_parts(self) -> tuple[str, ...]:
        return ("projects", str(self.project_id), "crashes", "quarantine", self.group_key, str(self.occurrence))


class CrashQuarantine:
    """Persist every original occurrence without following workspace symlinks."""

    def __init__(self, workspace: Path, max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES):
        if isinstance(max_input_bytes, bool) or not isinstance(max_input_bytes, int) or max_input_bytes <= 0:
            raise ValueError("maximum crash input size must be positive")
        self.workspace = Path(os.path.abspath(workspace))
        self.max_input_bytes = max_input_bytes
        root = _open_absolute_directory(self.workspace)
        try:
            info = os.fstat(root)
            self._root_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(root)

    def persist(self, observation: CrashObservation) -> QuarantinedCrash:
        if len(observation.input_bytes) > self.max_input_bytes:
            raise ValueError("crash input exceeds the quarantine bound")
        metadata = observation.provenance()
        encoded = json.dumps(metadata, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_METADATA_BYTES:
            raise ValueError("crash metadata exceeds the quarantine reader bound")
        digest = sha256()
        digest.update(len(encoded).to_bytes(8, "big")); digest.update(encoded)
        digest.update(len(observation.input_bytes).to_bytes(8, "big")); digest.update(observation.input_bytes)
        group_key = digest.hexdigest()
        root = self._open_root()
        occurrence_directory = None
        try:
            parent = self._open_path(
                root,
                ("projects", str(observation.project_id), "crashes", "quarantine", group_key),
                create=True,
            )
            try:
                group_info = os.fstat(parent)
                self._after_group_opened(observation.project_id, group_key, parent)
                for occurrence in range(1, 1_000_001):
                    try:
                        os.mkdir(str(occurrence), mode=0o700, dir_fd=parent)
                    except FileExistsError:
                        continue
                    os.fsync(parent)
                    occurrence_directory = _open_component(parent, str(occurrence), create=False)
                    break
                else:
                    raise RuntimeError("crash occurrence limit exceeded")
                self._write_file(occurrence_directory, "original.bin", observation.input_bytes)
                self._write_file(occurrence_directory, "metadata.json", encoded)
                os.fsync(occurrence_directory)
                if not self._is_canonical_group(
                    root, observation.project_id, group_key, (group_info.st_dev, group_info.st_ino),
                ):
                    raise ValueError("canonical quarantine directory changed during publication")
                return QuarantinedCrash(
                    project_id=observation.project_id,
                    group_key=group_key,
                    occurrence=occurrence,
                    input_sha256=metadata["input_sha256"],
                    input_size=len(observation.input_bytes),
                )
            except BaseException:
                if occurrence_directory is not None:
                    for name in ("original.bin", "metadata.json"):
                        try:
                            os.unlink(name, dir_fd=occurrence_directory)
                        except FileNotFoundError:
                            pass
                    os.close(occurrence_directory)
                    occurrence_directory = None
                    try:
                        os.rmdir(str(occurrence), dir_fd=parent)
                        os.fsync(parent)
                    except OSError:
                        pass
                raise
            finally:
                os.close(parent)
        finally:
            if occurrence_directory is not None:
                os.close(occurrence_directory)
            os.close(root)

    def read_original(self, crash: QuarantinedCrash, max_bytes: int | None = None) -> bytes:
        return self._read_file(crash, "original.bin", max_bytes or self.max_input_bytes)

    def read_metadata(self, crash: QuarantinedCrash) -> bytes:
        return self._read_file(crash, "metadata.json", MAX_METADATA_BYTES)

    def _read_file(self, crash: QuarantinedCrash, name: str, maximum: int) -> bytes:
        _positive_id(crash.project_id, "project ID")
        if not re.fullmatch(r"[0-9a-f]{64}", crash.group_key) or crash.occurrence <= 0:
            raise ValueError("quarantine reference is invalid")
        root = self._open_root()
        try:
            directory = self._open_path(root, crash.relative_parts, create=False)
            try:
                descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory)
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                        raise ValueError("quarantined crash artefact is invalid or exceeds its bound")
                    chunks = []
                    remaining = maximum + 1
                    while remaining and (block := os.read(descriptor, min(1024 * 1024, remaining))):
                        chunks.append(block); remaining -= len(block)
                    value = b"".join(chunks)
                    if len(value) > maximum:
                        raise ValueError("quarantined crash artefact exceeds its bound")
                    return value
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory)
        finally:
            os.close(root)

    def _open_root(self) -> int:
        descriptor = _open_absolute_directory(self.workspace)
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != self._root_identity:
            os.close(descriptor)
            raise ValueError("workspace root changed after crash service initialisation")
        return descriptor

    @staticmethod
    def _after_group_opened(_project_id: int, _group_key: str, _descriptor: int) -> None:
        """Test seam for proving path replacement cannot publish unreachable evidence."""

    def _is_canonical_group(
        self, root: int, project_id: int, group_key: str, expected: tuple[int, int],
    ) -> bool:
        try:
            current = self._open_path(
                root, ("projects", str(project_id), "crashes", "quarantine", group_key), create=False,
            )
        except (OSError, ValueError):
            return False
        try:
            info = os.fstat(current)
            return (info.st_dev, info.st_ino) == expected
        finally:
            os.close(current)

    @staticmethod
    def _open_path(root: int, parts: tuple[str, ...], create: bool) -> int:
        descriptor = os.dup(root)
        try:
            for part in parts:
                next_descriptor = _open_component(descriptor, part, create=create)
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _write_file(directory: int, name: str, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("crash artefact write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("workspace root must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_descriptor = _open_component(descriptor, part, create=False)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_component(parent: int, component: str, create: bool) -> int:
    if not component or component in {".", ".."} or "/" in component:
        raise ValueError("workspace path component is invalid")
    if create:
        created = False
        try:
            os.mkdir(component, mode=0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        if created:
            os.fsync(parent)
    try:
        return os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("workspace path contains a symlink or non-directory component") from error
        raise
