"""Contained, versioned publication and reading of replayed finding artefacts."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import stat
from hashlib import sha256
from uuid import uuid4

from backend.agents.outputs.triage_result import TriageResult
from backend.fuzzing.crashes.correction import CorrectionEvidence
from backend.fuzzing.crashes.quarantine import (
    CrashQuarantine,
    DEFAULT_MAX_INPUT_BYTES,
    QuarantinedCrash,
    _FILE_READ_FLAGS,
    _open_component,
)
from backend.models.finding import Finding


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POINTER_MAX_BYTES = 2_048
_EVIDENCE_MAX_BYTES = 512 * 1024


class FindingArtifactStore:
    """Publish complete immutable generations, then atomically select one."""

    def __init__(self, quarantine: CrashQuarantine):
        self._quarantine = quarantine

    def publish(
        self,
        fingerprint: str,
        quarantined: QuarantinedCrash,
        reproducer: bytes,
        evidence: CrashTriageEvidence,
        triage: TriageResult,
    ) -> None:
        self._validate_digest(fingerprint, "finding fingerprint")
        if not isinstance(reproducer, bytes) or len(reproducer) > self._quarantine.max_input_bytes:
            raise ValueError("finding reproducer is invalid or exceeds its bound")
        root = self._quarantine._open_root()
        directory = None
        try:
            directory = self._quarantine._open_path(
                root, ("projects", str(quarantined.project_id), "findings", fingerprint), create=True,
            )
            identity = os.fstat(directory)
            lock = self._lock(directory)
            try:
                self._record_occurrence(directory, quarantined)
                current = self._current(directory, fingerprint, required=False)
                if current is None or current["reproducer"]["size"] > len(reproducer):
                    self._publish_generation(directory, fingerprint, reproducer, evidence, triage)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)
            if not self._is_canonical(quarantined.project_id, fingerprint, (identity.st_dev, identity.st_ino)):
                raise ValueError("canonical finding directory changed during publication")
        finally:
            if directory is not None:
                os.close(directory)
            os.close(root)

    def detail(self, finding: Finding) -> dict[str, object]:
        root, directory, generation, pointer = self._open_selected(finding)
        try:
            document = self._json_object(
                self._read_file(generation, "evidence.json", _EVIDENCE_MAX_BYTES, immutable=True),
                "finding evidence",
            )
            if document.get("fingerprint") != finding.fingerprint:
                raise ValueError("finding evidence fingerprint does not match the database group")
            if document.get("reproducer") != pointer["reproducer"]:
                raise ValueError("finding evidence does not match its selected reproducer")
            return {
                "uncertainty": self._required_text(document.get("uncertainty"), 2_000),
                "evidence_ids": self._string_list(document.get("evidence_ids"), 64, 2_000),
                "reproducer": self._reproducer_metadata(document.get("reproducer")),
                "replay": self._mapping(document.get("replay")),
                "minimisation": self._mapping(document.get("minimisation")),
                "correction": self._optional_mapping(document.get("correction")),
                "repair_intent": self._required_text(document.get("repair_intent"), 2_000),
            }
        finally:
            os.close(generation); os.close(directory); os.close(root)

    def read_reproducer(self, finding: Finding, max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> bytes:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= DEFAULT_MAX_INPUT_BYTES:
            raise ValueError("reproducer read bound is invalid")
        root, directory, generation, pointer = self._open_selected(finding)
        try:
            value = self._read_file(generation, "minimal.bin", max_bytes, immutable=True)
            if {"sha256": sha256(value).hexdigest(), "size": len(value)} != pointer["reproducer"]:
                raise ValueError("selected finding reproducer does not match its pointer")
            return value
        finally:
            os.close(generation); os.close(directory); os.close(root)

    def claim_correction(self, project_id: int, fingerprint: str) -> bool:
        """Durably allow at most one corrective experiment for a crash group."""
        root, directory = self._open_finding(project_id, fingerprint, create=True)
        try:
            lock = self._lock(directory)
            try:
                return self._write_once(directory, "correction-attempt.json", b'{"attempted":true}')
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN); os.close(lock)
        finally:
            os.close(directory); os.close(root)

    def store_correction_result(self, project_id: int, fingerprint: str, evidence: CorrectionEvidence) -> None:
        if not isinstance(evidence, CorrectionEvidence):
            raise ValueError("correction result must be validated evidence")
        content = self._json(evidence.as_dict())
        if len(content) > 16 * 1024:
            raise ValueError("correction result exceeds its reader bound")
        root, directory = self._open_finding(project_id, fingerprint, create=False)
        try:
            lock = self._lock(directory)
            try:
                self._write_once(directory, "correction-result.json", content)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN); os.close(lock)
        finally:
            os.close(directory); os.close(root)

    def read_correction_result(self, project_id: int, fingerprint: str) -> CorrectionEvidence | None:
        root, directory = self._open_finding(project_id, fingerprint, create=False)
        try:
            try:
                content = self._read_file(directory, "correction-result.json", 16 * 1024, immutable=True)
            except FileNotFoundError:
                return None
            return CorrectionEvidence.from_dict(self._json_object(content, "correction result"))
        finally:
            os.close(directory); os.close(root)

    def _publish_generation(
        self, directory: int, fingerprint: str, reproducer: bytes,
        evidence: CrashTriageEvidence, triage: TriageResult,
    ) -> None:
        reproducer_metadata = {"sha256": sha256(reproducer).hexdigest(), "size": len(reproducer)}
        manifest = {
            "fingerprint": fingerprint,
            "uncertainty": triage.uncertainty[:2_000],
            "evidence_ids": list(evidence.evidence_ids),
            "reproducer": reproducer_metadata,
            "replay": {
                "attempts": evidence.original_attempts,
                "matching": evidence.matching_original_runs,
                "compatible_variants": list(evidence.compatible_variants),
                "clean_variant": evidence.clean_variant,
            },
            "minimisation": evidence.minimisation,
            "correction": evidence.correction,
            "repair_intent": triage.repair_intent[:2_000],
        }
        evidence_bytes = self._json(manifest)
        if len(evidence_bytes) > _EVIDENCE_MAX_BYTES:
            raise ValueError("finding evidence exceeds its reader bound")
        digest = sha256()
        for value in (reproducer, evidence_bytes):
            digest.update(len(value).to_bytes(8, "big")); digest.update(value)
        generation_name = digest.hexdigest()
        generations = _open_component(directory, "generations", create=True)
        created = False
        try:
            created = self._create_generation(generations, generation_name, reproducer, evidence_bytes)
            pointer = self._json({
                "fingerprint": fingerprint,
                "generation": generation_name,
                "reproducer": reproducer_metadata,
            })
            try:
                self._before_pointer_switch(directory, generation_name)
                self._atomic_file(directory, "current.json", pointer, mode=0o400)
            except BaseException:
                if created:
                    self._remove_generation(generations, generation_name)
                raise
        finally:
            os.close(generations)

    def _create_generation(
        self, generations: int, name: str, reproducer: bytes, evidence: bytes,
    ) -> bool:
        try:
            existing = _open_component(generations, name, create=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            try:
                self._validate_generation(existing, reproducer, evidence)
            finally:
                os.close(existing)
            return False
        staging = f".{name}.{uuid4().hex}.tmp"
        os.mkdir(staging, mode=0o700, dir_fd=generations)
        os.fsync(generations)
        staging_descriptor = _open_component(generations, staging, create=False)
        try:
            self._write_new_file(staging_descriptor, "minimal.bin", reproducer, 0o400)
            self._write_new_file(staging_descriptor, "evidence.json", evidence, 0o400)
            os.fchmod(staging_descriptor, 0o500)
            os.fsync(staging_descriptor)
        except BaseException:
            os.close(staging_descriptor)
            self._remove_generation(generations, staging)
            raise
        os.close(staging_descriptor)
        try:
            os.rename(staging, name, src_dir_fd=generations, dst_dir_fd=generations)
            os.fsync(generations)
        except BaseException:
            self._remove_generation(generations, staging)
            raise
        return True

    def _validate_generation(self, directory: int, reproducer: bytes, evidence: bytes) -> None:
        current = os.fstat(directory)
        if not stat.S_ISDIR(current.st_mode) or current.st_mode & 0o222:
            raise ValueError("finding generation is not immutable")
        if self._read_file(directory, "minimal.bin", DEFAULT_MAX_INPUT_BYTES, immutable=True) != reproducer:
            raise ValueError("finding generation reproducer content changed")
        if self._read_file(directory, "evidence.json", _EVIDENCE_MAX_BYTES, immutable=True) != evidence:
            raise ValueError("finding generation evidence content changed")

    def _current(self, directory: int, fingerprint: str, required: bool) -> dict[str, object] | None:
        try:
            value = self._read_file(directory, "current.json", _POINTER_MAX_BYTES, immutable=True)
        except FileNotFoundError:
            if required:
                raise ValueError("finding has no selected evidence generation")
            return None
        pointer = self._json_object(value, "finding generation pointer")
        if set(pointer) != {"fingerprint", "generation", "reproducer"} or pointer.get("fingerprint") != fingerprint:
            raise ValueError("finding generation pointer is invalid")
        self._validate_digest(pointer.get("generation"), "finding generation")
        pointer["reproducer"] = self._reproducer_metadata(pointer.get("reproducer"))
        return pointer

    def _open_selected(self, finding: Finding) -> tuple[int, int, int, dict[str, object]]:
        self._validate_digest(finding.fingerprint, "finding fingerprint")
        root = self._quarantine._open_root()
        directory = generation = None
        try:
            directory = self._quarantine._open_path(
                root, ("projects", str(finding.project_id), "findings", finding.fingerprint), create=False,
            )
            pointer = self._current(directory, finding.fingerprint, required=True)
            generations = _open_component(directory, "generations", create=False)
            try:
                generation = _open_component(generations, pointer["generation"], create=False)
            finally:
                os.close(generations)
            info = os.fstat(generation)
            if info.st_mode & 0o222:
                raise ValueError("selected finding generation is not immutable")
            return root, directory, generation, pointer
        except BaseException:
            if generation is not None:
                os.close(generation)
            if directory is not None:
                os.close(directory)
            os.close(root)
            raise

    def _open_finding(self, project_id: int, fingerprint: str, create: bool) -> tuple[int, int]:
        self._validate_digest(fingerprint, "finding fingerprint")
        if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
            raise ValueError("finding project ID must be positive")
        root = self._quarantine._open_root()
        try:
            directory = self._quarantine._open_path(
                root, ("projects", str(project_id), "findings", fingerprint), create=create,
            )
            return root, directory
        except BaseException:
            os.close(root)
            raise

    def _record_occurrence(self, directory: int, crash: QuarantinedCrash) -> None:
        occurrences = _open_component(directory, "occurrences", create=True)
        try:
            name = f"{crash.group_key}-{crash.occurrence}.json"
            content = self._json({
                "quarantine_group": crash.group_key,
                "quarantine_occurrence": crash.occurrence,
                "input_sha256": crash.input_sha256,
                "input_size": crash.input_size,
            })
            self._write_once(occurrences, name, content)
        finally:
            os.close(occurrences)

    @staticmethod
    def _lock(directory: int) -> int:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(".lock", flags, 0o600, dir_fd=directory)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError("finding publication lock is a symlink or non-file") from error
            raise
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("finding publication lock is not a regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _write_once(directory: int, name: str, content: bytes) -> bool:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, 0o400, dir_fd=directory)
        except FileExistsError:
            try:
                descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError("finding occurrence record is a symlink or non-file") from error
                raise
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size != len(content) or info.st_mode & 0o222:
                    raise ValueError("finding occurrence record was changed after publication")
                if FindingArtifactStore._read_descriptor(descriptor, len(content)) != content:
                    raise ValueError("finding occurrence record was changed after publication")
            finally:
                os.close(descriptor)
            return False
        try:
            FindingArtifactStore._write_descriptor(descriptor, content)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
        return True

    @staticmethod
    def _write_new_file(directory: int, name: str, content: bytes, mode: int) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        try:
            FindingArtifactStore._write_descriptor(descriptor, content)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _atomic_file(directory: int, name: str, content: bytes, mode: int) -> None:
        temporary = f".{name}.{uuid4().hex}.tmp"
        FindingArtifactStore._write_new_file(directory, temporary, content, mode)
        try:
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _remove_generation(parent: int, name: str) -> None:
        try:
            directory = _open_component(parent, name, create=False)
        except FileNotFoundError:
            return
        try:
            os.fchmod(directory, 0o700)
            for child in ("minimal.bin", "evidence.json"):
                try:
                    os.unlink(child, dir_fd=directory)
                except FileNotFoundError:
                    pass
        finally:
            os.close(directory)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)

    def _is_canonical(self, project_id: int, fingerprint: str, expected: tuple[int, int]) -> bool:
        root = self._quarantine._open_root()
        try:
            try:
                current = self._quarantine._open_path(
                    root, ("projects", str(project_id), "findings", fingerprint), create=False,
                )
            except (OSError, ValueError):
                return False
            try:
                info = os.fstat(current)
                return (info.st_dev, info.st_ino) == expected
            finally:
                os.close(current)
        finally:
            os.close(root)

    @staticmethod
    def _read_file(directory: int, name: str, maximum: int, immutable: bool) -> bytes:
        descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_size > maximum
                or immutable and info.st_mode & 0o222
            ):
                raise ValueError("finding artefact is invalid, mutable, or exceeds its bound")
            value = FindingArtifactStore._read_descriptor(descriptor, maximum)
            if len(value) > maximum:
                raise ValueError("finding artefact exceeds its bound")
            return value
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_descriptor(descriptor: int, maximum: int) -> bytes:
        chunks = []
        remaining = maximum + 1
        while remaining and (block := os.read(descriptor, min(1024 * 1024, remaining))):
            chunks.append(block); remaining -= len(block)
        return b"".join(chunks)

    @staticmethod
    def _write_descriptor(descriptor: int, content: bytes) -> None:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("finding artefact write made no progress")
            view = view[written:]

    @staticmethod
    def _before_pointer_switch(_directory: int, _generation: str) -> None:
        """Test seam after a complete generation and before its atomic selection."""

    @staticmethod
    def _json(value: object) -> bytes:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _json_object(value: bytes, label: str) -> dict[str, object]:
        try:
            document = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"{label} is not valid JSON") from error
        if not isinstance(document, dict):
            raise ValueError(f"{label} must be a JSON object")
        return document

    @staticmethod
    def _validate_digest(value: object, label: str) -> None:
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise ValueError(f"{label} is invalid")

    @staticmethod
    def _required_text(value: object, maximum: int) -> str:
        if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
            raise ValueError("finding evidence text is invalid")
        return value

    @classmethod
    def _string_list(cls, value: object, maximum_items: int, maximum_chars: int) -> list[str]:
        if not isinstance(value, list) or len(value) > maximum_items:
            raise ValueError("finding evidence list is invalid")
        return [cls._required_text(item, maximum_chars) for item in value]

    @staticmethod
    def _mapping(value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            raise ValueError("finding evidence mapping is invalid")
        return value

    @classmethod
    def _optional_mapping(cls, value: object) -> dict[str, object] | None:
        return None if value is None else cls._mapping(value)

    @staticmethod
    def _reproducer_metadata(value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != {"sha256", "size"}:
            raise ValueError("finding reproducer metadata is invalid")
        digest, size = value.get("sha256"), value.get("size")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError("finding reproducer hash is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= DEFAULT_MAX_INPUT_BYTES:
            raise ValueError("finding reproducer size is invalid")
        return {"sha256": digest, "size": size}
