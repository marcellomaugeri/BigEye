"""Contained publication and reading of replayed finding artefacts."""

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
from backend.fuzzing.crashes.quarantine import (
    CrashQuarantine,
    DEFAULT_MAX_INPUT_BYTES,
    QuarantinedCrash,
    _FILE_READ_FLAGS,
    _open_component,
)
from backend.models.finding import Finding


_FINGERPRINT = re.compile(r"[0-9a-f]{64}$")


class FindingArtifactStore:
    """Publish one bounded representative and JSON evidence per crash group."""

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
        self._validate_fingerprint(fingerprint)
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
                self._publish_locked(directory, fingerprint, quarantined, reproducer, evidence, triage)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)
            if not self._is_canonical(quarantined.project_id, fingerprint, (identity.st_dev, identity.st_ino)):
                raise ValueError("canonical finding directory changed during publication")
        finally:
            if directory is not None:
                os.close(directory)
            os.close(root)

    def _publish_locked(
        self, directory: int, fingerprint: str, quarantined: QuarantinedCrash,
        reproducer: bytes, evidence: CrashTriageEvidence, triage: TriageResult,
    ) -> None:
        occurrences = _open_component(directory, "occurrences", create=True)
        try:
            occurrence_name = f"{quarantined.group_key}-{quarantined.occurrence}.json"
            occurrence = {
                "quarantine_group": quarantined.group_key,
                "quarantine_occurrence": quarantined.occurrence,
                "input_sha256": quarantined.input_sha256,
                "input_size": quarantined.input_size,
            }
            self._write_once(occurrences, occurrence_name, self._json(occurrence))
        finally:
            os.close(occurrences)
        reproducer_metadata, selected = self._publish_smallest(directory, reproducer)
        if not selected:
            self._require_existing_manifest(directory, fingerprint, reproducer_metadata)
            return
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
        self._atomic_write(directory, "evidence.json", self._json(manifest))
        os.fsync(directory)

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

    def detail(self, finding: Finding) -> dict[str, object]:
        document = self._read_json(finding, "evidence.json", 512 * 1024)
        if document.get("fingerprint") != finding.fingerprint:
            raise ValueError("finding evidence fingerprint does not match the database group")
        return {
            "uncertainty": self._required_text(document.get("uncertainty"), 2_000),
            "evidence_ids": self._string_list(document.get("evidence_ids"), 128, 2_000),
            "reproducer": self._reproducer_metadata(document.get("reproducer")),
            "replay": self._mapping(document.get("replay")),
            "minimisation": self._mapping(document.get("minimisation")),
            "correction": self._optional_mapping(document.get("correction")),
            "repair_intent": self._required_text(document.get("repair_intent"), 2_000),
        }

    def read_reproducer(self, finding: Finding, max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> bytes:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= DEFAULT_MAX_INPUT_BYTES:
            raise ValueError("reproducer read bound is invalid")
        return self._read(finding, "minimal.bin", max_bytes)

    def _read_json(self, finding: Finding, name: str, maximum: int) -> dict[str, object]:
        try:
            value = json.loads(self._read(finding, name, maximum))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("finding evidence is not valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("finding evidence must be a JSON object")
        return value

    def _read(self, finding: Finding, name: str, maximum: int) -> bytes:
        self._validate_fingerprint(finding.fingerprint)
        root = self._quarantine._open_root()
        try:
            directory = self._quarantine._open_path(
                root, ("projects", str(finding.project_id), "findings", finding.fingerprint), create=False,
            )
            try:
                descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory)
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                        raise ValueError("finding artefact is invalid or exceeds its bound")
                    chunks = []
                    remaining = maximum + 1
                    while remaining and (block := os.read(descriptor, min(1024 * 1024, remaining))):
                        chunks.append(block); remaining -= len(block)
                    value = b"".join(chunks)
                    if len(value) > maximum:
                        raise ValueError("finding artefact exceeds its bound")
                    return value
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory)
        finally:
            os.close(root)

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
    def _publish_smallest(directory: int, content: bytes) -> tuple[dict[str, object], bool]:
        try:
            current = os.stat("minimal.bin", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            if not stat.S_ISREG(current.st_mode):
                raise ValueError("finding reproducer destination is not a regular file")
            if current.st_size <= len(content):
                descriptor = os.open("minimal.bin", _FILE_READ_FLAGS, dir_fd=directory)
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > DEFAULT_MAX_INPUT_BYTES:
                        raise ValueError("finding reproducer destination is invalid or exceeds its bound")
                    digest = sha256()
                    size = 0
                    while block := os.read(descriptor, 1024 * 1024):
                        digest.update(block); size += len(block)
                    current_after = os.stat("minimal.bin", dir_fd=directory, follow_symlinks=False)
                    if (
                        (info.st_dev, info.st_ino, info.st_size)
                        != (current_after.st_dev, current_after.st_ino, current_after.st_size)
                    ):
                        raise ValueError("finding reproducer changed during validation")
                    return {"sha256": digest.hexdigest(), "size": size}, False
                finally:
                    os.close(descriptor)
        FindingArtifactStore._atomic_write(directory, "minimal.bin", content)
        return {"sha256": sha256(content).hexdigest(), "size": len(content)}, True

    @staticmethod
    def _require_existing_manifest(
        directory: int, fingerprint: str, reproducer: dict[str, object],
    ) -> None:
        try:
            descriptor = os.open("evidence.json", _FILE_READ_FLAGS, dir_fd=directory)
        except (FileNotFoundError, OSError) as error:
            raise ValueError("existing finding representative has no validated evidence") from error
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024:
                raise ValueError("existing finding evidence is invalid or exceeds its bound")
            content = bytearray()
            while block := os.read(descriptor, 64 * 1024):
                content.extend(block)
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("existing finding evidence is invalid") from error
        finally:
            os.close(descriptor)
        if (
            not isinstance(document, dict) or document.get("fingerprint") != fingerprint
            or document.get("reproducer") != reproducer
        ):
            raise ValueError("existing finding evidence does not match its representative")

    @staticmethod
    def _write_once(directory: int, name: str, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        except FileExistsError:
            try:
                descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError("finding occurrence record is a symlink or non-file") from error
                raise
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size != len(content):
                    raise ValueError("finding occurrence record was changed after publication")
                existing = bytearray()
                while block := os.read(descriptor, 64 * 1024):
                    existing.extend(block)
                    if len(existing) > len(content):
                        break
                if bytes(existing) != content:
                    raise ValueError("finding occurrence record was changed after publication")
            finally:
                os.close(descriptor)
            return
        try:
            FindingArtifactStore._write_descriptor(descriptor, content)
        finally:
            os.close(descriptor)
        os.fsync(directory)

    @staticmethod
    def _atomic_write(directory: int, name: str, content: bytes) -> None:
        temporary = f".{name}.{uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        try:
            FindingArtifactStore._write_descriptor(descriptor, content)
        finally:
            os.close(descriptor)
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
    def _write_descriptor(descriptor: int, content: bytes) -> None:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("finding artefact write made no progress")
            view = view[written:]
        os.fsync(descriptor)

    @staticmethod
    def _json(value: object) -> bytes:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _validate_fingerprint(value: str) -> None:
        if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
            raise ValueError("finding fingerprint is invalid")

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
        if not isinstance(value, dict):
            raise ValueError("finding reproducer metadata is invalid")
        digest, size = value.get("sha256"), value.get("size")
        if not isinstance(digest, str) or not _FINGERPRINT.fullmatch(digest):
            raise ValueError("finding reproducer hash is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= DEFAULT_MAX_INPUT_BYTES:
            raise ValueError("finding reproducer size is invalid")
        return {"sha256": digest, "size": size}
