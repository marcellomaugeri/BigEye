"""Contained durable journal for application-selected campaign actions."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True)
class JournalEntry:
    action_id: str
    state: str
    record_sha256: str
    result: dict | None


class ActionAlreadySelected(RuntimeError):
    """The action may have crossed a side-effect boundary before restart."""


class ActionJournal:
    """Write-once selected/result records; never repeat an uncertain side effect."""

    def __init__(self, workspace: Path):
        self._workspace = Path(os.path.abspath(os.fspath(workspace)))
        if self._workspace.is_symlink():
            raise ValueError("action journal workspace must not be a symlink")
        self._workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._workspace = self._workspace.resolve(strict=True)

    def begin(self, project_id: int, action_id: str, record: dict) -> JournalEntry | None:
        root = self._root(project_id, action_id)
        digest = self._digest(record)
        selected = root / "selected.json"
        completed = root / "completed.json"
        failed = root / "failed.json"
        for path, state in ((completed, "completed"), (failed, "failed")):
            if path.exists():
                payload = self._read(path)
                self._same(payload, action_id, digest)
                return JournalEntry(action_id, state, digest, payload.get("result"))
        if selected.exists():
            payload = self._read(selected)
            self._same(payload, action_id, digest)
            raise ActionAlreadySelected(
                "selected action has no durable result; refusing to repeat possible side effects"
            )
        self._publish(selected, {
            "action_id": action_id,
            "state": "selected",
            "record_sha256": digest,
            "record": record,
        })
        return None

    def complete(self, project_id: int, action_id: str, record: dict, result: dict) -> None:
        self._finish(project_id, action_id, record, "completed", result)

    def fail(self, project_id: int, action_id: str, record: dict, result: dict) -> None:
        self._finish(project_id, action_id, record, "failed", result)

    def _finish(self, project_id, action_id, record, state, result) -> None:
        root = self._root(project_id, action_id)
        digest = self._digest(record)
        selected = self._read(root / "selected.json")
        self._same(selected, action_id, digest)
        destination = root / f"{state}.json"
        if destination.exists():
            existing = self._read(destination)
            self._same(existing, action_id, digest)
            if existing.get("result") != result:
                raise ValueError("action journal result identity changed")
            return
        self._publish(destination, {
            "action_id": action_id,
            "state": state,
            "record_sha256": digest,
            "result": result,
        })

    def _root(self, project_id: int, action_id: str) -> Path:
        if type(project_id) is not int or project_id <= 0:
            raise ValueError("action journal project ID is invalid")
        if not isinstance(action_id, str) or not action_id or len(action_id) > 200 or "\x00" in action_id:
            raise ValueError("action journal action ID is invalid")
        name = sha256(action_id.encode("utf-8")).hexdigest()
        root = self._workspace / "projects" / str(project_id) / "action-journal" / name
        current = self._workspace
        for part in root.relative_to(self._workspace).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("action journal path contains a symlink")
            current.mkdir(exist_ok=True, mode=0o700)
        return root

    @staticmethod
    def _digest(value: dict) -> str:
        return sha256(json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()

    @staticmethod
    def _same(payload: dict, action_id: str, digest: str) -> None:
        if payload.get("action_id") != action_id or payload.get("record_sha256") != digest:
            raise ValueError("action journal identity changed")

    @staticmethod
    def _read(path: Path) -> dict:
        if path.is_symlink() or not path.is_file():
            raise ValueError("action journal record is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("action journal record is invalid")
        return value

    @staticmethod
    def _publish(path: Path, value: dict) -> None:
        staging = path.parent / f".{path.name}.{uuid4().hex}.tmp"
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        try:
            with staging.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            staging.chmod(0o400)
            os.link(staging, path)
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if staging.exists() and not staging.is_symlink():
                staging.chmod(0o600)
                staging.unlink()
