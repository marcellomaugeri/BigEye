"""Descriptor-contained JSONL storage for project observability."""

import asyncio
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import stat
import threading

from backend.models.event import StoredEvent
from backend.services.observability.redaction import redact
from backend.services.projects.clone_repository import UnsafeWorkspacePath, contained_path


STREAMS = frozenset({"activity", "debug", "events"})
PUBLIC_STREAMS = frozenset({"activity", "debug"})
INVALIDATION_NAMES = frozenset({"project", "campaigns", "coverage", "findings", "activity", "debug"})
EVENT_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
EVENT_RECORD_MAX_BYTES = 1024 * 1024

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class InvalidEventCursor(ValueError):
    """Raised when an event cursor is not the start of a stored record."""


class CorruptEventLog(ValueError):
    """Raised when an event record cannot be read within the bounded format."""


class EventPage(list[StoredEvent]):
    """A list-compatible event page with the last safely examined cursor."""

    def __init__(self, events=(), next_offset: int = -1, has_more: bool = False):
        super().__init__(events)
        self.next_offset = next_offset
        self.has_more = has_more


class ProjectEventStore:
    """Append-only activity/debug records plus a compact SSE invalidation log."""

    def __init__(self, workspace: Path):
        self._workspace = Path(workspace)
        self._locks: dict[int, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._listeners: set[Callable[[int], None]] = set()

    def subscribe(self, listener: Callable[[int], None]) -> None:
        self._listeners.add(listener)

    def path_for(self, project_id: int, stream: str) -> Path:
        self._validate_project_id(project_id)
        self._validate_stream(stream)
        return contained_path(self._workspace, "projects", str(project_id), "logs", f"{stream}.jsonl")

    async def append(self, project_id: int, stream: str, payload) -> StoredEvent:
        return await asyncio.to_thread(self.append_sync, project_id, stream, payload)

    def append_sync(self, project_id: int, stream: str, payload) -> StoredEvent:
        self._validate_project_id(project_id)
        self._validate_stream(stream)
        with self._locks_guard:
            lock = self._locks.setdefault(project_id, threading.Lock())
        with lock:
            if stream == "events":
                event = self._append(project_id, stream, self._invalidation_payload(payload))
            else:
                event = self._append(project_id, stream, redact(payload))
                self._append(project_id, "events", {"name": stream})
        for listener in tuple(self._listeners):
            listener(project_id)
        return event

    async def read(self, project_id: int, stream: str, after: int, limit: int) -> EventPage:
        self._validate_project_id(project_id)
        self._validate_stream(stream)
        if not isinstance(after, int) or isinstance(after, bool) or after < -1:
            raise ValueError("event offset is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("event limit is invalid")
        descriptor = self._open_file(project_id, stream, create=False, write=False)
        if descriptor is None:
            if after not in (-1, 0):
                raise InvalidEventCursor("event cursor is not a record boundary")
            return EventPage(next_offset=after)
        try:
            return self._read_records(descriptor, stream, after, limit)
        finally:
            os.close(descriptor)

    async def read_latest(self, project_id: int, stream: str, before: int, limit: int) -> EventPage:
        """Read a public log newest-first, paging backwards from an exclusive byte offset."""
        self._validate_project_id(project_id)
        self._validate_stream(stream)
        if not isinstance(before, int) or isinstance(before, bool) or before < -1:
            raise ValueError("event offset is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("event limit is invalid")
        descriptor = self._open_file(project_id, stream, create=False, write=False)
        if descriptor is None:
            if before not in (-1, 0):
                raise InvalidEventCursor("event cursor is not a record boundary")
            return EventPage(next_offset=0)
        try:
            return self._read_latest_records(descriptor, stream, before, limit)
        finally:
            os.close(descriptor)

    def _append(self, project_id: int, stream: str, payload) -> StoredEvent:
        created_at = datetime.now(UTC)
        descriptor = self._open_file(project_id, stream, create=True, write=True)
        try:
            offset = os.lseek(descriptor, 0, os.SEEK_END)
            record = {
                "id": offset,
                "created_at": created_at.isoformat(),
                "stream": stream,
                "payload": payload,
            }
            encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            if len(encoded) > EVENT_RECORD_MAX_BYTES:
                raise ValueError("event record exceeds its byte limit")
            written = 0
            while written < len(encoded):
                count = os.write(descriptor, encoded[written:])
                if count <= 0:
                    raise OSError("event record could not be written")
                written += count
            os.fsync(descriptor)
            return StoredEvent(offset, created_at, stream, payload)
        finally:
            os.close(descriptor)

    def _read_records(self, descriptor: int, stream: str, after: int, limit: int) -> EventPage:
        size = os.fstat(descriptor).st_size
        if after > size:
            raise InvalidEventCursor("event cursor is not a record boundary")
        if after == size:
            return EventPage(next_offset=size)
        records: list[StoredEvent] = []
        consumed = 0
        next_offset = after
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as file:
            if after >= 0:
                if after > 0:
                    file.seek(after - 1)
                    if file.read(1) != b"\n":
                        raise InvalidEventCursor("event cursor is not a record boundary")
                file.seek(after)
                consumed += len(self._read_line(file))
            while len(records) < limit:
                offset = file.tell()
                remaining = EVENT_RESPONSE_MAX_BYTES - consumed
                if remaining <= 0:
                    break
                raw = file.readline(min(EVENT_RECORD_MAX_BYTES, remaining) + 1)
                if not raw:
                    break
                if len(raw) > remaining:
                    file.seek(offset)
                    break
                if len(raw) > EVENT_RECORD_MAX_BYTES or not raw.endswith(b"\n"):
                    raise CorruptEventLog("project event log is corrupt")
                consumed += len(raw)
                next_offset = offset
                try:
                    value = json.loads(raw.decode("utf-8"))
                    created_at = datetime.fromisoformat(value["created_at"])
                    if value["stream"] != stream:
                        continue
                    records.append(StoredEvent(offset, created_at, value["stream"], value["payload"]))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    continue
        return EventPage(records, next_offset)

    def _read_latest_records(self, descriptor: int, stream: str, before: int, limit: int) -> EventPage:
        size = os.fstat(descriptor).st_size
        boundary = size if before == -1 else before
        if boundary > size:
            raise InvalidEventCursor("event cursor is not a record boundary")
        if boundary > 0 and os.pread(descriptor, 1, boundary - 1) != b"\n":
            raise InvalidEventCursor("event cursor is not a record boundary")
        records: list[StoredEvent] = []
        consumed = 0
        while boundary > 0 and len(records) < limit:
            remaining = EVENT_RESPONSE_MAX_BYTES - consumed
            if remaining <= 0:
                break
            start, raw = self._previous_line(descriptor, boundary, remaining)
            if raw is None:
                break
            consumed += len(raw)
            boundary = start
            try:
                value = json.loads(raw.decode("utf-8"))
                created_at = datetime.fromisoformat(value["created_at"])
                if value["stream"] != stream:
                    continue
                records.append(StoredEvent(start, created_at, value["stream"], value["payload"]))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return EventPage(records, boundary if boundary > 0 else 0, boundary > 0)

    @staticmethod
    def _previous_line(descriptor: int, boundary: int, remaining: int) -> tuple[int, bytes | None]:
        """Return the complete record ending at boundary using bounded reverse reads."""
        record_end = boundary - 1
        cursor = record_end
        scanned = 0
        while cursor > 0:
            chunk_size = min(64 * 1024, cursor, EVENT_RECORD_MAX_BYTES + 1 - scanned, remaining + 1 - scanned)
            if chunk_size <= 0:
                return boundary, None
            chunk_start = cursor - chunk_size
            chunk = os.pread(descriptor, chunk_size, chunk_start)
            scanned += len(chunk)
            newline = chunk.rfind(b"\n")
            if newline >= 0:
                start = chunk_start + newline + 1
                raw = os.pread(descriptor, boundary - start, start)
                if len(raw) > EVENT_RECORD_MAX_BYTES or len(raw) > remaining or not raw.endswith(b"\n"):
                    return boundary, None
                return start, raw
            cursor = chunk_start
        raw = os.pread(descriptor, boundary, 0)
        if len(raw) > EVENT_RECORD_MAX_BYTES or len(raw) > remaining or not raw.endswith(b"\n"):
            return boundary, None
        return 0, raw

    @staticmethod
    def _read_line(file) -> bytes:
        raw = file.readline(EVENT_RECORD_MAX_BYTES + 1)
        if not raw:
            return raw
        if len(raw) > EVENT_RECORD_MAX_BYTES or not raw.endswith(b"\n"):
            raise CorruptEventLog("project event log is corrupt")
        return raw

    def _open_file(self, project_id: int, stream: str, create: bool, write: bool) -> int | None:
        try:
            directory = self._log_directory(project_id, create)
        except FileNotFoundError:
            return None
        try:
            flags = (os.O_APPEND | os.O_WRONLY | os.O_CREAT if write else os.O_RDONLY) | _FILE_FLAGS
            try:
                descriptor = os.open(f"{stream}.jsonl", flags, 0o600, dir_fd=directory)
            except FileNotFoundError:
                return None
            except OSError as error:
                raise UnsafeWorkspacePath("project event log is unsafe") from error
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise UnsafeWorkspacePath("project event log must be a regular file")
                return descriptor
            except BaseException:
                os.close(descriptor)
                raise
        finally:
            os.close(directory)

    def _log_directory(self, project_id: int, create: bool) -> int:
        descriptor = self._workspace_fd()
        try:
            for name in ("projects", str(project_id), "logs"):
                child = self._child_directory(descriptor, name, create)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _workspace_fd(self) -> int:
        absolute = Path(os.path.abspath(os.fspath(self._workspace)))
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        try:
            for part in absolute.parts[1:]:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except OSError as error:
            os.close(descriptor)
            raise UnsafeWorkspacePath("workspace directory is unsafe") from error

    @staticmethod
    def _child_directory(parent: int, name: str, create: bool) -> int:
        try:
            if create:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                except FileExistsError:
                    pass
            return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            raise
        except OSError as error:
            raise UnsafeWorkspacePath("project event directory is unsafe") from error

    @staticmethod
    def _validate_project_id(project_id: int) -> None:
        if not isinstance(project_id, int) or isinstance(project_id, bool) or project_id < 1:
            raise ValueError("project ID is invalid")

    @staticmethod
    def _validate_stream(stream: str) -> None:
        if stream not in STREAMS:
            raise ValueError("event stream is invalid")

    @staticmethod
    def _invalidation_payload(payload) -> dict[str, str]:
        if not isinstance(payload, Mapping) or set(payload) != {"name"} or payload["name"] not in INVALIDATION_NAMES:
            raise ValueError("event invalidation is invalid")
        return {"name": payload["name"]}
