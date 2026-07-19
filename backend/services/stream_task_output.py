"""Read and append task logs through a descriptor-contained workspace boundary."""

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import stat

from backend.services.clone_repository import UnsafeWorkspacePath, contained_path


@dataclass(frozen=True)
class TaskLog:
    content: str
    next_offset: int


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class TaskLogReader:
    def __init__(self, workspace: Path):
        self._workspace = Path(workspace)

    def path_for(self, task) -> Path:
        return contained_path(self._workspace, "projects", str(task.project_id), "logs", f"{task.id}.log")

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
            raise UnsafeWorkspacePath("task log directory is unsafe") from error

    def _log_directory(self, task, create: bool) -> int:
        descriptor = self._workspace_fd()
        try:
            for name in ("projects", str(task.project_id), "logs"):
                child = self._child_directory(descriptor, name, create)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _file_name(task) -> str:
        if not isinstance(task.id, int) or isinstance(task.id, bool) or task.id < 1:
            raise UnsafeWorkspacePath("task log ID is unsafe")
        return f"{task.id}.log"

    def _read_bytes(self, task) -> bytes | None:
        try:
            directory = self._log_directory(task, create=False)
        except FileNotFoundError:
            return None
        try:
            try:
                descriptor = os.open(self._file_name(task), os.O_RDONLY | _FILE_FLAGS, dir_fd=directory)
            except FileNotFoundError:
                return None
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise UnsafeWorkspacePath("task log must be a regular file")
                chunks = []
                while chunk := os.read(descriptor, 65536):
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise UnsafeWorkspacePath("task log is unsafe") from error
        finally:
            os.close(directory)

    async def read(self, task, after: int) -> TaskLog:
        if after < 0:
            raise ValueError("after must be a non-negative byte offset")
        data = self._read_bytes(task)
        if data is None:
            return TaskLog("", after)
        after = min(after, len(data))
        return TaskLog(data[after:].decode("utf-8", errors="replace"), len(data))

    async def size_for(self, task) -> int:
        return len(self._read_bytes(task) or b"")

    async def signature_for(self, task) -> tuple[int, str]:
        data = self._read_bytes(task)
        return (0, "") if data is None else (len(data), sha256(data).hexdigest())


class TaskLogWriter(TaskLogReader):
    """Append UTF-8 output to a derived log without path-based reopening."""

    def append_sync(self, task, content: str) -> None:
        if not isinstance(content, str):
            raise TypeError("task log content must be text")
        encoded = content.encode("utf-8")
        directory = self._log_directory(task, create=True)
        try:
            try:
                descriptor = os.open(
                    self._file_name(task), os.O_APPEND | os.O_WRONLY | os.O_CREAT | _FILE_FLAGS,
                    0o600, dir_fd=directory,
                )
            except OSError as error:
                raise UnsafeWorkspacePath("task log is unsafe") from error
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise UnsafeWorkspacePath("task log must be a regular file")
                written = 0
                while written < len(encoded):
                    count = os.write(descriptor, encoded[written:])
                    if count <= 0:
                        raise OSError("task log could not be written")
                    written += count
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)

    async def append(self, task, content: str) -> None:
        self.append_sync(task, content)
