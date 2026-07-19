"""Read task logs from their derived, contained workspace locations."""

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from backend.services.clone_repository import UnsafeWorkspacePath, contained_path


@dataclass(frozen=True)
class TaskLog:
    content: str
    next_offset: int


class TaskLogReader:
    def __init__(self, workspace: Path):
        self._workspace = workspace

    def path_for(self, task) -> Path:
        return contained_path(self._workspace, "projects", str(task.project_id), "logs", f"{task.id}.log")

    async def read(self, task, after: int) -> TaskLog:
        if after < 0:
            raise ValueError("after must be a non-negative byte offset")
        path = self.path_for(task)
        if path.is_symlink():
            raise UnsafeWorkspacePath("task log must not be a symlink")
        if not path.exists():
            return TaskLog("", after)
        data = path.read_bytes()
        if after > len(data):
            after = len(data)
        return TaskLog(data[after:].decode("utf-8", errors="replace"), len(data))

    async def size_for(self, task) -> int:
        path = self.path_for(task)
        if path.is_symlink():
            raise UnsafeWorkspacePath("task log must not be a symlink")
        return path.stat().st_size if path.exists() else 0

    async def signature_for(self, task) -> tuple[int, str]:
        """Return a content-sensitive log marker for live update detection."""
        path = self.path_for(task)
        if path.is_symlink():
            raise UnsafeWorkspacePath("task log must not be a symlink")
        if not path.exists():
            return (0, "")
        content = path.read_bytes()
        return (len(content), sha256(content).hexdigest())
