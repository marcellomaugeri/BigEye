"""Task and log response bodies."""

from datetime import datetime

from pydantic import BaseModel


class TaskResponse(BaseModel):
    id: str
    project_id: str
    name: str
    created_at: datetime
    finished_at: datetime | None
    error: str | None

    @classmethod
    def from_model(cls, task):
        return cls(id=str(task.id), project_id=str(task.project_id), name=task.name, created_at=task.created_at, finished_at=task.finished_at, error=task.error)


class TaskLogResponse(BaseModel):
    content: str
    next_offset: int
