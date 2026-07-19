"""Task domain data stored by PostgreSQL."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Task:
    id: int
    project_id: int
    name: str
    created_at: datetime
    finished_at: datetime | None
    error: str | None
