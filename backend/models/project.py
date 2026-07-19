"""Project domain data stored by PostgreSQL."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Project:
    id: int
    repository_url: str
    worker_count: int
    commit_sha: str | None
    created_at: datetime
    finished_at: datetime | None
    error: str | None
