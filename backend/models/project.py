"""Project domain data stored by PostgreSQL."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Project:
    id: int
    repository_url: str
    requested_revision: str
    worker_count: int
    commit_sha: str | None
    token_present: bool
    created_at: datetime
    manager_wake_at: datetime | None
    manager_wake_reason: str | None
    error: str | None
