"""Persisted replayed crash-group findings."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Finding:
    id: int
    project_id: int
    fingerprint: str
    classification: str
    priority_rank: int | None
    priority_reason: str | None
    description: str
    reproducible: bool
    occurrence_count: int
    created_at: datetime
    triaged_at: datetime | None
    error: str | None
