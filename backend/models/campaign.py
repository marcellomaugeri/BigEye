"""Persisted fuzzing campaigns."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Campaign:
    id: int
    project_id: int
    target_asset_id: int
    configuration_asset_id: int | None
    engine: str
    started_at: datetime
    stopped_at: datetime | None
    last_heartbeat_at: datetime | None
    cpu_seconds: float
    next_review_after: datetime | None
    next_review_reason: str | None
    error: str | None
