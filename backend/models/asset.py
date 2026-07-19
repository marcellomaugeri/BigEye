"""Persisted campaign assets."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class CampaignAsset:
    id: int
    project_id: int
    kind: str
    name: str
    content_hash: str
    parent_id: int | None
    created_at: datetime
    validated_at: datetime | None
    error: str | None
