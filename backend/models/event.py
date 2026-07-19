"""Durably stored project observability event."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class StoredEvent:
    id: int
    created_at: datetime
    stream: str
    payload: object
