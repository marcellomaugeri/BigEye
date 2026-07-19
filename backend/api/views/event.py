"""Project observability response bodies."""

from datetime import datetime

from pydantic import BaseModel


class StoredEventResponse(BaseModel):
    id: int
    created_at: datetime
    stream: str
    payload: object

    @classmethod
    def from_model(cls, event):
        return cls(id=event.id, created_at=event.created_at, stream=event.stream, payload=event.payload)


class EventLogResponse(BaseModel):
    events: list[StoredEventResponse]
    next_offset: int
