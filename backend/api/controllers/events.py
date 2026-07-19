"""Project activity and debug log HTTP handling."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request

from backend.api.views.event import EventLogResponse, StoredEventResponse
from backend.services.projects.clone_repository import UnsafeWorkspacePath


router = APIRouter()


@router.get("/projects/{project_id}/logs/{stream}", response_model=EventLogResponse)
async def get_project_log(
    project_id: int,
    stream: Literal["activity", "debug"],
    request: Request,
    after: int = Query(default=-1, ge=-1),
    limit: int = Query(default=100, ge=1, le=1000),
):
    if stream not in {"activity", "debug"}:
        raise HTTPException(status_code=422, detail="invalid project event log")
    if await request.app.state.services.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="project not found")
    try:
        events = await request.app.state.services.observability.read(project_id, stream, after, limit)
    except (ValueError, UnsafeWorkspacePath) as error:
        raise HTTPException(status_code=422, detail="invalid project event log") from error
    return EventLogResponse(
        events=[StoredEventResponse.from_model(event) for event in events],
        next_offset=events.next_offset,
    )
