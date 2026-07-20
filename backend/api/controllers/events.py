"""Project activity and debug log HTTP handling."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request

from backend.api.views.event import EventLogResponse, StoredEventResponse
from backend.services.projects.clone_repository import UnsafeWorkspacePath


router = APIRouter()


@router.get("/projects/{project_id}/logs/{stream}/{event_id}", response_model=StoredEventResponse)
async def get_project_event(
    project_id: int,
    stream: Literal["activity", "debug"],
    event_id: int,
    request: Request,
):
    if stream not in {"activity", "debug"} or event_id < 0:
        raise HTTPException(status_code=422, detail="invalid project event")
    if await request.app.state.services.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="project not found")
    try:
        event = await request.app.state.services.observability.read_exact(project_id, stream, event_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="project event not found") from error
    except (ValueError, UnsafeWorkspacePath) as error:
        raise HTTPException(status_code=422, detail="invalid project event") from error
    return StoredEventResponse.from_model(event)


@router.get("/projects/{project_id}/logs/{stream}", response_model=EventLogResponse)
async def get_project_log(
    project_id: int,
    stream: Literal["activity", "debug"],
    request: Request,
    before: int = Query(default=-1, ge=-1),
    limit: int = Query(default=100, ge=1, le=1000),
):
    if stream not in {"activity", "debug"}:
        raise HTTPException(status_code=422, detail="invalid project event log")
    if await request.app.state.services.projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="project not found")
    try:
        events = await request.app.state.services.observability.read_latest(project_id, stream, before, limit)
    except (ValueError, UnsafeWorkspacePath) as error:
        raise HTTPException(status_code=422, detail="invalid project event log") from error
    return EventLogResponse(
        events=[StoredEventResponse.from_model(event) for event in events],
        next_offset=events.next_offset,
        has_more=events.has_more,
    )
