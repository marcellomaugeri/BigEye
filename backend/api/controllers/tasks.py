"""Task log HTTP request handling."""

from fastapi import APIRouter, HTTPException, Query, Request

from backend.api.views.task import TaskLogResponse
from backend.services.projects.clone_repository import UnsafeWorkspacePath


router = APIRouter()


@router.get("/tasks/{task_id}/log", response_model=TaskLogResponse)
async def get_task_log(task_id: int, request: Request, after: int = Query(default=0, ge=0)):
    task = await request.app.state.services.tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    try:
        log = await request.app.state.services.logs.read(task, after)
    except (ValueError, UnsafeWorkspacePath) as error:
        raise HTTPException(status_code=422, detail="invalid task log path") from error
    return TaskLogResponse(content=log.content, next_offset=log.next_offset)
