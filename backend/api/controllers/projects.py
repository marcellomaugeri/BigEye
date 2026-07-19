"""Project HTTP request handling."""

from fastapi import APIRouter, HTTPException, Request, status
from starlette.responses import StreamingResponse

from backend.api.views.project import CreateProjectRequest, ProjectResponse
from backend.api.views.task import TaskResponse
from backend.services.create_project import InvalidRepositoryUrl
from backend.services.run_project_backbone import AnalysisNotReady


router = APIRouter()


def services(request: Request):
    return request.app.state.services


@router.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_project(body: CreateProjectRequest, request: Request):
    try:
        project = await services(request).project_creator.create(body.repository_url, body.worker_count)
    except InvalidRepositoryUrl as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return ProjectResponse.from_model(project)


@router.get("/projects", response_model=list[ProjectResponse])
async def list_projects(request: Request):
    return [ProjectResponse.from_model(project) for project in await services(request).projects.list()]


@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: int, request: Request):
    project = await services(request).projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    return ProjectResponse.from_model(project)


@router.get("/projects/{project_id}/tasks", response_model=list[TaskResponse])
async def list_tasks(project_id: int, request: Request):
    if await services(request).projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="project not found")
    return [TaskResponse.from_model(task) for task in await services(request).tasks.list_for_project(project_id)]


@router.get("/projects/{project_id}/analysis")
async def get_analysis(project_id: int, request: Request):
    if await services(request).projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="project not found")
    analysis = services(request).analysis
    if analysis is None:
        raise HTTPException(status_code=409, detail="repository analysis is not ready")
    try:
        return {"content": await analysis.get(project_id)}
    except AnalysisNotReady as error:
        raise HTTPException(status_code=409, detail="repository analysis is not ready") from error


@router.get("/projects/{project_id}/events")
async def project_events(project_id: int, request: Request):
    if await services(request).projects.get(project_id) is None:
        raise HTTPException(status_code=404, detail="project not found")
    return StreamingResponse(services(request).events.stream(project_id), media_type="text/event-stream")
