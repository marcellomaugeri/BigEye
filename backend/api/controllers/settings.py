"""Host and project settings HTTP request handling."""

from fastapi import APIRouter, HTTPException, Request

from backend.api.views.settings import ProjectSettingsResponse, SettingsResponse, UpdateProjectSettingsRequest


router = APIRouter()


@router.get("/settings", response_model=SettingsResponse)
async def get_settings(request: Request):
    return await request.app.state.services.settings.check()


def project_settings(request: Request):
    return request.app.state.services.project_settings


@router.get("/projects/{project_id}/settings", response_model=ProjectSettingsResponse)
async def get_project_settings(project_id: int, request: Request):
    try:
        project = await project_settings(request).get(project_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="project not found") from error
    return ProjectSettingsResponse.from_model(project)


@router.patch("/projects/{project_id}/settings", response_model=ProjectSettingsResponse)
async def update_project_settings(project_id: int, body: UpdateProjectSettingsRequest, request: Request):
    try:
        project = await project_settings(request).update(project_id, body.worker_count, body.repository_token)
    except (KeyError, ValueError) as error:
        status_code = 404 if isinstance(error, KeyError) else 422
        detail = "project not found" if isinstance(error, KeyError) else str(error)
        raise HTTPException(status_code=status_code, detail=detail) from error
    return ProjectSettingsResponse.from_model(project)
