"""Settings HTTP request handling."""

from fastapi import APIRouter, Request

from backend.api.views.settings import SettingsResponse


router = APIRouter()


@router.get("/settings", response_model=SettingsResponse)
async def get_settings(request: Request):
    return await request.app.state.services.settings.check()
