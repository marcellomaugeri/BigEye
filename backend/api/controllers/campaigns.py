"""Thin project-scoped campaign read handling."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Request

from backend.api.views.campaign import (
    CampaignAssetResponse,
    CampaignListResponse,
    CampaignResponse,
)


router = APIRouter()
PositiveId = Annotated[int, Path(ge=1)]


@router.get("/projects/{project_id}/campaigns", response_model=CampaignListResponse)
async def list_campaigns(project_id: PositiveId, request: Request):
    services = request.app.state.services
    reader = getattr(services, "campaign_reader", None)
    if reader is None:
        raise HTTPException(status_code=409, detail="campaign evidence is not ready")
    projects = getattr(services, "projects", None)
    if projects is None:
        raise HTTPException(status_code=409, detail="project state is not ready")
    project = await projects.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    try:
        result = await reader.read(project_id)
    except (OverflowError, ValueError) as error:
        raise HTTPException(status_code=409, detail="campaign evidence is unavailable") from error
    assets_by_id = {asset.id: asset for asset in result.assets if asset.project_id == project_id}
    try:
        return CampaignListResponse(
            project_id=project_id,
            campaigns=[
                CampaignResponse.from_model(campaign, assets_by_id, result.summaries[campaign.id])
                for campaign in result.campaigns
            ],
            assets=[CampaignAssetResponse.from_model(asset) for asset in assets_by_id.values()],
        )
    except KeyError as error:
        raise HTTPException(status_code=409, detail="campaign evidence is unavailable") from error
