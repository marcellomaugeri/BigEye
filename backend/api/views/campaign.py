"""Response-only campaign and project asset views for Overview and source evidence."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CampaignAssetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int = Field(gt=0)
    kind: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=500)
    parent_id: int | None = Field(default=None, gt=0)

    @classmethod
    def from_model(cls, asset):
        return cls(id=asset.id, kind=asset.kind, name=asset.name, parent_id=asset.parent_id)


class CampaignResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int = Field(gt=0)
    target_asset_id: int = Field(gt=0)
    target_name: str = Field(min_length=1, max_length=500)
    configuration_asset_id: int | None = Field(default=None, gt=0)
    configuration_name: str | None = Field(default=None, min_length=1, max_length=500)
    engine: str = Field(min_length=1, max_length=200)
    started_at: datetime
    stopped_at: datetime | None
    last_heartbeat_at: datetime | None
    cpu_exposure_seconds: float = Field(ge=0)
    next_review_after: datetime | None
    next_review_reason: str | None = Field(default=None, max_length=2_000)
    error: str | None = Field(default=None, max_length=2_000)
    configuration_purpose: str | None = Field(default=None, max_length=2_000)
    retirement_reason: str | None = Field(default=None, max_length=1_024)
    reached_line_count: int | None = Field(default=None, ge=0)
    unique_line_count: int | None = Field(default=None, ge=0)
    overlapping_line_count: int | None = Field(default=None, ge=0)
    total_reached_lines: int | None = Field(default=None, ge=0)
    covered_line_delta_5m: int | None = None
    activity: str = Field(min_length=1, max_length=32)

    @classmethod
    def from_model(cls, campaign, assets_by_id, summary):
        target = assets_by_id.get(campaign.target_asset_id)
        configuration = (
            assets_by_id.get(campaign.configuration_asset_id)
            if campaign.configuration_asset_id is not None else None
        )
        if target is None or (
            campaign.configuration_asset_id is not None and configuration is None
        ):
            raise KeyError("campaign asset name is unavailable")
        activity = (
            "failed" if campaign.error is not None
            else "stopped" if campaign.stopped_at is not None or summary.get("retirement_reason") is not None
            else "running" if campaign.last_heartbeat_at is not None
            else "waiting"
        )
        return cls(
            id=campaign.id,
            target_asset_id=campaign.target_asset_id,
            target_name=target.name,
            configuration_asset_id=campaign.configuration_asset_id,
            configuration_name=configuration.name if configuration is not None else None,
            engine=campaign.engine,
            started_at=campaign.started_at,
            stopped_at=campaign.stopped_at,
            last_heartbeat_at=campaign.last_heartbeat_at,
            cpu_exposure_seconds=campaign.cpu_seconds,
            next_review_after=campaign.next_review_after,
            next_review_reason=campaign.next_review_reason,
            error=campaign.error,
            activity=activity,
            **summary,
        )


class CampaignListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: int = Field(gt=0)
    campaigns: list[CampaignResponse]
    assets: list[CampaignAssetResponse]
