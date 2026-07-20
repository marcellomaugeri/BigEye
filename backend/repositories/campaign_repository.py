"""SQL access for campaigns only."""

from backend.models.asset import CampaignAsset
from backend.models.campaign import Campaign


class CampaignRepository:
    _MAX_PROJECT_ASSETS = 1_000

    def __init__(self, pool):
        self._pool = pool

    async def get(self, campaign_id: int) -> Campaign | None:
        row = await self._pool.fetchrow(
            """SELECT id, project_id, target_asset_id, configuration_asset_id, engine, started_at, stopped_at,
                      last_heartbeat_at, cpu_seconds, next_review_after, next_review_reason, error
               FROM campaigns WHERE id = $1""",
            campaign_id,
        )
        return self._campaign(row) if row else None

    async def list_for_project(self, project_id: int) -> list[Campaign]:
        rows = await self._pool.fetch(
            """SELECT id, project_id, target_asset_id, configuration_asset_id, engine, started_at, stopped_at,
                      last_heartbeat_at, cpu_seconds, next_review_after, next_review_reason, error
               FROM campaigns WHERE project_id = $1 ORDER BY started_at, id""",
            project_id,
        )
        return [self._campaign(row) for row in rows]

    async def list_with_assets_for_project(
        self, project_id: int,
    ) -> tuple[list[Campaign], list[CampaignAsset]]:
        """Read campaign state and its project-owned names without adding persistence state."""
        campaigns = await self.list_for_project(project_id)
        rows = await self._pool.fetch(
            """SELECT id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error
               FROM assets WHERE project_id = $1 ORDER BY created_at, id LIMIT $2""",
            project_id,
            self._MAX_PROJECT_ASSETS + 1,
        )
        if len(rows) > self._MAX_PROJECT_ASSETS:
            raise OverflowError("campaign asset read limit exceeded")
        return campaigns, [CampaignAsset(**dict(row)) for row in rows]

    @staticmethod
    def _campaign(row) -> Campaign:
        return Campaign(**dict(row))
