"""SQL access for campaigns only."""

from backend.models.campaign import Campaign


class CampaignRepository:
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

    @staticmethod
    def _campaign(row) -> Campaign:
        return Campaign(**dict(row))
