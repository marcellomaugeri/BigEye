"""SQL access for campaign assets only."""

from backend.models.asset import CampaignAsset


class AssetRepository:
    def __init__(self, pool):
        self._pool = pool

    async def get(self, asset_id: int) -> CampaignAsset | None:
        row = await self._pool.fetchrow(
            """SELECT id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error
               FROM assets WHERE id = $1""",
            asset_id,
        )
        return self._asset(row) if row else None

    async def list_for_project(self, project_id: int) -> list[CampaignAsset]:
        rows = await self._pool.fetch(
            """SELECT id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error
               FROM assets WHERE project_id = $1 ORDER BY created_at, id""",
            project_id,
        )
        return [self._asset(row) for row in rows]

    @staticmethod
    def _asset(row) -> CampaignAsset:
        return CampaignAsset(**dict(row))
