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

    async def create(
        self, project_id: int, kind: str, name: str, content_hash: str, parent_id: int | None
    ) -> CampaignAsset:
        row = await self._pool.fetchrow(
            """INSERT INTO assets (project_id, kind, name, content_hash, parent_id)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error""",
            project_id, kind, name, content_hash, parent_id,
        )
        if row is None:
            raise RuntimeError("asset creation did not return a row")
        return self._asset(row)

    async def mark_validated(self, asset_id: int) -> CampaignAsset:
        row = await self._pool.fetchrow(
            """UPDATE assets SET validated_at = CURRENT_TIMESTAMP, error = NULL
               WHERE id = $1
               RETURNING id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error""",
            asset_id,
        )
        if row is None:
            raise KeyError(asset_id)
        return self._asset(row)

    async def record_error(self, asset_id: int, error: str) -> CampaignAsset:
        row = await self._pool.fetchrow(
            """UPDATE assets SET error = $2 WHERE id = $1
               RETURNING id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error""",
            asset_id, error,
        )
        if row is None:
            raise KeyError(asset_id)
        return self._asset(row)

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
