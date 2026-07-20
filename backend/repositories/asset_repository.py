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

    async def find_validated(
        self, project_id: int, kind: str, name: str, content_hash: str, parent_id: int | None,
    ) -> CampaignAsset | None:
        row = await self._pool.fetchrow(
            """SELECT id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error
               FROM assets
               WHERE project_id = $1 AND kind = $2 AND name = $3 AND content_hash = $4
                 AND parent_id IS NOT DISTINCT FROM $5
                 AND validated_at IS NOT NULL AND error IS NULL
               ORDER BY id LIMIT 1""",
            project_id, kind, name, content_hash, parent_id,
        )
        return self._asset(row) if row else None

    async def find_validated_content(
        self, project_id: int, kind: str, name: str, content_hash: str,
    ) -> CampaignAsset | None:
        """Find an exact reusable version regardless of its validated parent ancestry."""
        row = await self._pool.fetchrow(
            """SELECT id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error
               FROM assets
               WHERE project_id = $1 AND kind = $2 AND name = $3 AND content_hash = $4
                 AND validated_at IS NOT NULL AND error IS NULL
               ORDER BY id DESC LIMIT 1""",
            project_id, kind, name, content_hash,
        )
        return self._asset(row) if row else None

    async def latest_validated(
        self, project_id: int, kind: str, name: str,
    ) -> CampaignAsset | None:
        """Return the newest healthy version to use as a small-edit CAS parent."""
        row = await self._pool.fetchrow(
            """SELECT id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error
               FROM assets
               WHERE project_id = $1 AND kind = $2 AND name = $3
                 AND validated_at IS NOT NULL AND error IS NULL
               ORDER BY id DESC LIMIT 1""",
            project_id, kind, name,
        )
        return self._asset(row) if row else None

    async def deletion_evidence(self, project_id: int, asset_id: int) -> dict | None:
        """Read complete absence evidence for a never-functional target candidate."""
        if type(project_id) is not int or project_id <= 0 or type(asset_id) is not int or asset_id <= 0:
            raise ValueError("asset lifecycle identity is invalid")
        row = await self._pool.fetchrow(
            """SELECT asset.id,
                      EXISTS (
                          SELECT 1 FROM campaigns AS campaign
                          WHERE campaign.project_id = asset.project_id
                            AND campaign.target_asset_id = asset.id
                      ) AS accepted_campaign,
                      EXISTS (
                          SELECT 1 FROM campaigns AS campaign
                          WHERE campaign.project_id = asset.project_id
                            AND campaign.target_asset_id = asset.id
                      ) AS successful_probe,
                      EXISTS (
                          SELECT 1 FROM campaigns AS campaign
                          JOIN coverage_evidence AS coverage
                            ON coverage.project_id = campaign.project_id
                           AND coverage.campaign_id = campaign.id
                          WHERE campaign.project_id = asset.project_id
                            AND campaign.target_asset_id = asset.id
                      ) AS useful_clean_coverage,
                      ARRAY(
                          SELECT DISTINCT finding.id::text
                          FROM campaigns AS campaign
                          JOIN campaign_crash_groups AS crash
                            ON crash.campaign_id = campaign.id
                          JOIN findings AS finding
                            ON finding.project_id = campaign.project_id
                           AND finding.fingerprint = crash.fingerprint
                          WHERE campaign.project_id = asset.project_id
                            AND campaign.target_asset_id = asset.id
                          ORDER BY finding.id::text
                      ) AS finding_dependencies
               FROM assets AS asset
               WHERE asset.id = $2 AND asset.project_id = $1""",
            project_id, asset_id,
        )
        if row is None:
            return None
        values = dict(row)
        return {
            "complete": True,
            "successful_probe": bool(values["successful_probe"]),
            "accepted_campaign": bool(values["accepted_campaign"]),
            "useful_clean_coverage": bool(values["useful_clean_coverage"]),
            "finding_dependencies": tuple(values["finding_dependencies"] or ()),
            "evidence_ids": (
                f"asset:{project_id}:{asset_id}",
                f"campaign-absence:{project_id}:{asset_id}",
                f"coverage-absence:{project_id}:{asset_id}",
                f"finding-dependency-check:{project_id}:{asset_id}",
            ),
        }

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
