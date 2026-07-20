"""SQL access for campaign assets and exact target validation attempts."""

from hashlib import sha256

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
                 AND (kind <> 'harness' OR EXISTS (
                     SELECT 1 FROM target_probe_attempts AS attempt
                     WHERE attempt.project_id = assets.project_id
                       AND attempt.target_asset_id = assets.id
                       AND attempt.successful IS TRUE
                 ))
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
                 AND (kind <> 'harness' OR EXISTS (
                     SELECT 1 FROM target_probe_attempts AS attempt
                     WHERE attempt.project_id = assets.project_id
                       AND attempt.target_asset_id = assets.id
                       AND attempt.successful IS TRUE
                 ))
               ORDER BY id DESC LIMIT 1""",
            project_id, kind, name,
        )
        return self._asset(row) if row else None

    async def deletion_evidence(self, project_id: int, asset_id: int) -> dict | None:
        """Read complete absence evidence for a never-functional target candidate."""
        if type(project_id) is not int or project_id <= 0 or type(asset_id) is not int or asset_id <= 0:
            raise ValueError("asset lifecycle identity is invalid")
        row = await self._pool.fetchrow(
            """SELECT asset.id, asset.kind, asset.content_hash,
                      COUNT(attempt.id) AS probe_attempts,
                      COUNT(attempt.id) FILTER (WHERE attempt.successful IS FALSE) AS failed_probe_attempts,
                      COALESCE(MAX(attempt.id), 0) AS attempt_revision,
                      EXISTS (
                          SELECT 1 FROM campaigns AS campaign
                          WHERE campaign.project_id = asset.project_id
                            AND campaign.target_asset_id = asset.id
                      ) AS accepted_campaign,
                      COALESCE(BOOL_OR(attempt.successful), FALSE) AS successful_probe,
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
               LEFT JOIN target_probe_attempts AS attempt
                 ON attempt.project_id = asset.project_id
                AND attempt.target_asset_id = asset.id
               WHERE asset.id = $2 AND asset.project_id = $1
               GROUP BY asset.id, asset.kind, asset.content_hash""",
            project_id, asset_id,
        )
        if row is None:
            return None
        values = dict(row)
        return {
            "complete": True,
            "asset_kind": values["kind"],
            "asset_content_hash": values["content_hash"],
            "probe_attempts": int(values["probe_attempts"]),
            "failed_probe_attempts": int(values["failed_probe_attempts"]),
            "attempt_revision": int(values["attempt_revision"]),
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

    async def record_probe_attempt(
        self, *, project_id: int, target_asset_id: int, proposal_result_id: str,
        operation: str, successful: bool, outcome: str,
    ) -> str:
        if (
            type(project_id) is not int or project_id <= 0
            or type(target_asset_id) is not int or target_asset_id <= 0
            or not isinstance(proposal_result_id, str) or not proposal_result_id
            or operation not in {"build", "probe"}
            or type(successful) is not bool
            or not isinstance(outcome, str) or not outcome.strip() or len(outcome) > 2_000
        ):
            raise ValueError("target probe attempt is invalid")
        digest = sha256(
            f"{project_id}\0{target_asset_id}\0{proposal_result_id}\0{operation}\0"
            f"{int(successful)}\0{outcome.strip()}".encode("utf-8")
        ).hexdigest()
        evidence_id = f"target-attempt:{project_id}:{digest}"
        value = await self._pool.fetchval(
            """INSERT INTO target_probe_attempts
                      (project_id, target_asset_id, proposal_result_id, operation,
                       successful, evidence_id, outcome)
               SELECT $1, asset.id, $3, $4, $5, $6, $7
                 FROM assets AS asset
                WHERE asset.id = $2 AND asset.project_id = $1 AND asset.kind = 'harness'
               ON CONFLICT (evidence_id) DO UPDATE SET evidence_id = EXCLUDED.evidence_id
               RETURNING evidence_id""",
            project_id, target_asset_id, proposal_result_id, operation,
            successful, evidence_id, outcome.strip(),
        )
        if value != evidence_id:
            raise ValueError("target probe attempt does not reference an exact harness asset")
        return evidence_id

    async def delete_authorized(
        self, *, project_id: int, asset_id: int, content_hash: str, attempt_revision: int,
    ) -> bool:
        """Delete only the exact unreferenced failed target revision authorised by lifecycle CAS."""
        deleted = await self._pool.fetchval(
            """DELETE FROM assets AS asset
               WHERE asset.id = $2 AND asset.project_id = $1 AND asset.kind = 'harness'
                 AND asset.content_hash = $3
                 AND NOT EXISTS (SELECT 1 FROM campaigns WHERE target_asset_id = asset.id)
                 AND NOT EXISTS (
                     SELECT 1 FROM target_probe_attempts
                      WHERE target_asset_id = asset.id AND successful IS TRUE
                 )
                 AND (SELECT COALESCE(MAX(id), 0) FROM target_probe_attempts
                       WHERE target_asset_id = asset.id) = $4
                 AND EXISTS (
                     SELECT 1 FROM target_probe_attempts
                      WHERE target_asset_id = asset.id AND successful IS FALSE
                 )
               RETURNING asset.id""",
            project_id, asset_id, content_hash, attempt_revision,
        )
        return deleted == asset_id

    async def delete_overlap_authorized(
        self, *, project_id: int, asset_id: int, content_hash: str, revision: int,
    ) -> bool:
        """Detach one stopped strategy configuration and delete its exact unused version."""
        if revision != asset_id:
            return False
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                asset = await connection.fetchrow(
                    """SELECT id, kind, content_hash FROM assets
                       WHERE id = $2 AND project_id = $1 FOR UPDATE""",
                    project_id, asset_id,
                )
                if asset is None or asset["content_hash"] != content_hash or asset["kind"] == "harness":
                    return False
                active = await connection.fetchval(
                    """SELECT EXISTS (
                           SELECT 1 FROM campaigns
                            WHERE project_id = $1 AND configuration_asset_id = $2
                              AND stopped_at IS NULL
                       )""",
                    project_id, asset_id,
                )
                if active:
                    return False
                await connection.execute(
                    """UPDATE campaigns SET configuration_asset_id = NULL
                       WHERE project_id = $1 AND configuration_asset_id = $2
                         AND stopped_at IS NOT NULL""",
                    project_id, asset_id,
                )
                deleted = await connection.fetchval(
                    """DELETE FROM assets
                       WHERE id = $2 AND project_id = $1 AND content_hash = $3
                         AND NOT EXISTS (
                             SELECT 1 FROM campaigns
                              WHERE target_asset_id = assets.id
                                 OR configuration_asset_id = assets.id
                         )
                       RETURNING id""",
                    project_id, asset_id, content_hash,
                )
                return deleted == asset_id

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
