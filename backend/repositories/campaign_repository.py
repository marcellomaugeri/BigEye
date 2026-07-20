"""SQL access for campaigns only."""

import math
import re

from backend.models.asset import CampaignAsset
from backend.models.campaign import Campaign


class CampaignRepository:
    _MAX_PROJECT_ASSETS = 1_000
    _MAX_PROJECT_CAMPAIGNS = 256

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

    async def create(
        self,
        *,
        project_id: int,
        target_asset_id: int,
        configuration_asset_id: int | None,
        engine: str,
        next_review_after,
        next_review_reason: str,
        configuration_purpose: str,
    ) -> Campaign:
        if (
            not isinstance(configuration_purpose, str)
            or not configuration_purpose.strip()
            or len(configuration_purpose) > 2_000
            or "\x00" in configuration_purpose
        ):
            raise ValueError("campaign configuration purpose is invalid")
        row = await self._pool.fetchrow(
            """WITH created AS (
                   INSERT INTO campaigns
                       (project_id, target_asset_id, configuration_asset_id, engine,
                        next_review_after, next_review_reason)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   RETURNING id, project_id, target_asset_id, configuration_asset_id, engine,
                             started_at, stopped_at, last_heartbeat_at, cpu_seconds,
                             next_review_after, next_review_reason, error
               ), context AS (
                   INSERT INTO campaign_contexts (campaign_id, configuration_purpose)
                   SELECT id, $7 FROM created RETURNING campaign_id
               )
               SELECT created.* FROM created JOIN context ON context.campaign_id = created.id""",
            project_id,
            target_asset_id,
            configuration_asset_id,
            engine,
            next_review_after,
            next_review_reason,
            configuration_purpose.strip(),
        )
        if row is None:
            raise RuntimeError("campaign creation did not return a row")
        return self._campaign(row)

    async def record_error(self, campaign_id: int, error: str) -> None:
        await self._pool.execute(
            """UPDATE campaigns
               SET stopped_at = CURRENT_TIMESTAMP, error = $2,
                   next_review_after = NULL, next_review_reason = NULL
               WHERE id = $1""",
            campaign_id,
            error,
        )

    async def record_heartbeat(self, campaign_id: int, observed_at) -> bool:
        value = await self._pool.fetchval(
            """UPDATE campaigns
               SET last_heartbeat_at = GREATEST(COALESCE(last_heartbeat_at, $2), $2)
               WHERE id = $1 AND stopped_at IS NULL
                 AND (last_heartbeat_at IS NULL OR last_heartbeat_at < $2)
               RETURNING id""",
            campaign_id, observed_at,
        )
        return value == campaign_id

    async def cumulative_cpu_seconds(
        self, campaign_id: int, container_id: str, raw_cpu_seconds: float,
    ) -> float:
        if (
            type(campaign_id) is not int or campaign_id <= 0
            or not isinstance(container_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", container_id)
            or isinstance(raw_cpu_seconds, bool)
            or not isinstance(raw_cpu_seconds, (int, float))
            or not math.isfinite(raw_cpu_seconds) or raw_cpu_seconds < 0
        ):
            raise ValueError("campaign container CPU observation is invalid")
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                campaign = await connection.fetchrow(
                    "SELECT cpu_seconds FROM campaigns WHERE id = $1 FOR UPDATE",
                    campaign_id,
                )
                if campaign is None:
                    raise KeyError(campaign_id)
                counter = await connection.fetchrow(
                    """SELECT base_cpu_seconds, last_raw_cpu_seconds
                       FROM campaign_container_counters
                       WHERE campaign_id = $1 AND container_id = $2 FOR UPDATE""",
                    campaign_id, container_id,
                )
                raw = float(raw_cpu_seconds)
                if counter is None:
                    base = float(campaign["cpu_seconds"])
                    await connection.execute(
                        """INSERT INTO campaign_container_counters
                                  (campaign_id, container_id, base_cpu_seconds, last_raw_cpu_seconds)
                           VALUES ($1, $2, $3, $4)""",
                        campaign_id, container_id, base, raw,
                    )
                else:
                    base = float(counter["base_cpu_seconds"])
                    if raw < float(counter["last_raw_cpu_seconds"]):
                        raise ValueError("campaign container CPU counter decreased")
                    await connection.execute(
                        """UPDATE campaign_container_counters SET last_raw_cpu_seconds = $3
                           WHERE campaign_id = $1 AND container_id = $2""",
                        campaign_id, container_id, raw,
                    )
                cumulative = base + raw
                if cumulative < float(campaign["cpu_seconds"]):
                    raise ValueError("campaign cumulative CPU observation decreased")
                return cumulative

    async def list_contexts_for_project(self, project_id: int) -> dict[int, dict[str, str | None]]:
        rows = await self._pool.fetch(
            """SELECT c.id AS campaign_id, cc.configuration_purpose, cc.retirement_reason
               FROM campaigns AS c JOIN campaign_contexts AS cc ON cc.campaign_id = c.id
               WHERE c.project_id = $1 ORDER BY c.id LIMIT $2""",
            project_id, self._MAX_PROJECT_CAMPAIGNS + 1,
        )
        if len(rows) > self._MAX_PROJECT_CAMPAIGNS:
            raise OverflowError("campaign context read limit exceeded")
        return {
            int(row["campaign_id"]): {
                "configuration_purpose": str(row["configuration_purpose"]),
                "retirement_reason": (
                    str(row["retirement_reason"]) if row["retirement_reason"] is not None else None
                ),
            }
            for row in rows
        }

    async def list_for_project(self, project_id: int) -> list[Campaign]:
        rows = await self._pool.fetch(
            """SELECT id, project_id, target_asset_id, configuration_asset_id, engine, started_at, stopped_at,
                      last_heartbeat_at, cpu_seconds, next_review_after, next_review_reason, error
               FROM campaigns WHERE project_id = $1 ORDER BY started_at, id LIMIT $2""",
            project_id,
            self._MAX_PROJECT_CAMPAIGNS + 1,
        )
        if len(rows) > self._MAX_PROJECT_CAMPAIGNS:
            raise OverflowError("campaign read limit exceeded")
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

    async def stop_redundant(
        self,
        *,
        project_id: int,
        campaign_id: int,
        strategy_asset_id: int,
        retained_campaign_id: int,
        retained_strategy_asset_id: int,
        retirement_reason: str,
    ) -> bool:
        """Stop only while the selected and retained identities are still exact and active."""
        if not isinstance(retirement_reason, str) or not retirement_reason.strip() or len(retirement_reason) > 1_024:
            raise ValueError("retirement reason is invalid")
        stopped_id = await self._pool.fetchval(
            """WITH stopped AS (
               UPDATE campaigns AS candidate
               SET stopped_at = CURRENT_TIMESTAMP,
                   next_review_after = NULL,
                   next_review_reason = NULL
               FROM campaigns AS retained
               WHERE candidate.id = $2
                 AND candidate.project_id = $1
                 AND candidate.stopped_at IS NULL
                 AND $3 IN (candidate.target_asset_id, candidate.configuration_asset_id)
                 AND retained.id = $4
                 AND retained.project_id = $1
                 AND retained.stopped_at IS NULL
                 AND $5 IN (retained.target_asset_id, retained.configuration_asset_id)
                 AND candidate.id <> retained.id
               RETURNING candidate.id
               ), recorded AS (
                   UPDATE campaign_contexts
                   SET retirement_reason = $6
                   WHERE campaign_id = (SELECT id FROM stopped)
                   RETURNING campaign_id
               )
               SELECT campaign_id FROM recorded""",
            project_id,
            campaign_id,
            strategy_asset_id,
            retained_campaign_id,
            retained_strategy_asset_id,
            retirement_reason.strip(),
        )
        return stopped_id == campaign_id

    @staticmethod
    def _campaign(row) -> Campaign:
        return Campaign(**dict(row))
