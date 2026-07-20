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

    async def get_progression(self, action_id: str) -> Campaign | None:
        if (
            not isinstance(action_id, str) or not action_id.strip() or len(action_id) > 200
            or "\x00" in action_id
        ):
            raise ValueError("campaign progression action ID is invalid")
        row = await self._pool.fetchrow(
            """SELECT c.id, c.project_id, c.target_asset_id, c.configuration_asset_id,
                      c.engine, c.started_at, c.stopped_at, c.last_heartbeat_at,
                      c.cpu_seconds, c.next_review_after, c.next_review_reason, c.error
               FROM campaign_progression_actions AS action
               JOIN campaigns AS c ON c.id = action.campaign_id
               WHERE action.action_id = $1""",
            action_id,
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

    async def create_progression(
        self,
        *,
        action_id: str,
        project_id: int,
        base_campaign_id: int,
        target_asset_id: int,
        configuration_asset_id: int,
        engine: str,
        next_review_after,
        next_review_reason: str,
        configuration_purpose: str,
    ) -> Campaign:
        """Atomically bind one durable action ID to exactly one sibling campaign."""
        if (
            not isinstance(action_id, str) or not action_id.strip() or len(action_id) > 200
            or type(project_id) is not int or project_id <= 0
            or type(base_campaign_id) is not int or base_campaign_id <= 0
            or type(target_asset_id) is not int or target_asset_id <= 0
            or type(configuration_asset_id) is not int or configuration_asset_id <= 0
            or not isinstance(engine, str) or not engine.strip() or len(engine) > 100
            or getattr(next_review_after, "tzinfo", None) is None
            or not isinstance(next_review_reason, str) or not next_review_reason.strip()
            or len(next_review_reason) > 1_000
            or not isinstance(configuration_purpose, str)
            or not configuration_purpose.strip() or len(configuration_purpose) > 2_000
            or "\x00" in action_id or "\x00" in configuration_purpose
        ):
            raise ValueError("campaign progression persistence is invalid")
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    action_id,
                )
                existing = await connection.fetchrow(
                    """SELECT c.id, c.project_id, c.target_asset_id, c.configuration_asset_id,
                              c.engine, c.started_at, c.stopped_at, c.last_heartbeat_at,
                              c.cpu_seconds, c.next_review_after, c.next_review_reason, c.error,
                              action.base_campaign_id AS action_base_campaign_id
                       FROM campaign_progression_actions AS action
                       JOIN campaigns AS c ON c.id = action.campaign_id
                       WHERE action.action_id = $1""",
                    action_id,
                )
                if existing is not None:
                    if (
                        existing["action_base_campaign_id"] != base_campaign_id
                        or existing["project_id"] != project_id
                        or existing["target_asset_id"] != target_asset_id
                        or existing["configuration_asset_id"] != configuration_asset_id
                        or existing["engine"] != engine.strip()
                    ):
                        raise ValueError("progression action is bound to a different campaign identity")
                    return self._campaign_fields(existing)
                row = await connection.fetchrow(
                    """WITH created AS (
                           INSERT INTO campaigns
                               (project_id, target_asset_id, configuration_asset_id, engine,
                                next_review_after, next_review_reason)
                           VALUES ($2, $4, $5, $6, $7, $8)
                           RETURNING id, project_id, target_asset_id, configuration_asset_id,
                                     engine, started_at, stopped_at, last_heartbeat_at,
                                     cpu_seconds, next_review_after, next_review_reason, error
                       ), context AS (
                           INSERT INTO campaign_contexts (campaign_id, configuration_purpose)
                           SELECT id, $9 FROM created RETURNING campaign_id
                       ), action AS (
                           INSERT INTO campaign_progression_actions
                               (action_id, base_campaign_id, campaign_id)
                           SELECT $1, $3, id FROM created RETURNING campaign_id
                       )
                       SELECT created.* FROM created
                       JOIN context ON context.campaign_id = created.id
                       JOIN action ON action.campaign_id = created.id""",
                    action_id,
                    project_id,
                    base_campaign_id,
                    target_asset_id,
                    configuration_asset_id,
                    engine.strip(),
                    next_review_after,
                    next_review_reason.strip(),
                    configuration_purpose.strip(),
                )
                if row is None:
                    raise RuntimeError("campaign progression creation did not return a row")
                return self._campaign(row)

    async def record_progression_error(
        self, action_id: str, campaign_id: int, error: str,
    ) -> bool:
        if (
            not isinstance(action_id, str) or not action_id.strip() or len(action_id) > 200
            or type(campaign_id) is not int or campaign_id <= 0
            or not isinstance(error, str) or not error.strip() or len(error) > 2_000
            or "\x00" in action_id or "\x00" in error
        ):
            raise ValueError("campaign progression error is invalid")
        value = await self._pool.fetchval(
            """UPDATE campaigns AS campaign SET error = $3
               FROM campaign_progression_actions AS action
               WHERE action.action_id = $1
                 AND action.campaign_id = $2
                 AND campaign.id = action.campaign_id
                 AND campaign.stopped_at IS NULL
               RETURNING campaign.id""",
            action_id, campaign_id, error.strip(),
        )
        return value == campaign_id

    async def clear_progression_error(self, action_id: str, campaign_id: int) -> bool:
        if (
            not isinstance(action_id, str) or not action_id.strip() or len(action_id) > 200
            or type(campaign_id) is not int or campaign_id <= 0
            or "\x00" in action_id
        ):
            raise ValueError("campaign progression identity is invalid")
        value = await self._pool.fetchval(
            """UPDATE campaigns AS campaign SET error = NULL
               FROM campaign_progression_actions AS action
               WHERE action.action_id = $1
                 AND action.campaign_id = $2
                 AND campaign.id = action.campaign_id
                 AND campaign.stopped_at IS NULL
               RETURNING campaign.id""",
            action_id, campaign_id,
        )
        return value == campaign_id

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

    async def for_finding(self, project_id: int, fingerprint: str) -> list[Campaign]:
        rows = await self._pool.fetch(
            """SELECT campaign.id, campaign.project_id, campaign.target_asset_id,
                      campaign.configuration_asset_id, campaign.engine, campaign.started_at,
                      campaign.stopped_at, campaign.last_heartbeat_at, campaign.cpu_seconds,
                      campaign.next_review_after, campaign.next_review_reason, campaign.error
                 FROM campaigns AS campaign
                 JOIN campaign_crash_groups AS crash ON crash.campaign_id = campaign.id
                WHERE campaign.project_id = $1 AND crash.fingerprint = $2
                ORDER BY campaign.id LIMIT $3""",
            project_id, fingerprint, self._MAX_PROJECT_CAMPAIGNS + 1,
        )
        if len(rows) > self._MAX_PROJECT_CAMPAIGNS:
            raise OverflowError("finding campaign read limit exceeded")
        return [self._campaign(row) for row in rows]

    async def list_with_assets_for_project(
        self, project_id: int,
    ) -> tuple[list[Campaign], list[CampaignAsset]]:
        """Read campaign state and its project-owned names without adding persistence state."""
        campaigns = await self.list_for_project(project_id)
        referenced_ids = sorted({
            asset_id
            for campaign in campaigns
            for asset_id in (campaign.target_asset_id, campaign.configuration_asset_id)
            if asset_id is not None
        })
        if not referenced_ids:
            return campaigns, []
        rows = await self._pool.fetch(
            """SELECT id, project_id, kind, name, content_hash, parent_id, created_at, validated_at, error
               FROM assets
               WHERE project_id = $1
                 AND (id = ANY($2::bigint[]) OR parent_id = ANY($2::bigint[]))
               ORDER BY created_at, id LIMIT $3""",
            project_id, referenced_ids,
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

    async def stop_for_worker_limit(
        self, project_id: int, campaign_id: int, retirement_reason: str,
    ) -> bool:
        if not isinstance(retirement_reason, str) or not retirement_reason.strip() or len(retirement_reason) > 1_024:
            raise ValueError("worker-limit retirement reason is invalid")
        stopped_id = await self._pool.fetchval(
            """WITH stopped AS (
                   UPDATE campaigns SET stopped_at = CURRENT_TIMESTAMP,
                       next_review_after = NULL, next_review_reason = NULL
                   WHERE id = $2 AND project_id = $1 AND stopped_at IS NULL
                   RETURNING id
               ), recorded AS (
                   UPDATE campaign_contexts SET retirement_reason = $3
                   WHERE campaign_id = (SELECT id FROM stopped)
                   RETURNING campaign_id
               )
               SELECT campaign_id FROM recorded""",
            project_id, campaign_id, retirement_reason.strip(),
        )
        return stopped_id == campaign_id

    async def schedule_next_reviews(self, project_id: int, deadline, reason: str) -> bool:
        if (
            getattr(deadline, "tzinfo", None) is None
            or not isinstance(reason, str) or not reason.strip() or len(reason) > 1_000
        ):
            raise ValueError("campaign review schedule is invalid")
        value = await self._pool.fetchval(
            """WITH updated AS (
                   UPDATE campaigns SET
                       next_review_reason = CASE
                           WHEN next_review_after IS NULL OR $2 < next_review_after
                                OR next_review_after <= CURRENT_TIMESTAMP THEN $3
                           ELSE next_review_reason
                       END,
                       next_review_after = CASE
                           WHEN next_review_after IS NULL
                                OR next_review_after <= CURRENT_TIMESTAMP THEN $2
                           ELSE LEAST(next_review_after, $2)
                       END
                   WHERE project_id = $1 AND stopped_at IS NULL
                   RETURNING id
               ) SELECT COUNT(*) FROM updated""",
            project_id, deadline, reason.strip(),
        )
        return int(value) > 0

    @staticmethod
    def _campaign(row) -> Campaign:
        return Campaign(**dict(row))

    @staticmethod
    def _campaign_fields(row) -> Campaign:
        names = (
            "id", "project_id", "target_asset_id", "configuration_asset_id", "engine",
            "started_at", "stopped_at", "last_heartbeat_at", "cpu_seconds",
            "next_review_after", "next_review_reason", "error",
        )
        return Campaign(**{name: row[name] for name in names})
