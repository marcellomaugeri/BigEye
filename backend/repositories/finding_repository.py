"""SQL access for findings only."""

import re
from datetime import datetime

from backend.models.finding import Finding


class FindingRepository:
    def __init__(self, pool):
        self._pool = pool

    async def get(self, finding_id: int) -> Finding | None:
        row = await self._pool.fetchrow(
            """SELECT id, project_id, fingerprint, classification, priority_rank, priority_reason, description,
                      reproducible, occurrence_count, created_at, triaged_at, error
               FROM findings WHERE id = $1""",
            finding_id,
        )
        return self._finding(row) if row else None

    async def list_for_project(self, project_id: int) -> list[Finding]:
        rows, _has_more = await self.list_page(project_id, 100, None)
        return rows

    async def list_page(
        self, project_id: int, limit: int, before: tuple[int | None, datetime, int] | None,
    ) -> tuple[list[Finding], bool]:
        if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
            raise ValueError("project ID must be positive")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("finding page limit must be between one and one hundred")
        if before is not None and (
            not isinstance(before, tuple) or len(before) != 3
        ):
            raise ValueError("finding cursor boundary is invalid")
        before_rank, before_created_at, before_id = before if before is not None else (None, None, None)
        if before is not None and (
            (before_rank is not None and (
                isinstance(before_rank, bool) or not isinstance(before_rank, int) or before_rank <= 0
            ))
            or not isinstance(before_created_at, datetime) or before_created_at.tzinfo is None
            or isinstance(before_id, bool) or not isinstance(before_id, int) or before_id <= 0
        ):
            raise ValueError("finding cursor boundary is invalid")
        rows = await self._pool.fetch(
            """SELECT id, project_id, fingerprint, classification, priority_rank, priority_reason, description,
                      reproducible, occurrence_count, created_at, triaged_at, error
              FROM findings
              WHERE project_id = $1
                AND (
                    ($3::bigint IS NULL AND $4::timestamptz IS NULL)
                    OR COALESCE(priority_rank, 9223372036854775807) > COALESCE($3::bigint, 9223372036854775807)
                    OR (
                        COALESCE(priority_rank, 9223372036854775807) = COALESCE($3::bigint, 9223372036854775807)
                        AND (created_at, id) < ($4::timestamptz, $5::bigint)
                    )
                )
              ORDER BY priority_rank ASC NULLS LAST, created_at DESC, id DESC
              LIMIT $2""",
            project_id, limit + 1, before_rank, before_created_at, before_id,
        )
        has_more = len(rows) > limit
        return [self._finding(row) for row in rows[:limit]], has_more

    async def create_or_increment(
        self, *, project_id: int, fingerprint: str, classification: str,
        description: str, reproducible: bool, candidate_selected: bool,
    ) -> Finding:
        """Atomically publish one database-unique project/fingerprint crash group."""
        if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
            raise ValueError("project ID must be positive")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("finding fingerprint must be a SHA-256 digest")
        if not isinstance(classification, str) or classification not in {
            "harness-induced false positive", "improper contract usage", "true vulnerability",
            "flaky or environmental", "unresolved",
        }:
            raise ValueError("finding classification is unsupported")
        if not isinstance(description, str) or not description or len(description) > 1_000 or "\x00" in description:
            raise ValueError("finding description is invalid")
        if not isinstance(reproducible, bool):
            raise ValueError("finding reproducibility must be boolean")
        if not isinstance(candidate_selected, bool):
            raise ValueError("finding candidate selection must be boolean")
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT pg_advisory_xact_lock($1::bigint)", project_id,
                )
                candidate = await connection.fetchrow(
                    """INSERT INTO findings
                              (project_id, fingerprint, classification, priority_rank, priority_reason,
                               description, reproducible, occurrence_count, triaged_at)
                       VALUES ($1, $2, $3, NULL, NULL, $4, $5, 1, CURRENT_TIMESTAMP)
                       ON CONFLICT (project_id, fingerprint) DO UPDATE
                          SET classification = CASE WHEN $6 THEN EXCLUDED.classification ELSE findings.classification END,
                              description = CASE WHEN $6 THEN EXCLUDED.description ELSE findings.description END,
                              reproducible = CASE WHEN $6 THEN EXCLUDED.reproducible ELSE findings.reproducible END,
                              occurrence_count = findings.occurrence_count + 1,
                              triaged_at = CURRENT_TIMESTAMP,
                              error = NULL
                    RETURNING id""",
                    project_id, fingerprint, classification, description, reproducible, candidate_selected,
                )
                if candidate is None:
                    raise RuntimeError("finding publication did not return a crash group")
                await connection.execute(
                    """WITH ranked AS (
                           SELECT id,
                                  ROW_NUMBER() OVER (
                                      ORDER BY CASE classification
                                          WHEN 'true vulnerability' THEN 1
                                          WHEN 'improper contract usage' THEN 2
                                          WHEN 'unresolved' THEN 3
                                          WHEN 'flaky or environmental' THEN 4
                                          WHEN 'harness-induced false positive' THEN 5
                                          ELSE 6 END,
                                      reproducible DESC, occurrence_count DESC,
                                      created_at, fingerprint, id
                                  ) AS project_rank
                             FROM findings
                            WHERE project_id = $1
                       )
                       UPDATE findings
                          SET priority_rank = ranked.project_rank,
                              priority_reason = findings.classification || '; '
                                  || CASE WHEN findings.reproducible THEN 'reproducible' ELSE 'not reproducible' END
                                  || '; observed ' || findings.occurrence_count::text
                                  || CASE WHEN findings.occurrence_count = 1 THEN ' time' ELSE ' times' END
                         FROM ranked
                        WHERE findings.id = ranked.id""",
                    project_id,
                )
                row = await connection.fetchrow(
                    """SELECT id, project_id, fingerprint, classification, priority_rank, priority_reason,
                              description, reproducible, occurrence_count, created_at, triaged_at, error
                         FROM findings WHERE id = $1 AND project_id = $2""",
                    candidate["id"], project_id,
                )
                if row is None:
                    raise RuntimeError("ranked finding publication did not return its crash group")
                finding = self._finding(row)
                if (
                    finding.classification != classification
                    or finding.description != description
                    or finding.reproducible != reproducible
                ):
                    raise RuntimeError("finding database fields differ from selected artifact evidence")
                return finding

    async def link_campaign(self, campaign_id: int, project_id: int, fingerprint: str) -> None:
        inserted = await self._pool.fetchval(
            """INSERT INTO campaign_crash_groups (campaign_id, fingerprint)
               SELECT c.id, f.fingerprint FROM campaigns AS c
               JOIN findings AS f ON f.project_id = c.project_id AND f.fingerprint = $3
               WHERE c.id = $1 AND c.project_id = $2
               ON CONFLICT DO NOTHING RETURNING campaign_id""",
            campaign_id, project_id, fingerprint,
        )
        if inserted not in {None, campaign_id}:
            raise RuntimeError("campaign crash group link returned another campaign")

    async def groups_for_campaign(self, campaign_id: int) -> tuple[str, ...]:
        rows = await self._pool.fetch(
            """SELECT fingerprint FROM campaign_crash_groups
               WHERE campaign_id = $1 ORDER BY fingerprint LIMIT 10001""",
            campaign_id,
        )
        if len(rows) > 10_000:
            raise OverflowError("campaign crash groups exceed their bound")
        return tuple(str(row["fingerprint"]) for row in rows)

    @staticmethod
    def _finding(row) -> Finding:
        return Finding(**dict(row))
