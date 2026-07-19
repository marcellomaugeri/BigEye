"""SQL access for findings only."""

import re

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
        rows = await self._pool.fetch(
            """SELECT id, project_id, fingerprint, classification, priority_rank, priority_reason, description,
                      reproducible, occurrence_count, created_at, triaged_at, error
               FROM findings WHERE project_id = $1 ORDER BY created_at DESC, id DESC""",
            project_id,
        )
        return [self._finding(row) for row in rows]

    async def create_or_increment(
        self, *, project_id: int, fingerprint: str, classification: str,
        priority_rank: int | None, priority_reason: str | None,
        description: str, reproducible: bool,
    ) -> Finding:
        """Serialize one project/fingerprint group without requiring a schema constraint."""
        if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
            raise ValueError("project ID must be positive")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("finding fingerprint must be a SHA-256 digest")
        if not isinstance(classification, str) or classification not in {
            "harness-induced false positive", "improper contract usage", "true vulnerability",
            "flaky or environmental", "unresolved",
        }:
            raise ValueError("finding classification is unsupported")
        if priority_rank is not None and (
            isinstance(priority_rank, bool) or not isinstance(priority_rank, int) or not 1 <= priority_rank <= 2_147_483_647
        ):
            raise ValueError("finding priority rank must be a positive integer")
        for value, label, maximum in (
            (priority_reason, "priority reason", 2_000),
            (description, "description", 1_000),
        ):
            if value is not None and (not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value):
                raise ValueError(f"finding {label} is invalid")
        if not isinstance(reproducible, bool):
            raise ValueError("finding reproducibility must be boolean")
        row = await self._pool.fetchrow(
            """WITH locked AS MATERIALIZED (
                       SELECT pg_advisory_xact_lock(hashtextextended($1::bigint::text || ':' || $2, 0))
                   ), updated AS (
                       UPDATE findings
                          SET classification = $3,
                              priority_rank = $4,
                              priority_reason = $5,
                              description = $6,
                              reproducible = $7,
                              occurrence_count = findings.occurrence_count + 1,
                              triaged_at = CURRENT_TIMESTAMP,
                              error = NULL
                         FROM locked
                        WHERE findings.project_id = $1 AND findings.fingerprint = $2
                    RETURNING findings.id, findings.project_id, findings.fingerprint,
                              findings.classification, findings.priority_rank, findings.priority_reason,
                              findings.description, findings.reproducible, findings.occurrence_count,
                              findings.created_at, findings.triaged_at, findings.error
                   ), inserted AS (
                       INSERT INTO findings
                              (project_id, fingerprint, classification, priority_rank, priority_reason,
                               description, reproducible, occurrence_count, triaged_at)
                       SELECT $1, $2, $3, $4, $5, $6, $7, 1, CURRENT_TIMESTAMP
                         FROM locked
                        WHERE NOT EXISTS (SELECT 1 FROM updated)
                    RETURNING id, project_id, fingerprint, classification, priority_rank, priority_reason,
                              description, reproducible, occurrence_count, created_at, triaged_at, error
                   )
                   SELECT * FROM updated
                   UNION ALL
                   SELECT * FROM inserted""",
            project_id, fingerprint, classification, priority_rank, priority_reason, description, reproducible,
        )
        if row is None:
            raise RuntimeError("finding publication did not return a crash group")
        return self._finding(row)

    @staticmethod
    def _finding(row) -> Finding:
        return Finding(**dict(row))
