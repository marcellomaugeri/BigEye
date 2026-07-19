"""SQL access for findings only."""

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

    @staticmethod
    def _finding(row) -> Finding:
        return Finding(**dict(row))
