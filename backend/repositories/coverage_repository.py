"""SQL access for coverage evidence only."""

from backend.models.coverage import CoverageEvidence


class CoverageRepository:
    def __init__(self, pool):
        self._pool = pool

    async def get(self, evidence_id: int) -> CoverageEvidence | None:
        row = await self._pool.fetchrow(
            """SELECT id, project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
                      first_testcase_sha256, cpu_exposure_seconds
               FROM coverage_evidence WHERE id = $1""",
            evidence_id,
        )
        return self._coverage(row) if row else None

    async def create(
        self, *, project_id: int, commit_sha: str, source_path: str, line_number: int,
        function_name: str | None, campaign_id: int, asset_id: int,
        first_testcase_sha256: str, cpu_exposure_seconds: float,
    ) -> CoverageEvidence:
        row = await self._pool.fetchrow(
            """INSERT INTO coverage_evidence
                      (project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
                       first_testcase_sha256, cpu_exposure_seconds)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               RETURNING id, project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
                         first_testcase_sha256, cpu_exposure_seconds""",
            project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
            first_testcase_sha256, cpu_exposure_seconds,
        )
        if row is None:
            raise RuntimeError("coverage evidence creation did not return a row")
        return self._coverage(row)

    async def list_for_project(self, project_id: int) -> list[CoverageEvidence]:
        rows = await self._pool.fetch(
            """SELECT id, project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
                      first_testcase_sha256, cpu_exposure_seconds
               FROM coverage_evidence WHERE project_id = $1 ORDER BY source_path, line_number, id""",
            project_id,
        )
        return [self._coverage(row) for row in rows]

    @staticmethod
    def _coverage(row) -> CoverageEvidence:
        return CoverageEvidence(**dict(row))
