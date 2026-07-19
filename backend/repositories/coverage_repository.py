"""Bounded SQL access and atomic first-winner claims for coverage evidence."""

from __future__ import annotations

from contextlib import asynccontextmanager
from hashlib import sha256

from backend.models.coverage import CoverageEvidence


_COLUMNS = (
    "id, project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id, "
    "first_testcase_sha256, cpu_exposure_seconds"
)


class CoverageClaim:
    """One logical first-hit key protected by a PostgreSQL transaction lock."""

    def __init__(self, connection, key, existing):
        self._connection = connection
        self._key = key
        self.existing = existing

    async def create(
        self, *, function_name: str | None, campaign_id: int,
        first_testcase_sha256: str, cpu_exposure_seconds: float,
    ) -> CoverageEvidence:
        if self.existing is not None:
            return self.existing
        project_id, commit_sha, source_path, line_number, asset_id = self._key
        row = await self._connection.fetchrow(
            f"""INSERT INTO coverage_evidence
                       (project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
                        first_testcase_sha256, cpu_exposure_seconds)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING {_COLUMNS}""",
            project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
            first_testcase_sha256, cpu_exposure_seconds,
        )
        if row is None:
            raise RuntimeError("coverage evidence creation did not return a row")
        self.existing = CoverageRepository._coverage(row)
        return self.existing


class CoverageRepository:
    def __init__(self, pool):
        self._pool = pool

    async def get(self, evidence_id: int) -> CoverageEvidence | None:
        row = await self._pool.fetchrow(
            f"SELECT {_COLUMNS} FROM coverage_evidence WHERE id = $1",
            evidence_id,
        )
        return self._coverage(row) if row else None

    async def create(
        self, *, project_id: int, commit_sha: str, source_path: str, line_number: int,
        function_name: str | None, campaign_id: int, asset_id: int,
        first_testcase_sha256: str, cpu_exposure_seconds: float,
    ) -> CoverageEvidence:
        row = await self._pool.fetchrow(
            f"""INSERT INTO coverage_evidence
                       (project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
                        first_testcase_sha256, cpu_exposure_seconds)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING {_COLUMNS}""",
            project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
            first_testcase_sha256, cpu_exposure_seconds,
        )
        if row is None:
            raise RuntimeError("coverage evidence creation did not return a row")
        return self._coverage(row)

    @asynccontextmanager
    async def claim(self, *, project_id: int, commit_sha: str, source_path: str, line_number: int, asset_id: int):
        key = (project_id, commit_sha, source_path, line_number, asset_id)
        lock_key = int.from_bytes(
            sha256("\0".join(map(str, key)).encode("utf-8")).digest()[:8], "big", signed=True
        )
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT pg_advisory_xact_lock($1)", lock_key)
                row = await connection.fetchrow(
                    f"""SELECT {_COLUMNS} FROM coverage_evidence
                        WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                          AND line_number = $4 AND asset_id = $5
                        ORDER BY id LIMIT 1""",
                    *key,
                )
                yield CoverageClaim(connection, key, self._coverage(row) if row else None)

    async def list_commits(self, project_id: int) -> list[str]:
        rows = await self._pool.fetch(
            "SELECT DISTINCT commit_sha FROM coverage_evidence WHERE project_id = $1 ORDER BY commit_sha LIMIT 2",
            project_id,
        )
        return [str(row["commit_sha"]) for row in rows]

    async def list_for_project(self, project_id: int, limit: int = 1_000, offset: int = 0) -> list[CoverageEvidence]:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            f"""SELECT {_COLUMNS} FROM coverage_evidence
                WHERE project_id = $1 ORDER BY source_path, line_number, id LIMIT $2 OFFSET $3""",
            project_id, limit, offset,
        )
        return [self._coverage(row) for row in rows]

    async def list_for_source(
        self, project_id: int, commit_sha: str, source_path: str, limit: int = 1_000, offset: int = 0,
    ) -> list[CoverageEvidence]:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            f"""SELECT {_COLUMNS} FROM coverage_evidence
                WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                ORDER BY line_number, id LIMIT $4 OFFSET $5""",
            project_id, commit_sha, source_path, limit, offset,
        )
        return [self._coverage(row) for row in rows]

    async def list_for_line(
        self, project_id: int, commit_sha: str, source_path: str, line_number: int,
        limit: int = 500, offset: int = 0,
    ) -> list[CoverageEvidence]:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            f"""SELECT {_COLUMNS} FROM coverage_evidence
                WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3 AND line_number = $4
                ORDER BY id LIMIT $5 OFFSET $6""",
            project_id, commit_sha, source_path, line_number, limit, offset,
        )
        return [self._coverage(row) for row in rows]

    @staticmethod
    def _validate_page(limit, offset):
        if type(limit) is not int or not 1 <= limit <= 5_000 or type(offset) is not int or not 0 <= offset <= 10_000_000:
            raise ValueError("coverage pagination is outside its bounded range")

    @staticmethod
    def _coverage(row) -> CoverageEvidence:
        return CoverageEvidence(**dict(row))
