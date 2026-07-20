"""Bounded SQL access and atomic first-winner claims for coverage evidence."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from hashlib import sha256
import math

from backend.models.coverage import CoverageEvidence


_COLUMNS = (
    "id, project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id, "
    "first_testcase_sha256, cpu_exposure_seconds"
)
_COLUMN_NAMES = tuple(part.strip() for part in _COLUMNS.split(","))
_PAGE_COLUMNS = ", ".join(f"page.{name}" for name in _COLUMN_NAMES)


@dataclass(frozen=True)
class CoveragePage:
    items: tuple
    total: int


class CoverageClaim:
    """One logical first-hit key protected by a PostgreSQL transaction lock."""

    def __init__(self, connection, key, existing):
        self._connection = connection
        self._key = key
        self.existing = existing
        self.created = False

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
                ON CONFLICT (project_id, commit_sha, source_path, line_number, asset_id) DO NOTHING
                RETURNING {_COLUMNS}""",
            project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
            first_testcase_sha256, cpu_exposure_seconds,
        )
        if row is None:
            row = await self._connection.fetchrow(
                f"""SELECT {_COLUMNS} FROM coverage_evidence
                    WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                      AND line_number = $4 AND asset_id = $5
                    ORDER BY id LIMIT 1""",
                *self._key,
            )
            if row is None:
                raise RuntimeError("coverage evidence conflict did not return its winner")
        else:
            self.created = True
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
                ON CONFLICT (project_id, commit_sha, source_path, line_number, asset_id) DO NOTHING
                RETURNING {_COLUMNS}""",
            project_id, commit_sha, source_path, line_number, function_name, campaign_id, asset_id,
            first_testcase_sha256, cpu_exposure_seconds,
        )
        if row is None:
            row = await self._pool.fetchrow(
                f"""SELECT {_COLUMNS} FROM coverage_evidence
                    WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                      AND line_number = $4 AND asset_id = $5
                    ORDER BY id LIMIT 1""",
                project_id, commit_sha, source_path, line_number, asset_id,
            )
            if row is None:
                raise RuntimeError("coverage evidence conflict did not return its winner")
        return self._coverage(row)

    async def apply_exposure_observation(
        self, *, campaign_id: int, observed_cpu_seconds: float,
        reached_lines: tuple[tuple[str, int], ...],
    ) -> bool:
        """Atomically advance a campaign CPU watermark and its exact reached lines."""
        if type(campaign_id) is not int or campaign_id <= 0:
            raise ValueError("campaign ID must be a positive integer")
        if (
            isinstance(observed_cpu_seconds, bool)
            or not isinstance(observed_cpu_seconds, (int, float))
            or not math.isfinite(observed_cpu_seconds)
            or observed_cpu_seconds < 0
        ):
            raise ValueError("observed CPU seconds must be finite and non-negative")
        if (
            not isinstance(reached_lines, tuple)
            or len(reached_lines) > 100_000
            or len(set(reached_lines)) != len(reached_lines)
            or any(
                not isinstance(item, tuple) or len(item) != 2
                or not isinstance(item[0], str) or not item[0]
                or type(item[1]) is not int or item[1] <= 0
                for item in reached_lines
            )
        ):
            raise ValueError("reached lines are invalid or exceed their bound")

        observed = float(observed_cpu_seconds)
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                campaign = await connection.fetchrow(
                    """SELECT c.project_id, p.commit_sha, c.cpu_seconds AS previous_cpu_seconds
                       FROM campaigns AS c
                       JOIN projects AS p ON p.id = c.project_id
                       WHERE c.id = $1
                       FOR UPDATE OF c""",
                    campaign_id,
                )
                if campaign is None:
                    raise KeyError(campaign_id)
                previous = float(campaign["previous_cpu_seconds"])
                if not math.isfinite(previous) or previous < 0:
                    raise ValueError("stored CPU seconds are invalid")
                if observed < previous:
                    raise ValueError("observed CPU seconds cannot decrease")
                if observed == previous:
                    return False
                delta = observed - previous

                if reached_lines:
                    paths = [path for path, _line in reached_lines]
                    line_numbers = [line for _path, line in reached_lines]
                    identities = await connection.fetch(
                        """SELECT DISTINCT ce.commit_sha, ce.asset_id
                           FROM coverage_evidence AS ce
                           JOIN assets AS a ON a.id = ce.asset_id AND a.project_id = ce.project_id
                           WHERE ce.campaign_id = $1
                             AND ce.project_id = $2
                             AND (ce.source_path, ce.line_number) IN (
                                 SELECT * FROM unnest($3::text[], $4::integer[])
                             )""",
                        campaign_id, campaign["project_id"], paths, line_numbers,
                    )
                    if len(identities) != 1 or identities[0]["commit_sha"] != campaign["commit_sha"]:
                        raise ValueError("reached lines do not share the campaign's exact clean commit and strategy")
                    strategy_asset_id = identities[0]["asset_id"]
                    updated = await connection.fetchval(
                        """WITH reached(source_path, line_number) AS (
                               SELECT * FROM unnest($4::text[], $5::integer[])
                           ), updated AS (
                               UPDATE coverage_evidence AS ce
                               SET cpu_exposure_seconds = ce.cpu_exposure_seconds + $6
                               FROM reached
                               WHERE ce.campaign_id = $1
                                 AND ce.commit_sha = $2
                                 AND ce.asset_id = $3
                                 AND ce.source_path = reached.source_path
                                 AND ce.line_number = reached.line_number
                               RETURNING ce.id
                           )
                           SELECT COUNT(*) FROM updated""",
                        campaign_id, campaign["commit_sha"], strategy_asset_id,
                        paths, line_numbers, delta,
                    )
                    if int(updated) != len(reached_lines):
                        raise ValueError("not every reached line has exact clean coverage evidence")

                await connection.execute(
                    "UPDATE campaigns SET cpu_seconds = $2 WHERE id = $1",
                    campaign_id, observed,
                )
                return True

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

    async def aggregate_project(
        self, project_id: int, commit_sha: str, limit: int = 1_000, offset: int = 0,
    ) -> CoveragePage:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            """WITH grouped AS (
                   SELECT source_path, COUNT(DISTINCT line_number) AS covered_lines,
                          SUM(cpu_exposure_seconds) AS cpu_exposure_seconds
                   FROM coverage_evidence
                   WHERE project_id = $1 AND commit_sha = $2
                   GROUP BY source_path
               ), page AS (
                   SELECT source_path, covered_lines, cpu_exposure_seconds
                   FROM grouped ORDER BY source_path LIMIT $3 OFFSET $4
               )
               SELECT page.source_path, page.covered_lines, page.cpu_exposure_seconds, total.total
               FROM (SELECT COUNT(*) AS total FROM grouped) AS total
               LEFT JOIN page ON TRUE ORDER BY page.source_path""",
            project_id, commit_sha, limit, offset,
        )
        total = int(rows[0]["total"]) if rows else 0
        return CoveragePage(tuple({
            "path": str(row["source_path"]),
            "covered_lines": int(row["covered_lines"]),
            "cpu_exposure_seconds": float(row["cpu_exposure_seconds"]),
        } for row in rows if row["source_path"] is not None), total)

    async def aggregate_functions(
        self, project_id: int, commit_sha: str, source_path: str,
        limit: int = 1_000, offset: int = 0,
    ) -> CoveragePage:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            """WITH per_campaign AS (
                   SELECT function_name, campaign_id, MAX(cpu_exposure_seconds) AS cpu_exposure_seconds
                   FROM coverage_evidence
                   WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                     AND function_name IS NOT NULL
                   GROUP BY function_name, campaign_id
               ), line_counts AS (
                   SELECT function_name, COUNT(DISTINCT line_number) AS covered_lines
                   FROM coverage_evidence
                   WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                     AND function_name IS NOT NULL
                   GROUP BY function_name
               ), grouped AS (
                   SELECT per_campaign.function_name, line_counts.covered_lines,
                          SUM(per_campaign.cpu_exposure_seconds) AS cpu_exposure_seconds
                   FROM per_campaign
                   JOIN line_counts USING (function_name)
                   GROUP BY per_campaign.function_name, line_counts.covered_lines
               ), page AS (
                   SELECT function_name, covered_lines, cpu_exposure_seconds
                   FROM grouped ORDER BY function_name LIMIT $4 OFFSET $5
               )
               SELECT page.function_name, page.covered_lines, page.cpu_exposure_seconds, total.total
               FROM (SELECT COUNT(*) AS total FROM grouped) AS total
               LEFT JOIN page ON TRUE ORDER BY page.function_name""",
            project_id, commit_sha, source_path, limit, offset,
        )
        total = int(rows[0]["total"]) if rows else 0
        return CoveragePage(tuple({
            "name": str(row["function_name"]),
            "path": source_path,
            "covered_lines": int(row["covered_lines"]),
            "cpu_exposure_seconds": float(row["cpu_exposure_seconds"]),
        } for row in rows if row["function_name"] is not None), total)

    async def aggregate_source_range(
        self, project_id: int, commit_sha: str, source_path: str, start_line: int, end_line: int,
    ) -> tuple[dict, ...]:
        if (
            type(start_line) is not int or type(end_line) is not int
            or start_line < 1 or end_line < start_line or end_line - start_line + 1 > 500
        ):
            raise ValueError("coverage source range is outside its bounded range")
        rows = await self._pool.fetch(
            """SELECT line_number, COUNT(DISTINCT asset_id) AS strategy_count,
                      SUM(cpu_exposure_seconds) AS cpu_exposure_seconds
               FROM coverage_evidence
               WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                 AND line_number BETWEEN $4 AND $5
               GROUP BY line_number ORDER BY line_number""",
            project_id, commit_sha, source_path, start_line, end_line,
        )
        return tuple({
            "line_number": int(row["line_number"]),
            "strategy_count": int(row["strategy_count"]),
            "cpu_exposure_seconds": float(row["cpu_exposure_seconds"]),
        } for row in rows)

    async def first_for_source(
        self, project_id: int, commit_sha: str, source_path: str,
    ) -> CoverageEvidence | None:
        row = await self._pool.fetchrow(
            f"""SELECT {_COLUMNS} FROM coverage_evidence
                WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                ORDER BY id LIMIT 1""",
            project_id, commit_sha, source_path,
        )
        return self._coverage(row) if row else None

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

    async def page_for_line(
        self, project_id: int, commit_sha: str, source_path: str, line_number: int,
        limit: int = 500, offset: int = 0,
    ) -> CoveragePage:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            f"""WITH matching AS (
                    SELECT {_COLUMNS} FROM coverage_evidence
                    WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3 AND line_number = $4
                ), page AS (
                    SELECT * FROM matching ORDER BY id LIMIT $5 OFFSET $6
                )
                SELECT {_PAGE_COLUMNS}, total.total
                FROM (SELECT COUNT(*) AS total FROM matching) AS total
                LEFT JOIN page ON TRUE ORDER BY page.id""",
            project_id, commit_sha, source_path, line_number, limit, offset,
        )
        total = int(rows[0]["total"]) if rows else 0
        return CoveragePage(tuple(self._coverage(row) for row in rows if row["id"] is not None), total)

    @staticmethod
    def _validate_page(limit, offset):
        if type(limit) is not int or not 1 <= limit <= 5_000 or type(offset) is not int or not 0 <= offset <= 10_000_000:
            raise ValueError("coverage pagination is outside its bounded range")

    @staticmethod
    def _coverage(row) -> CoverageEvidence:
        return CoverageEvidence(**{name: row[name] for name in _COLUMN_NAMES})
