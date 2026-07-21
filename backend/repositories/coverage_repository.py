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
    summary: dict | None = None


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

    async def upsert_snapshot(self, snapshot) -> None:
        """Union one immutable exact-build inventory in a single transaction."""
        summaries = tuple(snapshot.source_summaries)
        functions = tuple(snapshot.functions)
        branches = tuple(snapshot.branches)
        if not summaries:
            return
        if len(summaries) > 100_000 or len(branches) > 2_000_000:
            raise ValueError("coverage snapshot exceeds its inventory bound")
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                identity = await connection.fetchrow(
                    """SELECT p.commit_sha, a.project_id AS asset_project_id
                       FROM campaigns AS c
                       JOIN projects AS p ON p.id = c.project_id
                       JOIN assets AS a ON a.id = $3
                       WHERE c.id = $1 AND c.project_id = $2
                       FOR UPDATE OF c""",
                    snapshot.campaign_id, snapshot.project_id, snapshot.coverage_asset_id,
                )
                if (
                    identity is None
                    or identity["commit_sha"] != snapshot.commit_sha
                    or int(identity["asset_project_id"]) != snapshot.project_id
                ):
                    raise ValueError("coverage snapshot is not bound to the exact project build")
                for source_path in sorted(summary.source_path for summary in summaries):
                    lock_key = int.from_bytes(
                        sha256(
                            f"{snapshot.project_id}\0{snapshot.commit_sha}\0{source_path}".encode()
                        ).digest()[:8],
                        "big", signed=True,
                    )
                    await connection.execute("SELECT pg_advisory_xact_lock($1)", lock_key)
                existing = await connection.fetch(
                    """SELECT source_path, commit_sha, source_sha256,
                              total_lines, total_functions, total_branches
                       FROM coverage_source_summaries
                       WHERE project_id = $1 AND commit_sha = $2
                         AND source_path = ANY($3::text[])
                       FOR UPDATE""",
                    snapshot.project_id, snapshot.commit_sha,
                    [summary.source_path for summary in summaries],
                )
                by_path: dict[str, list] = {}
                for row in existing:
                    by_path.setdefault(str(row["source_path"]), []).append(row)
                for summary in summaries:
                    prior_rows = by_path.get(summary.source_path, ())
                    totals = (
                        _count_total(summary.lines), _count_total(summary.functions),
                        _count_total(summary.branches),
                    )
                    if any(
                        prior["source_sha256"] != summary.source_sha256
                        or tuple(prior[name] for name in (
                            "total_lines", "total_functions", "total_branches",
                        )) != totals
                        for prior in prior_rows
                    ):
                        raise ValueError("coverage source denominator conflicts with its exact build")
                    await connection.execute(
                        """INSERT INTO coverage_source_summaries
                                  (project_id, commit_sha, coverage_asset_id, source_path,
                                   source_sha256, covered_lines, total_lines,
                                   covered_functions, total_functions,
                                   covered_branches, total_branches)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                           ON CONFLICT (project_id, coverage_asset_id, source_path) DO UPDATE SET
                               covered_lines = GREATEST(
                                   coverage_source_summaries.covered_lines, EXCLUDED.covered_lines),
                               covered_functions = GREATEST(
                                   coverage_source_summaries.covered_functions, EXCLUDED.covered_functions),
                               covered_branches = GREATEST(
                                   coverage_source_summaries.covered_branches, EXCLUDED.covered_branches)""",
                        snapshot.project_id, snapshot.commit_sha, snapshot.coverage_asset_id,
                        summary.source_path, summary.source_sha256,
                        _count_covered(summary.lines), totals[0],
                        _count_covered(summary.functions), totals[1],
                        _count_covered(summary.branches), totals[2],
                    )
                for function in functions:
                    await connection.execute(
                        """INSERT INTO coverage_function_evidence
                                  (project_id, commit_sha, coverage_asset_id, source_path,
                                   function_name, start_line, start_column, covered)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                           ON CONFLICT (project_id, coverage_asset_id, source_path,
                                        function_name, start_line, start_column) DO UPDATE SET
                               covered = coverage_function_evidence.covered OR EXCLUDED.covered""",
                        snapshot.project_id, snapshot.commit_sha, snapshot.coverage_asset_id,
                        function.source_path, function.function_name,
                        function.start_line, function.start_column, function.covered,
                    )
                for branch in branches:
                    await connection.execute(
                        """INSERT INTO coverage_branch_evidence
                                  (project_id, commit_sha, coverage_asset_id, source_path,
                                   line_number, start_column, end_line, end_column,
                                   branch_index, outcome_index, covered)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                           ON CONFLICT (project_id, coverage_asset_id, source_path,
                                        line_number, start_column, end_line, end_column,
                                        branch_index, outcome_index) DO UPDATE SET
                               covered = coverage_branch_evidence.covered OR EXCLUDED.covered""",
                        snapshot.project_id, snapshot.commit_sha, snapshot.coverage_asset_id,
                        branch.source_path, branch.line_number, branch.start_column,
                        branch.end_line, branch.end_column, branch.branch_index,
                        branch.outcome_index, branch.covered,
                    )
                await self._record_coverage_history(
                    connection, snapshot.project_id, snapshot.commit_sha,
                )

    @staticmethod
    async def _record_coverage_history(connection, project_id: int, commit_sha: str) -> None:
        totals = await connection.fetchrow(
            """WITH per_source AS (
                   SELECT source_path,
                          LEAST(MAX(covered_lines), MIN(total_lines)) AS covered_lines,
                          MIN(total_lines) AS total_lines
                   FROM coverage_source_summaries
                   WHERE project_id = $1 AND commit_sha = $2 AND total_lines IS NOT NULL
                   GROUP BY source_path
               )
               SELECT SUM(covered_lines) AS covered_lines, SUM(total_lines) AS total_lines
               FROM per_source""",
            project_id, commit_sha,
        )
        if totals is None or totals["total_lines"] is None:
            return
        covered_lines = int(totals["covered_lines"] or 0)
        total_lines = int(totals["total_lines"])
        previous = await connection.fetchrow(
            """SELECT covered_lines, total_lines FROM coverage_history
               WHERE project_id = $1 AND commit_sha = $2 ORDER BY id DESC LIMIT 1""",
            project_id, commit_sha,
        )
        if previous is not None and (
            int(previous["covered_lines"]), int(previous["total_lines"])
        ) == (covered_lines, total_lines):
            return
        await connection.execute(
            """INSERT INTO coverage_history
                      (project_id, commit_sha, covered_lines, total_lines)
               VALUES ($1, $2, $3, $4)""",
            project_id, commit_sha, covered_lines, total_lines,
        )

    async def coverage_history(
        self, project_id: int, commit_sha: str, limit: int = 128,
    ) -> tuple[dict, ...]:
        if type(limit) is not int or not 1 <= limit <= 512:
            raise ValueError("coverage history limit is outside its bounded range")
        rows = await self._pool.fetch(
            """SELECT observed_at, covered_lines, total_lines
               FROM (
                   SELECT id, observed_at, covered_lines, total_lines
                   FROM coverage_history
                   WHERE project_id = $1 AND commit_sha = $2
                   ORDER BY id DESC LIMIT $3
               ) AS recent ORDER BY id""",
            project_id, commit_sha, limit,
        )
        return tuple({
            "observed_at": row["observed_at"],
            "covered": int(row["covered_lines"]),
            "total": int(row["total_lines"]),
            "percent": (
                int(row["covered_lines"]) * 100.0 / int(row["total_lines"])
                if int(row["total_lines"]) else 0.0
            ),
        } for row in rows)

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
            """SELECT DISTINCT commit_sha FROM (
                   SELECT commit_sha FROM coverage_evidence WHERE project_id = $1
                   UNION ALL
                   SELECT commit_sha FROM coverage_source_summaries WHERE project_id = $1
               ) AS commits ORDER BY commit_sha LIMIT 2""",
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

    async def reached_for_campaign(
        self, project_id: int, commit_sha: str, campaign_id: int,
    ) -> tuple[int, tuple]:
        """Return one campaign's exact bounded clean reachable set and strategy identity."""
        rows = await self._pool.fetch(
            f"""SELECT {_COLUMNS} FROM coverage_evidence
                WHERE project_id = $1 AND commit_sha = $2 AND campaign_id = $3
                ORDER BY source_path, line_number, id LIMIT $4""",
            project_id, commit_sha, campaign_id, 100_001,
        )
        if len(rows) > 100_000:
            raise OverflowError("campaign clean coverage exceeds its bound")
        evidence = tuple(self._coverage(row) for row in rows)
        if not evidence:
            raise KeyError("campaign clean coverage is unavailable")
        strategy_ids = {item.asset_id for item in evidence}
        if len(strategy_ids) != 1:
            raise ValueError("campaign clean coverage spans multiple strategy identities")
        from backend.fuzzing.coverage.exposure import ReachedLine
        reached = tuple(sorted({
            ReachedLine(item.source_path, item.line_number, item.function_name)
            for item in evidence
        }))
        return next(iter(strategy_ids)), reached

    async def aggregate_project(
        self, project_id: int, commit_sha: str, limit: int = 1_000, offset: int = 0,
    ) -> CoveragePage:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            """WITH per_campaign AS (
                   SELECT source_path, campaign_id,
                          MAX(cpu_exposure_seconds) AS cpu_exposure_seconds
                   FROM coverage_evidence
                   WHERE project_id = $1 AND commit_sha = $2
                   GROUP BY source_path, campaign_id
               ), exposure AS (
                   SELECT source_path, SUM(cpu_exposure_seconds) AS cpu_exposure_seconds
                   FROM per_campaign GROUP BY source_path
               ), inventories AS (
                   SELECT source_path,
                          COALESCE(
                              LEAST(MAX(covered_lines), MIN(total_lines)), 0
                          ) AS covered_lines,
                          CASE WHEN MIN(total_functions) IS NULL THEN NULL ELSE COALESCE(
                              LEAST(MAX(covered_functions), MIN(total_functions)), 0
                          ) END AS covered_functions,
                          CASE WHEN MIN(total_branches) IS NULL THEN NULL ELSE COALESCE(
                              LEAST(MAX(covered_branches), MIN(total_branches)), 0
                          ) END AS covered_branches,
                          MIN(total_lines) AS total_lines,
                          MIN(total_functions) AS total_functions,
                          MIN(total_branches) AS total_branches
                   FROM coverage_source_summaries
                   WHERE project_id = $1 AND commit_sha = $2 GROUP BY source_path
               ), grouped AS (
                   SELECT inventories.source_path,
                          inventories.covered_lines,
                          inventories.covered_functions,
                          inventories.covered_branches,
                          inventories.total_lines, inventories.total_functions,
                          inventories.total_branches,
                          COALESCE(exposure.cpu_exposure_seconds, 0) AS cpu_exposure_seconds
                   FROM inventories
                   LEFT JOIN exposure USING (source_path)
               ), page AS (
                   SELECT *
                   FROM grouped ORDER BY source_path LIMIT $3 OFFSET $4
               ), overall AS (
                   SELECT SUM(covered_lines) AS project_covered_lines,
                          SUM(total_lines) AS project_total_lines,
                          SUM(covered_functions) AS project_covered_functions,
                          SUM(total_functions) AS project_total_functions,
                          SUM(covered_branches) AS project_covered_branches,
                          SUM(total_branches) AS project_total_branches,
                          BOOL_AND(total_lines IS NOT NULL) AS project_lines_available,
                          BOOL_AND(total_functions IS NOT NULL) AS project_functions_available,
                          BOOL_AND(total_branches IS NOT NULL) AS project_branches_available
                   FROM grouped
               )
               SELECT page.*, total.total, overall.*
               FROM (SELECT COUNT(*) AS total FROM grouped) AS total
               CROSS JOIN overall LEFT JOIN page ON TRUE ORDER BY page.source_path""",
            project_id, commit_sha, limit, offset,
        )
        total = int(rows[0]["total"]) if rows else 0
        items = []
        for row in rows:
            if row["source_path"] is None:
                continue
            covered_lines = int(row["covered_lines"])
            total_lines = _optional_int(_row_value(row, "total_lines"))
            covered_functions = _optional_int(_row_value(row, "covered_functions"))
            total_functions = _optional_int(_row_value(row, "total_functions"))
            covered_branches = _optional_int(_row_value(row, "covered_branches"))
            total_branches = _optional_int(_row_value(row, "total_branches"))
            items.append({
                "path": str(row["source_path"]),
                "covered_lines": covered_lines,
                "total_lines": total_lines,
                "covered_functions": covered_functions,
                "total_functions": total_functions,
                "covered_branches": covered_branches,
                "total_branches": total_branches,
                "cpu_exposure_seconds": float(row["cpu_exposure_seconds"]),
            })
        summary = _project_summary(rows[0]) if rows else {
            "lines": None, "functions": None, "branches": None,
        }
        return CoveragePage(tuple(items), total, summary)

    async def source_summary(self, project_id: int, commit_sha: str, source_path: str):
        rows = await self._pool.fetch(
            """SELECT source_sha256, total_lines, total_functions, total_branches
               FROM coverage_source_summaries
               WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
               ORDER BY coverage_asset_id LIMIT 100001""",
            project_id, commit_sha, source_path,
        )
        if not rows:
            return None
        if len(rows) > 100_000:
            raise OverflowError("coverage source inventories exceed their bound")
        identities = {(
            row["source_sha256"], row["total_lines"],
            row["total_functions"], row["total_branches"],
        ) for row in rows}
        if len(identities) != 1:
            raise ValueError("coverage source hashes or denominators conflict")
        source_sha256, total_lines, total_functions, total_branches = identities.pop()
        return {
            "source_sha256": str(source_sha256),
            "total_lines": _optional_int(total_lines),
            "total_functions": _optional_int(total_functions),
            "total_branches": _optional_int(total_branches),
        }

    async def aggregate_functions(
        self, project_id: int, commit_sha: str, source_path: str,
        limit: int = 1_000, offset: int = 0,
    ) -> CoveragePage:
        self._validate_page(limit, offset)
        rows = await self._pool.fetch(
            """WITH identities AS (
                   SELECT function_name, start_line, start_column, BOOL_OR(covered) AS covered
                   FROM coverage_function_evidence
                   WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                   GROUP BY function_name, start_line, start_column
               ), per_campaign AS (
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
               ), exposure AS (
                   SELECT function_name, SUM(cpu_exposure_seconds) AS cpu_exposure_seconds
                   FROM per_campaign GROUP BY function_name
               ), page AS (
                   SELECT identities.function_name, identities.start_line,
                          identities.start_column, identities.covered,
                          COALESCE(line_counts.covered_lines, 0) AS covered_lines,
                          COALESCE(exposure.cpu_exposure_seconds, 0) AS cpu_exposure_seconds
                   FROM identities
                   LEFT JOIN line_counts USING (function_name)
                   LEFT JOIN exposure USING (function_name)
                   ORDER BY function_name, start_line, start_column LIMIT $4 OFFSET $5
               )
               SELECT page.*, total.total
               FROM (SELECT COUNT(*) AS total FROM identities) AS total
               LEFT JOIN page ON TRUE ORDER BY page.function_name, page.start_line, page.start_column""",
            project_id, commit_sha, source_path, limit, offset,
        )
        total = int(rows[0]["total"]) if rows else 0
        return CoveragePage(tuple({
            "name": str(row["function_name"]),
            "path": source_path,
            "start_line": _optional_int(_row_value(row, "start_line")),
            "start_column": _optional_int(_row_value(row, "start_column")),
            "covered": (
                bool(_row_value(row, "covered"))
                if _row_value(row, "covered") is not None else None
            ),
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

    async def branch_states(
        self, project_id: int, commit_sha: str, source_path: str,
        start_line: int, end_line: int,
    ) -> dict[int, tuple[bool, ...]]:
        rows = await self._pool.fetch(
            """SELECT line_number, branch_index, outcome_index, BOOL_OR(covered) AS covered
               FROM coverage_branch_evidence
               WHERE project_id = $1 AND commit_sha = $2 AND source_path = $3
                 AND line_number BETWEEN $4 AND $5
               GROUP BY line_number, branch_index, outcome_index
               ORDER BY line_number, branch_index, outcome_index""",
            project_id, commit_sha, source_path, start_line, end_line,
        )
        grouped: dict[int, list[bool]] = {}
        for row in rows:
            grouped.setdefault(int(row["line_number"]), []).append(bool(row["covered"]))
        return {line: tuple(states) for line, states in grouped.items()}

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


def _count_total(value):
    return None if value is None else value.total


def _count_covered(value):
    return None if value is None else value.covered


def _row_value(row, name, default=None):
    try:
        return row[name]
    except (KeyError, TypeError):
        return default


def _optional_int(value):
    return None if value is None else int(value)


def _project_summary(row):
    return {
        name: _measurement(
            _row_value(row, f"project_covered_{name}"),
            _row_value(row, f"project_total_{name}"),
        ) if _row_value(row, f"project_{name}_available", False) else None
        for name in ("lines", "functions", "branches")
    }


def _measurement(covered, total):
    if covered is None or total is None:
        return None
    covered, total = int(covered), int(total)
    return {
        "covered": covered,
        "total": total,
        "percent": (covered * 100.0 / total) if total else 0.0,
    }
