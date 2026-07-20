"""Persist bounded clean-coverage checkpoints for conservative overlap review."""

from __future__ import annotations

import json
import math

from backend.fuzzing.coverage.overlap import (
    CampaignCoverageHistory,
    CleanCoverageCheckpoint,
)


class CoverageCheckpointRepository:
    _MAX_ROWS = 256 * 64

    def __init__(self, pool, coverage):
        self._pool = pool
        self._coverage = coverage

    async def reached_lines(self, project, campaign):
        return await self._coverage.reached_for_campaign(
            project.id, project.commit_sha, campaign.id,
        )

    async def append(
        self, *, project_id: int, campaign_id: int, strategy_asset_id: int,
        commit_sha: str, compatibility_group_id: str, observed_cpu_seconds: float,
        reached_lines, crash_group_ids=(), crash_evidence_complete: bool,
        configuration_purpose: str | None = None,
    ) -> bool:
        lines = frozenset((item.source_path, item.line_number) for item in reached_lines)
        functions = frozenset(
            (item.source_path, item.function_name)
            for item in reached_lines if item.function_name is not None
        )
        # Validate every external value through the domain type before persistence.
        CampaignCoverageHistory(
            project_id, campaign_id, strategy_asset_id, commit_sha,
            compatibility_group_id,
            (CleanCoverageCheckpoint("pending", lines, functions),),
            frozenset(crash_group_ids),
            configuration_purpose,
        )
        if type(crash_evidence_complete) is not bool:
            raise ValueError("crash evidence completeness must be boolean")
        if (
            isinstance(observed_cpu_seconds, bool)
            or not isinstance(observed_cpu_seconds, (int, float))
            or not math.isfinite(observed_cpu_seconds)
            or observed_cpu_seconds < 0
        ):
            raise ValueError("coverage checkpoint CPU seconds are invalid")
        encoded_lines = json.dumps(sorted([path, line] for path, line in lines))
        encoded_functions = json.dumps(sorted([path, name] for path, name in functions))
        encoded_crashes = json.dumps(sorted(crash_group_ids))
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                identity = await connection.fetchrow(
                    """SELECT id FROM campaigns
                       WHERE id = $1 AND project_id = $2 FOR UPDATE""",
                    campaign_id, project_id,
                )
                if identity is None:
                    raise KeyError(campaign_id)
                previous = await connection.fetchrow(
                    """SELECT observed_cpu_seconds, reached_lines, reached_functions,
                              compatibility_group_id, strategy_asset_id, commit_sha,
                              configuration_purpose, crash_group_ids,
                              crash_evidence_complete
                       FROM coverage_checkpoints
                       WHERE project_id = $1 AND campaign_id = $2
                       ORDER BY id DESC LIMIT 1""",
                    project_id, campaign_id,
                )
                previous_lines = set()
                if previous is not None:
                    if (
                        previous["compatibility_group_id"] != compatibility_group_id
                        or previous["strategy_asset_id"] != strategy_asset_id
                        or previous["commit_sha"] != commit_sha
                        or previous["configuration_purpose"] != configuration_purpose
                    ):
                        raise ValueError("campaign checkpoint identity changed")
                    previous_lines = {
                        tuple(value) for value in _json_array(previous["reached_lines"])
                    }
                    previous_cpu = float(previous["observed_cpu_seconds"])
                    if float(observed_cpu_seconds) < previous_cpu:
                        raise ValueError("coverage checkpoint CPU seconds decreased")
                    if (
                        previous_cpu == float(observed_cpu_seconds)
                        and previous_lines == set(lines)
                        and {
                            tuple(value) for value in _json_array(previous["reached_functions"])
                        } == set(functions)
                        and set(_json_array(previous["crash_group_ids"])) == set(crash_group_ids)
                        and previous["crash_evidence_complete"] is crash_evidence_complete
                    ):
                        return False
                marginal = json.dumps(sorted([path, line] for path, line in lines - previous_lines))
                await connection.execute(
                    """INSERT INTO coverage_checkpoints
                              (project_id, campaign_id, strategy_asset_id, commit_sha,
                               compatibility_group_id, observed_cpu_seconds, reached_lines,
                               reached_functions, recent_marginal_lines, crash_group_ids,
                               crash_evidence_complete, configuration_purpose)
                       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb,
                               $9::jsonb, $10::jsonb, $11, $12)""",
                    project_id, campaign_id, strategy_asset_id, commit_sha,
                    compatibility_group_id, float(observed_cpu_seconds), encoded_lines,
                    encoded_functions, marginal, encoded_crashes, crash_evidence_complete,
                    configuration_purpose,
                )
                return True

    async def histories(self, project_id: int):
        rows = await self._pool.fetch(
            """SELECT id, project_id, campaign_id, strategy_asset_id, commit_sha,
                      compatibility_group_id, reached_lines, reached_functions,
                      recent_marginal_lines, crash_group_ids, configuration_purpose
               FROM coverage_checkpoints AS checkpoint
               WHERE project_id = $1
                 AND EXISTS (
                     SELECT 1 FROM coverage_checkpoints AS latest
                     WHERE latest.campaign_id = checkpoint.campaign_id
                       AND latest.project_id = checkpoint.project_id
                       AND latest.crash_evidence_complete IS TRUE
                       AND latest.id = (
                           SELECT MAX(current.id) FROM coverage_checkpoints AS current
                           WHERE current.project_id = checkpoint.project_id
                             AND current.campaign_id = checkpoint.campaign_id
                       )
                 )
               ORDER BY campaign_id, id LIMIT $2""",
            project_id, self._MAX_ROWS + 1,
        )
        if len(rows) > self._MAX_ROWS:
            raise OverflowError("coverage checkpoint history exceeds its bound")
        grouped: dict[int, list] = {}
        for row in rows:
            grouped.setdefault(int(row["campaign_id"]), []).append(row)
        result = []
        for campaign_rows in grouped.values():
            latest = campaign_rows[-1]
            identities = {
                (
                    row["strategy_asset_id"], row["commit_sha"],
                    row["compatibility_group_id"], row["configuration_purpose"],
                )
                for row in campaign_rows
            }
            if len(identities) != 1:
                raise ValueError("persisted campaign checkpoint identity changed")
            checkpoints = tuple(
                CleanCoverageCheckpoint(
                    f"coverage-checkpoint:{row['id']}",
                    frozenset((str(path), int(line)) for path, line in _json_array(row["reached_lines"])),
                    frozenset((str(path), str(name)) for path, name in _json_array(row["reached_functions"])),
                    frozenset((str(path), int(line)) for path, line in _json_array(row["recent_marginal_lines"])),
                )
                for row in campaign_rows[-64:]
            )
            result.append(CampaignCoverageHistory(
                int(latest["project_id"]), int(latest["campaign_id"]),
                int(latest["strategy_asset_id"]), str(latest["commit_sha"]),
                str(latest["compatibility_group_id"]), checkpoints,
                frozenset(str(value) for value in _json_array(latest["crash_group_ids"])),
                (
                    str(latest["configuration_purpose"])
                    if latest["configuration_purpose"] is not None else None
                ),
            ))
        return tuple(result)


def _json_array(value):
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list):
        raise ValueError("persisted coverage checkpoint JSON is invalid")
    return value
