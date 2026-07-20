"""Real PostgreSQL FK-order checks for authorised lifecycle deletion."""

from __future__ import annotations

import os
import asyncio

import pytest


pytestmark = pytest.mark.skipif(
    not os.environ.get("BIGEYE_TEST_DATABASE_URL"),
    reason="requires disposable BIGEYE_TEST_DATABASE_URL",
)


def test_authorized_deletions_respect_fk_order_and_preserve_retained_evidence() -> None:
    asyncio.run(_exercise_authorized_deletions())


async def _exercise_authorized_deletions() -> None:
    import asyncpg

    from backend.repositories.asset_repository import AssetRepository

    pool = await asyncpg.create_pool(os.environ["BIGEYE_TEST_DATABASE_URL"], min_size=1, max_size=2)
    try:
        project_id = await pool.fetchval(
            """INSERT INTO projects (repository_url, worker_count, commit_sha)
               VALUES ('https://example.test/repository.git', 1, $1) RETURNING id""",
            "a" * 40,
        )
        repository = AssetRepository(pool)

        failed_target_id = await pool.fetchval(
            """INSERT INTO assets (project_id, kind, name, content_hash)
               VALUES ($1, 'harness', 'failed-target', $2) RETURNING id""",
            project_id, "b" * 64,
        )
        await repository.record_probe_attempt(
            project_id=project_id, target_asset_id=failed_target_id,
            proposal_result_id="proposal:failed", operation="probe",
            successful=False, outcome="probe did not reach target",
        )
        evidence = await repository.deletion_evidence(project_id, failed_target_id)

        assert await repository.delete_authorized(
            project_id=project_id, asset_id=failed_target_id,
            content_hash="b" * 64, attempt_revision=evidence["attempt_revision"],
        ) is True
        assert await pool.fetchval(
            "SELECT COUNT(*) FROM target_probe_attempts WHERE target_asset_id = $1",
            failed_target_id,
        ) == 0
        assert await pool.fetchval("SELECT COUNT(*) FROM assets WHERE id = $1", failed_target_id) == 0

        target_id = await pool.fetchval(
            """INSERT INTO assets (project_id, kind, name, content_hash)
               VALUES ($1, 'harness', 'working-target', $2) RETURNING id""",
            project_id, "c" * 64,
        )
        candidate_id = await pool.fetchval(
            """INSERT INTO assets (project_id, kind, name, content_hash)
               VALUES ($1, 'configuration', 'redundant', $2) RETURNING id""",
            project_id, "d" * 64,
        )
        retained_id = await pool.fetchval(
            """INSERT INTO assets (project_id, kind, name, content_hash)
               VALUES ($1, 'configuration', 'retained', $2) RETURNING id""",
            project_id, "e" * 64,
        )
        candidate_campaign = await pool.fetchval(
            """INSERT INTO campaigns
                      (project_id, target_asset_id, configuration_asset_id, engine, stopped_at)
               VALUES ($1, $2, $3, 'afl++', CURRENT_TIMESTAMP) RETURNING id""",
            project_id, target_id, candidate_id,
        )
        retained_campaign = await pool.fetchval(
            """INSERT INTO campaigns
                      (project_id, target_asset_id, configuration_asset_id, engine, stopped_at)
               VALUES ($1, $2, $3, 'afl++', CURRENT_TIMESTAMP) RETURNING id""",
            project_id, target_id, retained_id,
        )
        for campaign_id, strategy_id, line in (
            (candidate_campaign, candidate_id, 10),
            (retained_campaign, retained_id, 20),
        ):
            await pool.execute(
                """INSERT INTO coverage_evidence
                          (project_id, commit_sha, source_path, line_number, campaign_id,
                           asset_id, first_testcase_sha256, cpu_exposure_seconds)
                   VALUES ($1, $2, 'parser.c', $3, $4, $5, $6, 1.0)""",
                project_id, "a" * 40, line, campaign_id, strategy_id,
                format(line, "064x"),
            )
            await pool.execute(
                """INSERT INTO coverage_checkpoints
                          (project_id, campaign_id, strategy_asset_id, commit_sha,
                           compatibility_group_id, observed_cpu_seconds, reached_lines,
                           reached_functions, recent_marginal_lines, crash_group_ids,
                           crash_evidence_complete)
                   VALUES ($1, $2, $3, $4, 'compatible', 1.0,
                           '[]', '[]', '[]', '[]', TRUE)""",
                project_id, campaign_id, strategy_id, "a" * 40,
            )

        assert await repository.delete_overlap_authorized(
            project_id=project_id, campaign_id=candidate_campaign, asset_id=candidate_id,
            content_hash="d" * 64, revision=candidate_id,
        ) is True
        assert await pool.fetchval("SELECT COUNT(*) FROM assets WHERE id = $1", candidate_id) == 0
        assert await pool.fetchval(
            "SELECT configuration_asset_id FROM campaigns WHERE id = $1", candidate_campaign,
        ) is None
        assert await pool.fetchval(
            "SELECT COUNT(*) FROM coverage_evidence WHERE campaign_id = $1", candidate_campaign,
        ) == 0
        assert await pool.fetchval(
            "SELECT COUNT(*) FROM coverage_checkpoints WHERE campaign_id = $1", candidate_campaign,
        ) == 0
        assert await pool.fetchval("SELECT COUNT(*) FROM assets WHERE id = $1", retained_id) == 1
        assert await pool.fetchval(
            "SELECT COUNT(*) FROM coverage_evidence WHERE campaign_id = $1", retained_campaign,
        ) == 1
        assert await pool.fetchval(
            "SELECT COUNT(*) FROM coverage_checkpoints WHERE campaign_id = $1", retained_campaign,
        ) == 1
    finally:
        await pool.close()
