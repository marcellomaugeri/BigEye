from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock


def run(awaitable):
    return asyncio.run(awaitable)


class _Transaction:
    async def __aenter__(self): return self
    async def __aexit__(self, *_args): return False


class _Acquire:
    def __init__(self, connection): self.connection = connection
    async def __aenter__(self): return self.connection
    async def __aexit__(self, *_args): return False


def test_checkpoint_append_persists_only_exact_marginal_clean_lines() -> None:
    from backend.fuzzing.coverage.exposure import ReachedLine
    from backend.repositories.coverage_checkpoint_repository import CoverageCheckpointRepository

    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=_Transaction())
    connection.fetchrow.side_effect = [
        {"id": 9},
        {
            "observed_cpu_seconds": 10.0,
            "reached_lines": json.dumps([["src/a.c", 10]]),
            "reached_functions": json.dumps([["src/a.c", "parse"]]),
            "compatibility_group_id": "c" * 64,
            "strategy_asset_id": 32,
            "commit_sha": "a" * 40,
            "configuration_purpose": None,
            "crash_group_ids": "[]",
            "crash_evidence_complete": True,
        },
    ]
    repository = CoverageCheckpointRepository(
        SimpleNamespace(acquire=lambda: _Acquire(connection)), AsyncMock(),
    )

    created = run(repository.append(
        project_id=7, campaign_id=9, strategy_asset_id=32,
        commit_sha="a" * 40, compatibility_group_id="c" * 64,
        observed_cpu_seconds=20.0,
        reached_lines=(
            ReachedLine("src/a.c", 10, "parse"),
            ReachedLine("src/a.c", 11, "parse"),
        ),
        crash_group_ids=(), crash_evidence_complete=True,
    ))

    assert created is True
    values = connection.execute.await_args.args
    assert json.loads(values[9]) == [["src/a.c", 11]]
    assert values[-2] is True
    assert values[-1] is None


def test_persisted_complete_histories_feed_conservative_overlap() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer
    from backend.repositories.coverage_checkpoint_repository import CoverageCheckpointRepository

    rows = []
    for identifier, campaign_id, strategy_id, lines in (
        (1, 4, 40, [["src/a.c", 10], ["src/a.c", 11]]),
        (2, 4, 40, [["src/a.c", 10], ["src/a.c", 11]]),
        (3, 9, 90, [["src/a.c", 10]]),
        (4, 9, 90, [["src/a.c", 10]]),
    ):
        rows.append({
            "id": identifier, "project_id": 7, "campaign_id": campaign_id,
            "strategy_asset_id": strategy_id, "commit_sha": "a" * 40,
            "compatibility_group_id": "c" * 64,
            "reached_lines": json.dumps(lines),
            "reached_functions": json.dumps([["src/a.c", "parse"]]),
            "recent_marginal_lines": "[]", "crash_group_ids": "[]",
            "configuration_purpose": "default protocol",
        })
    pool = AsyncMock()
    pool.fetch.return_value = rows

    histories = run(CoverageCheckpointRepository(pool, AsyncMock()).histories(7))
    candidates = OverlapAnalyzer().compare(histories)

    assert [(item.campaign_id, item.retained_campaign_id) for item in candidates] == [(9, 4)]
    assert "crash_evidence_complete IS TRUE" in pool.fetch.await_args.args[0]
    assert "MAX(current.id)" in pool.fetch.await_args.args[0]


def test_replaced_container_cpu_counter_keeps_campaign_total_monotonic() -> None:
    from backend.repositories.campaign_repository import CampaignRepository

    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=_Transaction())
    connection.fetchrow.side_effect = [
        {"cpu_seconds": 10.0}, None,
        {"cpu_seconds": 12.0}, None,
    ]
    repository = CampaignRepository(SimpleNamespace(acquire=lambda: _Acquire(connection)))

    first = run(repository.cumulative_cpu_seconds(9, "container-one", 2.0))
    replaced = run(repository.cumulative_cpu_seconds(9, "container-two", 1.0))

    assert first == 12.0
    assert replaced == 13.0
    inserts = [call.args for call in connection.execute.await_args_list]
    assert inserts[0][-2:] == (10.0, 2.0)
    assert inserts[1][-2:] == (12.0, 1.0)


def test_new_raw_crash_invalidates_previous_complete_checkpoint_without_new_coverage() -> None:
    from backend.fuzzing.coverage.exposure import ReachedLine
    from backend.repositories.coverage_checkpoint_repository import CoverageCheckpointRepository

    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=_Transaction())
    connection.fetchrow.side_effect = [
        {"id": 9},
        {
            "observed_cpu_seconds": 20.0,
            "reached_lines": '[["src/a.c", 10]]',
            "reached_functions": '[["src/a.c", "parse"]]',
            "compatibility_group_id": "c" * 64, "strategy_asset_id": 32,
            "commit_sha": "a" * 40, "configuration_purpose": "default",
            "crash_group_ids": "[]", "crash_evidence_complete": True,
        },
    ]
    repository = CoverageCheckpointRepository(
        SimpleNamespace(acquire=lambda: _Acquire(connection)), AsyncMock(),
    )

    created = run(repository.append(
        project_id=7, campaign_id=9, strategy_asset_id=32,
        commit_sha="a" * 40, compatibility_group_id="c" * 64,
        observed_cpu_seconds=20.0,
        reached_lines=(ReachedLine("src/a.c", 10, "parse"),),
        crash_group_ids=(), crash_evidence_complete=False,
        configuration_purpose="default",
    ))

    assert created is True
    assert connection.execute.await_args.args[-2] is False


def test_retirement_reason_is_persisted_atomically_with_exact_stop() -> None:
    from backend.repositories.campaign_repository import CampaignRepository

    pool = AsyncMock()
    pool.fetchval.return_value = 9

    stopped = run(CampaignRepository(pool).stop_redundant(
        project_id=7, campaign_id=9, strategy_asset_id=90,
        retained_campaign_id=4, retained_strategy_asset_id=40,
        retirement_reason="clean subset for two checkpoints",
    ))

    query = pool.fetchval.await_args.args[0]
    assert "WITH stopped AS" in query
    assert "UPDATE campaign_contexts" in query
    assert pool.fetchval.await_args.args[-1] == "clean subset for two checkpoints"
    assert stopped is True


def test_campaign_configuration_purpose_is_created_atomically() -> None:
    from backend.repositories.campaign_repository import CampaignRepository

    now = datetime(2026, 7, 20, tzinfo=UTC)
    pool = AsyncMock()
    pool.fetchrow.return_value = {
        "id": 9, "project_id": 7, "target_asset_id": 31,
        "configuration_asset_id": 32, "engine": "afl", "started_at": now,
        "stopped_at": None, "last_heartbeat_at": None, "cpu_seconds": 0.0,
        "next_review_after": now, "next_review_reason": "initial", "error": None,
    }

    run(CampaignRepository(pool).create(
        project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", next_review_after=now, next_review_reason="initial",
        configuration_purpose="encrypted protocol",
    ))

    query = pool.fetchrow.await_args.args[0]
    assert "INSERT INTO campaign_contexts" in query
    assert pool.fetchrow.await_args.args[-1] == "encrypted protocol"
