from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


def run(awaitable):
    return asyncio.run(awaitable)


def test_cpu_delta_is_added_to_every_reachable_line_not_divided() -> None:
    from backend.fuzzing.coverage.exposure import ExposureAccountant

    result = ExposureAccountant.calculate(3600.0, {("a.c", 10), ("a.c", 11)})

    assert result[("a.c", 10)] == 3600.0
    assert result[("a.c", 11)] == 3600.0


def test_empty_or_zero_checkpoint_does_not_create_exposure() -> None:
    from backend.fuzzing.coverage.exposure import ExposureAccountant

    assert ExposureAccountant.calculate(0.0, {("a.c", 10)}) == {}
    assert ExposureAccountant.calculate(1.0, set()) == {}


@pytest.mark.parametrize("cpu_delta", [-1.0, float("nan"), float("inf"), True])
def test_invalid_cpu_delta_is_rejected(cpu_delta) -> None:
    from backend.fuzzing.coverage.exposure import ExposureAccountant

    with pytest.raises(ValueError, match="CPU delta"):
        ExposureAccountant.calculate(cpu_delta, {("a.c", 10)})


def test_apply_passes_cumulative_cpu_observation_and_current_reached_lines() -> None:
    from backend.fuzzing.coverage.exposure import ExposureAccountant, ReachedLine

    calls = []

    class Repository:
        async def apply_exposure_observation(self, **values):
            calls.append(values)
            return True

    result = run(ExposureAccountant(Repository()).apply(
        campaign_id=4,
        observed_cpu_seconds=7200.0,
        reached_lines={
            ReachedLine("src/a.c", 10, "parse"),
            ReachedLine("src/a.c", 11, "parse"),
            ReachedLine("src/b.c", 5, None),
        },
    ))

    assert result is True
    assert calls == [{
        "campaign_id": 4,
        "observed_cpu_seconds": 7200.0,
        "reached_lines": (("src/a.c", 10), ("src/a.c", 11), ("src/b.c", 5)),
    }]


def test_apply_still_persists_an_empty_reached_set_so_the_watermark_advances() -> None:
    from backend.fuzzing.coverage.exposure import ExposureAccountant, ReachedLine

    class Repository:
        async def apply_exposure_observation(self, **values):
            assert values["reached_lines"] == ()
            return True

    result = run(ExposureAccountant(Repository()).apply(
        campaign_id=4,
        observed_cpu_seconds=15.0,
        reached_lines=set(),
    ))

    assert result is True


def test_repository_applies_cumulative_observation_once_in_one_transaction() -> None:
    from unittest.mock import AsyncMock, MagicMock

    from backend.repositories.coverage_repository import CoverageRepository

    class Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class Acquisition:
        def __init__(self, connection):
            self.connection = connection

        async def __aenter__(self):
            return self.connection

        async def __aexit__(self, *_args):
            return False

    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=Transaction())
    connection.fetchrow.return_value = {
        "project_id": 7,
        "commit_sha": "a" * 40,
        "previous_cpu_seconds": 5.0,
    }
    connection.fetch.return_value = [{"commit_sha": "a" * 40, "asset_id": 33}]
    connection.fetchval.return_value = 2
    pool = SimpleNamespace(acquire=lambda: Acquisition(connection))

    applied = run(CoverageRepository(pool).apply_exposure_observation(
        campaign_id=4,
        observed_cpu_seconds=20.0,
        reached_lines=(("src/a.c", 10), ("src/a.c", 11)),
    ))

    assert applied is True
    connection.transaction.assert_called_once_with()
    queries = [
        call.args[0]
        for call in (
            connection.fetchrow.await_args_list
            + connection.fetch.await_args_list
            + connection.fetchval.await_args_list
            + connection.execute.await_args_list
        )
    ]
    assert any("FOR UPDATE OF c" in query for query in queries)
    assert any("UPDATE coverage_evidence" in query for query in queries)
    assert any("UPDATE campaigns SET cpu_seconds" in query for query in queries)
    assert connection.fetchval.await_args.args[-1] == 15.0


def test_repository_repeated_cumulative_observation_does_not_apply_delta_twice() -> None:
    from unittest.mock import AsyncMock, MagicMock

    from backend.repositories.coverage_repository import CoverageRepository

    class Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class Acquisition:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return False

    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=Transaction())
    connection.fetchrow.return_value = {
        "project_id": 7, "commit_sha": "a" * 40, "previous_cpu_seconds": 20.0,
    }
    pool = SimpleNamespace(acquire=lambda: Acquisition())

    applied = run(CoverageRepository(pool).apply_exposure_observation(
        campaign_id=4,
        observed_cpu_seconds=20.0,
        reached_lines=(("src/a.c", 10),),
    ))

    assert applied is False
    connection.fetchval.assert_not_awaited()
    connection.execute.assert_not_awaited()


def test_repository_rejects_cpu_counter_decrease_without_mutation() -> None:
    from unittest.mock import AsyncMock, MagicMock

    from backend.repositories.coverage_repository import CoverageRepository

    class Transaction:
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return False

    class Acquisition:
        async def __aenter__(self): return connection
        async def __aexit__(self, *_args): return False

    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=Transaction())
    connection.fetchrow.return_value = {
        "project_id": 7, "commit_sha": "a" * 40, "previous_cpu_seconds": 20.0,
    }

    with pytest.raises(ValueError, match="cannot decrease"):
        run(CoverageRepository(SimpleNamespace(acquire=lambda: Acquisition())).apply_exposure_observation(
            campaign_id=4,
            observed_cpu_seconds=19.0,
            reached_lines=(("src/a.c", 10),),
        ))

    connection.fetchval.assert_not_awaited()
    connection.execute.assert_not_awaited()


def test_repository_rejects_nonfinite_persisted_cpu_watermark() -> None:
    from unittest.mock import AsyncMock, MagicMock

    from backend.repositories.coverage_repository import CoverageRepository

    class Transaction:
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return False

    class Acquisition:
        async def __aenter__(self): return connection
        async def __aexit__(self, *_args): return False

    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=Transaction())
    connection.fetchrow.return_value = {
        "project_id": 7, "commit_sha": "a" * 40, "previous_cpu_seconds": float("nan"),
    }

    with pytest.raises(ValueError, match="stored CPU"):
        run(CoverageRepository(SimpleNamespace(acquire=lambda: Acquisition())).apply_exposure_observation(
            campaign_id=4,
            observed_cpu_seconds=20.0,
            reached_lines=(),
        ))

    connection.execute.assert_not_awaited()


def test_function_summary_uses_per_campaign_maximum_not_line_sum() -> None:
    from unittest.mock import AsyncMock

    from backend.repositories.coverage_repository import CoverageRepository

    pool = AsyncMock()
    pool.fetch.return_value = [{
        "function_name": "parse", "covered_lines": 2,
        "cpu_exposure_seconds": 15.0, "total": 1,
    }]

    page = run(CoverageRepository(pool).aggregate_functions(7, "a" * 40, "src/a.c"))

    query = pool.fetch.await_args.args[0]
    assert "MAX(cpu_exposure_seconds)" in query
    assert "GROUP BY function_name, campaign_id" in query
    assert page.items[0]["cpu_exposure_seconds"] == 15.0


def test_project_source_exposure_uses_campaign_maximum_then_sums_campaigns() -> None:
    from unittest.mock import AsyncMock

    from backend.repositories.coverage_repository import CoverageRepository

    pool = AsyncMock()
    pool.fetch.return_value = [{
        "source_path": "src/a.c", "covered_lines": 2,
        "cpu_exposure_seconds": 25.0, "covered_line_total": 2,
        "total_lines": 3, "covered_functions": 1, "total_functions": 2,
        "covered_branches": None, "total_branches": None, "total": 1,
    }]

    page = run(CoverageRepository(pool).aggregate_project(7, "a" * 40))

    query = pool.fetch.await_args.args[0]
    assert "MAX(cpu_exposure_seconds)" in query
    assert "GROUP BY source_path, campaign_id" in query
    assert page.items[0]["cpu_exposure_seconds"] == 25.0


def test_project_function_union_uses_exact_function_inventory_not_line_names() -> None:
    from unittest.mock import AsyncMock

    from backend.repositories.coverage_repository import CoverageRepository

    pool = AsyncMock()
    pool.fetch.return_value = []

    run(CoverageRepository(pool).aggregate_project(7, "a" * 40))

    query = pool.fetch.await_args.args[0]
    assert "coverage_function_evidence" in query
    assert "COUNT(DISTINCT function_name)" not in query
