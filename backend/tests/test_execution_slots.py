from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


def run(awaitable):
    return asyncio.run(awaitable)


def project(*, identifier=7, worker_count=4):
    return SimpleNamespace(id=identifier, worker_count=worker_count)


def test_compilation_rejects_at_the_project_heavy_job_limit_and_agents_do_not_use_slots() -> None:
    from backend.services.campaigns.execution_slots import (
        ProjectCapacityUnavailable,
        ProjectExecutionSlots,
    )

    async def exercise():
        slots = ProjectExecutionSlots()
        value = project()
        await slots.observe_running(value.id, frozenset({31, 32}))
        first_entered = asyncio.Event()
        second_entered = asyncio.Event()
        release_first = asyncio.Event()
        release_second = asyncio.Event()

        async def hold(operation_id, entered, release):
            async with slots.compilation(value, operation_id):
                entered.set()
                await release.wait()

        first = asyncio.create_task(hold("compile:1", first_entered, release_first))
        second = asyncio.create_task(hold("compile:2", second_entered, release_second))
        await first_entered.wait()
        await second_entered.wait()
        with pytest.raises(ProjectCapacityUnavailable):
            async with slots.compilation(value, "compile:5"):
                raise AssertionError("capacity-full compilation was admitted")

        agent_calls = 0

        async def agent_side_work():
            nonlocal agent_calls
            agent_calls += 1
            await asyncio.sleep(0)

        await asyncio.gather(*(agent_side_work() for _ in range(10)))
        assert agent_calls == 10
        assert (await slots.snapshot(value)).occupied == 4

        release_first.set()
        await first
        fifth_entered = asyncio.Event()
        release_fifth = asyncio.Event()
        fifth = asyncio.create_task(hold("compile:5", fifth_entered, release_fifth))
        await fifth_entered.wait()
        assert (await slots.snapshot(value)).occupied == 4

        release_fifth.set()
        release_second.set()
        await asyncio.gather(first, second, fifth, return_exceptions=True)
        assert (await slots.snapshot(value)).occupied == 2

    run(exercise())


def test_recovery_reservations_are_exclusive_and_release_after_cancellation() -> None:
    from backend.services.campaigns.execution_slots import ProjectExecutionSlots

    async def exercise():
        slots = ProjectExecutionSlots()
        value = project(worker_count=1)
        first = await slots.try_fuzzing_start(value, 41)
        assert first is not None
        assert await slots.try_fuzzing_start(value, 42) is None

        await first.__aexit__(None, None, None)
        second = await slots.try_fuzzing_start(value, 42)
        assert second is not None
        await second.promote()
        await second.__aexit__(None, None, None)
        snapshot = await slots.snapshot(value)
        assert snapshot.running_campaign_ids == frozenset({42})
        assert snapshot.free_slots == 0

    run(exercise())


def test_compilation_admission_returns_capacity_evidence_without_waiting_for_a_fuzzer() -> None:
    from backend.services.campaigns.execution_slots import (
        ProjectCapacityUnavailable,
        ProjectExecutionSlots,
    )

    async def exercise():
        slots = ProjectExecutionSlots()
        value = project(worker_count=4)
        running = frozenset({31, 32, 33, 34})
        await slots.observe_running(value.id, running)
        entered = False

        with pytest.raises(ProjectCapacityUnavailable) as captured:
            async with asyncio.timeout(0.05):
                async with slots.compilation(value, "prepare-target:component"):
                    entered = True
        assert str(captured.value) == "project compilation capacity is unavailable"
        assert dict(captured.value.failure_detail) == {
            "phase": "compilation-admission",
            "capacity_limit": 4,
            "occupied_slots": 4,
            "running_campaign_ids": (31, 32, 33, 34),
        }

        assert entered is False
        snapshot = await slots.snapshot(value)
        assert snapshot.running_campaign_ids == running
        assert snapshot.compilation_count == 0
        assert snapshot.free_slots == 0

    run(exercise())


def test_stale_project_snapshot_does_not_overwrite_a_configured_limit() -> None:
    from backend.services.campaigns.execution_slots import (
        ProjectCapacityUnavailable,
        ProjectExecutionSlots,
    )

    async def exercise():
        slots = ProjectExecutionSlots()
        constrained = project(worker_count=1)
        expanded = project(worker_count=2)
        await slots.observe_running(constrained.id, frozenset({31}))
        entered = asyncio.Event()

        with pytest.raises(ProjectCapacityUnavailable):
            async with slots.compilation(constrained, "compile:rejected"):
                raise AssertionError("capacity-full compilation was admitted")

        await slots.configure(expanded)
        snapshot = await slots.snapshot(constrained)
        assert snapshot.limit == 2

        async with slots.compilation(constrained, "compile:admitted"):
            entered.set()
            assert (await slots.snapshot(constrained)).occupied == 2

        assert entered.is_set() is True

    run(exercise())


def test_first_operation_initialises_a_fresh_project_ledger_limit() -> None:
    from backend.services.campaigns.execution_slots import ProjectExecutionSlots

    async def exercise():
        slots = ProjectExecutionSlots()
        value = project(worker_count=1)

        reservation = await slots.try_fuzzing_start(value, 31)

        assert reservation is not None
        assert (await slots.snapshot(value)).limit == 1
        await reservation.__aexit__(None, None, None)

    run(exercise())
