from __future__ import annotations

import asyncio
from types import SimpleNamespace


def run(awaitable):
    return asyncio.run(awaitable)


def project(*, identifier=7, worker_count=4):
    return SimpleNamespace(id=identifier, worker_count=worker_count)


def test_compilation_waits_at_the_project_heavy_job_limit_and_agents_do_not_use_slots() -> None:
    from backend.services.campaigns.execution_slots import ProjectExecutionSlots

    async def exercise():
        slots = ProjectExecutionSlots()
        value = project()
        await slots.observe_running(value.id, frozenset({31, 32}))
        first_entered = asyncio.Event()
        second_entered = asyncio.Event()
        release_first = asyncio.Event()
        release_second = asyncio.Event()
        fifth_entered = asyncio.Event()

        async def hold(operation_id, entered, release):
            async with slots.compilation(value, operation_id):
                entered.set()
                await release.wait()

        first = asyncio.create_task(hold("compile:1", first_entered, release_first))
        second = asyncio.create_task(hold("compile:2", second_entered, release_second))
        await first_entered.wait()
        await second_entered.wait()
        fifth = asyncio.create_task(hold("compile:5", fifth_entered, asyncio.Event()))
        await asyncio.sleep(0)
        assert fifth_entered.is_set() is False

        agent_calls = 0

        async def agent_side_work():
            nonlocal agent_calls
            agent_calls += 1
            await asyncio.sleep(0)

        await asyncio.gather(*(agent_side_work() for _ in range(10)))
        assert agent_calls == 10
        assert (await slots.snapshot(value)).occupied == 4

        release_first.set()
        await fifth_entered.wait()
        assert (await slots.snapshot(value)).occupied == 4

        fifth.cancel()
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
