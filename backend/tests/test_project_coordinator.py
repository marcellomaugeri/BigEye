from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


NOW = datetime(2026, 7, 20, 9, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


def project(*, identifier=7, workers=2, commit="a" * 40, paused_at=None, error=None):
    return SimpleNamespace(
        id=identifier, worker_count=workers, commit_sha=commit,
        paused_at=paused_at, error=error,
    )


def healthy_snapshot(**changes):
    from backend.services.campaigns.wake_rules import CampaignSnapshot

    values = {
        "evidence_ids": ("campaign:3",),
        "coverage_path_counts": (10, 11, 12),
        "active_workers": 2,
    }
    values.update(changes)
    return CampaignSnapshot(**values)


class Lock:
    def __init__(self, acquired=True):
        self.acquired = acquired
        self.entered = []

    @asynccontextmanager
    async def acquire(self, project_id):
        self.entered.append(project_id)
        yield self.acquired


def coordinator(*, value=None, snapshot=None, manager=None, runtime=None, bootstrap=None, discovery=None, lock=None, events=None):
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    value = value or project()
    projects = AsyncMock()
    projects.get.return_value = value
    runtime = runtime or AsyncMock()
    runtime.reconcile.return_value = snapshot or healthy_snapshot()
    runtime.review_context.return_value = SimpleNamespace(project_id=value.id)
    runtime.review_evidence.return_value = [{"evidence_id": "campaign:3"}]
    return ProjectCoordinator(
        projects=projects,
        bootstrap=bootstrap or AsyncMock(),
        discovery=discovery or AsyncMock(),
        manager=manager or AsyncMock(),
        decision_executor=AsyncMock(),
        runtime=runtime,
        advisory_lock=lock or Lock(),
        events=events,
        clock=lambda: NOW,
    )


def test_healthy_campaign_does_not_call_manager_between_conditions() -> None:
    manager = AsyncMock()
    subject = coordinator(manager=manager)

    run(subject.tick(project_id=7, snapshot=healthy_snapshot()))

    manager.review.assert_not_awaited()


def test_triggered_tick_runs_manager_and_only_the_validated_decision_executor() -> None:
    manager = AsyncMock()
    decision = object()
    manager.review.return_value = decision
    subject = coordinator(manager=manager)

    run(subject.tick(7, healthy_snapshot(corpus_opportunity=True)))

    manager.review.assert_awaited_once()
    call = manager.review.await_args
    assert call.args[2] == "validated corpus opportunity"
    subject.decision_executor.execute.assert_awaited_once_with(subject.projects.get.return_value, decision)


def test_openai_failure_is_recorded_without_stopping_a_healthy_fuzzer() -> None:
    manager = AsyncMock()
    manager.review.side_effect = RuntimeError("OpenAI unavailable")
    runtime = AsyncMock()
    runtime.reconcile.return_value = healthy_snapshot()
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "campaign:3"}]
    events = AsyncMock()
    subject = coordinator(manager=manager, runtime=runtime, events=events)

    run(subject.tick(7, healthy_snapshot(corpus_opportunity=True)))

    runtime.stop_all.assert_not_awaited()
    runtime.stop_campaigns.assert_not_awaited()
    assert events.append.await_args.args[:2] == (7, "activity")
    assert events.append.await_args.args[2]["decision"] == "manager review deferred"


def test_manager_failure_activity_does_not_persist_exception_secret_text() -> None:
    manager = AsyncMock()
    manager.review.side_effect = RuntimeError("Authorization: secret-token")
    events = AsyncMock()
    subject = coordinator(manager=manager, events=events)

    run(subject.tick(7, healthy_snapshot(corpus_opportunity=True)))

    payload = events.append.await_args.args[2]
    assert "secret-token" not in repr(payload)
    assert "RuntimeError" in payload["motivation"]


def test_worker_count_decrease_retires_only_excess_lowest_priority_workers() -> None:
    runtime = AsyncMock()
    subject = coordinator(value=project(workers=2), runtime=runtime)

    run(subject.tick(7, healthy_snapshot(active_workers=4)))

    runtime.enforce_worker_count.assert_awaited_once_with(subject.projects.get.return_value, 2)


def test_paused_project_gracefully_stops_workers_and_does_not_review() -> None:
    runtime = AsyncMock()
    manager = AsyncMock()
    subject = coordinator(value=project(paused_at=NOW), runtime=runtime, manager=manager)

    run(subject.tick(7, healthy_snapshot(initial_supervision_complete=True)))

    runtime.pause.assert_awaited_once_with(7)
    manager.review.assert_not_awaited()


def test_resume_verifies_commit_and_assets_before_restarting_selected_campaigns() -> None:
    runtime = AsyncMock()
    subject = coordinator(runtime=runtime)

    run(subject.resume(7))

    runtime.verify_resume.assert_awaited_once_with(subject.projects.get.return_value)
    runtime.resume.assert_awaited_once_with(subject.projects.get.return_value)


def test_run_holds_advisory_lock_bootstraps_then_discovers_and_waits_for_events() -> None:
    lock = Lock()
    bootstrap = AsyncMock()
    discovery = AsyncMock()
    runtime = AsyncMock()
    runtime.reconcile.return_value = healthy_snapshot()
    entered_wait = asyncio.Event()

    async def wait_for_change(project_id, signal, deadline):
        assert project_id == 7
        assert deadline is None
        entered_wait.set()
        await signal.wait()

    runtime.wait_for_change.side_effect = wait_for_change
    subject = coordinator(runtime=runtime, bootstrap=bootstrap, discovery=discovery, lock=lock)

    async def scenario():
        task = asyncio.create_task(subject.run(7))
        await asyncio.wait_for(entered_wait.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())

    assert lock.entered == [7]
    bootstrap.schedule.assert_awaited_once_with(7)
    discovery.discover.assert_awaited_once_with(subject.projects.get.return_value)
    runtime.reconcile.assert_awaited()


def test_run_exits_without_side_effects_when_database_lock_is_owned_elsewhere() -> None:
    bootstrap = AsyncMock()
    subject = coordinator(bootstrap=bootstrap, lock=Lock(acquired=False))

    run(subject.run(7))

    bootstrap.schedule.assert_not_awaited()


def test_postgres_advisory_lock_releases_the_same_project_key() -> None:
    from backend.services.campaigns.project_coordinator import PostgresProjectLock

    connection = AsyncMock()
    connection.fetchval.side_effect = [True, True]

    class Acquisition:
        async def __aenter__(self): return connection
        async def __aexit__(self, *args): return False

    pool = SimpleNamespace(acquire=lambda: Acquisition())

    async def scenario():
        async with PostgresProjectLock(pool).acquire(7) as acquired:
            assert acquired is True

    run(scenario())
    assert "pg_try_advisory_lock" in connection.fetchval.await_args_list[0].args[0]
    assert "pg_advisory_unlock" in connection.fetchval.await_args_list[1].args[0]
    assert connection.fetchval.await_args_list[0].args[1] == 7
    assert connection.fetchval.await_args_list[1].args[1] == 7


def test_advisory_unlock_failure_does_not_replace_the_coordinator_failure() -> None:
    from backend.services.campaigns.project_coordinator import PostgresProjectLock

    connection = AsyncMock()
    connection.fetchval.side_effect = [True, RuntimeError("unlock failed")]

    class Acquisition:
        async def __aenter__(self): return connection
        async def __aexit__(self, *args): return False

    async def scenario():
        with pytest.raises(ValueError, match="coordinator failed") as caught:
            async with PostgresProjectLock(SimpleNamespace(acquire=lambda: Acquisition())).acquire(7):
                raise ValueError("coordinator failed")
        assert any("unlock failed" in note for note in caught.value.__notes__)

    run(scenario())


def test_registry_starts_one_task_per_project_signals_changes_and_closes_every_task() -> None:
    from backend.services.campaigns.coordinator_registry import CoordinatorRegistry

    started = {1: asyncio.Event(), 2: asyncio.Event()}
    coordinators = {}

    class Coordinator:
        def __init__(self, identifier):
            self.identifier = identifier
            self.changed = Mock()
            self.paused = AsyncMock()
            self.resumed = AsyncMock()

        async def run(self, identifier):
            assert identifier == self.identifier
            started[identifier].set()
            await asyncio.Future()

        def notify(self, identifier):
            assert identifier == self.identifier
            self.changed()

        async def pause(self, identifier): await self.paused(identifier)
        async def resume(self, identifier): await self.resumed(identifier)

    def factory(identifier):
        value = Coordinator(identifier)
        coordinators[identifier] = value
        return value

    projects = AsyncMock()
    projects.list_unfinished.return_value = [project(identifier=1), project(identifier=2)]
    registry = CoordinatorRegistry(projects, factory)

    async def scenario():
        await registry.recover()
        await asyncio.wait_for(started[1].wait(), 1)
        await asyncio.wait_for(started[2].wait(), 1)
        assert registry.start(1) is False
        await registry.settings_changed(1)
        await registry.pause(1)
        await registry.resume(1)
        await registry.close()
        assert not registry.tasks

    run(scenario())

    coordinators[1].changed.assert_called()
    coordinators[1].paused.assert_awaited_once_with(1)
    coordinators[1].resumed.assert_awaited_once_with(1)


def test_registry_keeps_concurrent_projects_independent_when_one_fails() -> None:
    from backend.services.campaigns.coordinator_registry import CoordinatorRegistry

    healthy_started = asyncio.Event()

    class Failing:
        async def run(self, _project_id): raise RuntimeError("project failed")
        def notify(self, _project_id): pass

    class Healthy:
        async def run(self, _project_id):
            healthy_started.set()
            await asyncio.Future()
        def notify(self, _project_id): pass

    projects = AsyncMock()
    registry = CoordinatorRegistry(projects, lambda identifier: Failing() if identifier == 1 else Healthy())

    async def scenario():
        registry.start(1)
        registry.start(2)
        await asyncio.wait_for(healthy_started.wait(), 1)
        await asyncio.sleep(0)
        assert 1 not in registry.tasks
        assert 2 in registry.tasks
        await registry.close()

    run(scenario())


def test_backbone_compatibility_service_uses_registry_lifecycle_for_legacy_bootstrap() -> None:
    from backend.services.run_project_backbone import ProjectBackboneService

    projects = AsyncMock()
    bootstrap = AsyncMock()
    service = ProjectBackboneService(projects, bootstrap)

    async def scenario():
        assert service.schedule(7) is True
        assert service.schedule(7) is False
        await asyncio.sleep(0)
        bootstrap.schedule.assert_awaited_once_with(7)
        await service.close()

    run(scenario())


def test_production_project_settings_signal_the_same_recovery_registry(tmp_path) -> None:
    from backend.api.dependencies import build_services
    from backend.services.campaigns.project_coordinator import PostgresProjectLock

    services = build_services(AsyncMock(), tmp_path)

    assert services.project_settings._coordinator_registry is services.recovery
    assert isinstance(services.recovery._advisory_lock, PostgresProjectLock)
