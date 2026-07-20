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


def coordinator(
    *, value=None, snapshot=None, manager=None, runtime=None, bootstrap=None, discovery=None,
    lock=None, events=None, retirement_candidates=(),
):
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    value = value or project()
    projects = AsyncMock()
    projects.get.return_value = value
    runtime = runtime or AsyncMock()
    runtime.retirement_candidates.return_value = retirement_candidates
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


def test_every_campaign_observation_applies_cpu_exposure_before_wake_evaluation() -> None:
    runtime = AsyncMock()
    subject = coordinator(runtime=runtime)

    run(subject.tick(project_id=7, snapshot=healthy_snapshot()))

    runtime.apply_cpu_checkpoint.assert_awaited_once_with(
        subject.projects.get.return_value, healthy_snapshot(),
    )
    assert runtime.method_calls[0][0] == "apply_cpu_checkpoint"


def test_overlap_candidate_is_reviewed_without_preemptively_stopping_the_worker() -> None:
    from backend.fuzzing.coverage.overlap import RetirementCandidate

    runtime = AsyncMock()
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "campaign:3"}]
    runtime.retirement_candidates.return_value = (
        RetirementCandidate(
            project_id=7,
            campaign_id=9,
            strategy_asset_id=90,
            retained_campaign_id=4,
            retained_strategy_asset_id=40,
            evidence_ids=("candidate:1", "retained:1", "candidate:2", "retained:2"),
            reason="clean coverage remained a subset for two consecutive checkpoints",
        ),
    )
    manager = AsyncMock()
    decision = object()
    manager.review.return_value = decision
    subject = coordinator(
        runtime=runtime,
        manager=manager,
        retirement_candidates=runtime.retirement_candidates.return_value,
    )

    trigger = run(subject.tick(project_id=7, snapshot=healthy_snapshot()))

    assert trigger.reason == "overlap retirement candidate"
    runtime.stop_campaigns.assert_not_awaited()
    evidence = manager.review.await_args.args[1]
    retirement = next(item for item in evidence if item["evidence_id"].startswith("retirement:"))
    assert retirement["campaign_id"] == 9
    assert retirement["retained_campaign_id"] == 4
    assert retirement["reversible"] is True
    assert retirement["preserved"] == ["assets", "corpus", "evidence", "reason"]
    subject.decision_executor.execute.assert_awaited_once_with(
        subject.projects.get.return_value, decision,
    )


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


def test_failed_one_shot_review_is_retried_once_without_losing_its_edge() -> None:
    manager = AsyncMock()
    decision = object()
    manager.review.side_effect = [RuntimeError("temporary"), decision]
    current_time = [NOW]
    subject = coordinator(manager=manager)
    subject._clock = lambda: current_time[0]
    observation = healthy_snapshot(corpus_opportunity=True)

    first = run(subject.tick(7, observation))
    current_time[0] += timedelta(seconds=30)
    second = run(subject.tick(7, observation))
    current_time[0] += timedelta(seconds=30)
    third = run(subject.tick(7, observation))

    assert first.reason == second.reason == "validated corpus opportunity"
    assert third is None
    assert manager.review.await_count == 2
    subject.decision_executor.execute.assert_awaited_once_with(
        subject.projects.get.return_value, decision,
    )


def test_failed_review_sets_one_time_deadline_instead_of_busy_polling() -> None:
    manager = AsyncMock()
    manager.review.side_effect = RuntimeError("temporary")
    runtime = AsyncMock()
    runtime.retirement_candidates.return_value = ()
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "campaign:3"}]
    subject = coordinator(manager=manager, runtime=runtime)

    run(subject.tick(7, healthy_snapshot(corpus_opportunity=True)))

    seen = []

    async def wait_for_change(project_id, received_signal, deadline):
        seen.append((project_id, received_signal, deadline))

    runtime.wait_for_change.side_effect = wait_for_change
    run(subject._wait_for_change(7, healthy_snapshot(corpus_opportunity=True)))

    assert len(seen) == 1
    assert seen[0][0] == 7
    assert isinstance(seen[0][1], asyncio.Event)
    assert seen[0][2] == NOW + timedelta(seconds=30)
    assert manager.review.await_count == 1


def test_repeated_manager_failure_is_bounded_to_two_attempts() -> None:
    manager = AsyncMock()
    manager.review.side_effect = RuntimeError("unavailable")
    current_time = [NOW]
    subject = coordinator(manager=manager)
    subject._clock = lambda: current_time[0]
    observation = healthy_snapshot(corpus_opportunity=True)

    run(subject.tick(7, observation))
    current_time[0] += timedelta(seconds=30)
    run(subject.tick(7, observation))
    current_time[0] += timedelta(seconds=30)
    assert run(subject.tick(7, observation)) is None

    assert manager.review.await_count == 2


def test_failed_retirement_review_retries_the_exact_original_action() -> None:
    from backend.fuzzing.coverage.overlap import RetirementCandidate

    candidate = RetirementCandidate(
        project_id=7, campaign_id=9, strategy_asset_id=90,
        retained_campaign_id=4, retained_strategy_asset_id=40,
        evidence_ids=("candidate:1", "retained:1", "candidate:2", "retained:2"),
        reason="clean subset at two checkpoints",
    )
    runtime = AsyncMock()
    runtime.retirement_candidates.side_effect = [(candidate,), ()]
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "campaign:3"}]
    manager = AsyncMock()
    manager.review.side_effect = [RuntimeError("temporary"), object()]
    current_time = [NOW]
    subject = coordinator(runtime=runtime, manager=manager)
    subject._clock = lambda: current_time[0]

    run(subject.tick(7, healthy_snapshot()))
    current_time[0] += timedelta(seconds=30)
    run(subject.tick(7, healthy_snapshot()))

    first = manager.review.await_args_list[0]
    second = manager.review.await_args_list[1]
    assert first.kwargs["prepared_actions"] == second.kwargs["prepared_actions"]
    assert first.args[1] == second.args[1]
    assert first.kwargs["prepared_actions"][0].action_id == "retirement:7:9:90:4:40"


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
