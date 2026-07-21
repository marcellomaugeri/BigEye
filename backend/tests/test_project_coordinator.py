from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest


NOW = datetime(2026, 7, 20, 9, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


def project(*, identifier=7, workers=2, commit="a" * 40, manager_wake_at=None, error=None):
    return SimpleNamespace(
        id=identifier, worker_count=workers, commit_sha=commit,
        manager_wake_at=manager_wake_at, error=error,
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
    subject.projects.schedule_manager_review.assert_awaited_once_with(
        7,
        NOW + timedelta(seconds=30),
        "Retry after RuntimeError: validated corpus opportunity",
    )


def test_wait_uses_the_persisted_project_manager_deadline_after_reconstruction() -> None:
    runtime = AsyncMock()
    wake_at = NOW + timedelta(seconds=900)
    subject = coordinator(value=project(manager_wake_at=wake_at), runtime=runtime)
    seen = []

    async def wait_for_change(project_id, received_signal, deadline):
        seen.append((project_id, received_signal, deadline))

    runtime.wait_for_change.side_effect = wait_for_change

    run(subject._wait_for_change(7, healthy_snapshot()))

    assert seen[0][0] == 7
    assert isinstance(seen[0][1], asyncio.Event)
    assert seen[0][2] == wake_at


def test_manager_review_timeout_allows_long_multi_agent_repairs() -> None:
    from backend.services.campaigns.project_coordinator import MANAGER_REVIEW_TIMEOUT_SECONDS

    assert MANAGER_REVIEW_TIMEOUT_SECONDS == 3_600


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


def test_failed_selected_action_is_retried_once_with_sanitized_failure_evidence() -> None:
    from backend.services.campaigns.decision_executor import ActionError, ActionResult

    manager = AsyncMock()
    manager.review.return_value = object()
    current_time = [NOW]
    subject = coordinator(manager=manager)
    subject.decision_executor.execute.return_value = [
        ActionResult("target_1", None, ActionError(
            "RuntimeError", "build failed",
            {
                "phase": "target-build",
                "command": "clang /opt/bigeye/generated-assets/decoder_fuzz.c",
                "exit_code": 1,
                "stderr": "decoder_fuzz.c: file not found",
                "generated_path_mapping": [{
                    "relative_path": "decoder_fuzz.c",
                    "container_path": "/opt/bigeye/generated-assets/decoder_fuzz.c",
                }],
            },
        )),
    ]
    subject._clock = lambda: current_time[0]
    observation = healthy_snapshot(corpus_opportunity=True)

    for _ in range(3):
        run(subject.tick(7, observation))
        current_time[0] += timedelta(seconds=30)

    assert manager.review.await_count == 2
    assert subject.decision_executor.execute.await_count == 2
    retry_evidence = manager.review.await_args_list[1].args[1]
    failure = next(
        item for item in retry_evidence
        if item.get("kind") == "action_execution_failure"
    )
    assert failure["action_ids"] == ["target_1"]
    assert failure["error_types"] == ["RuntimeError"]
    assert failure["failures"] == [{
        "action_id": "target_1",
        "error_type": "RuntimeError",
        "message": "build failed",
        "phase": "target-build",
        "command": "clang /opt/bigeye/generated-assets/decoder_fuzz.c",
        "exit_code": 1,
        "stderr": "decoder_fuzz.c: file not found",
        "generated_path_mapping": [{
            "relative_path": "decoder_fuzz.c",
            "container_path": "/opt/bigeye/generated-assets/decoder_fuzz.c",
        }],
    }]
    assert 7 not in subject._pending_reviews


def test_action_failure_survives_coordinator_reconstruction_and_unrelated_crash_evidence(
    tmp_path,
) -> None:
    from backend.services.campaigns.decision_executor import ActionError, ActionResult
    from backend.services.observability.event_store import ProjectEventStore

    events = ProjectEventStore(tmp_path)
    runtime = AsyncMock()
    runtime.retirement_candidates.return_value = ()
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "repository:inventory"}]
    first_manager = AsyncMock()
    first_manager.review.return_value = object()
    first = coordinator(manager=first_manager, runtime=runtime, events=events)
    first.decision_executor.execute.return_value = [
        ActionResult("pipeline_bad_cli", None, ActionError(
            "TargetPreparationFailed", "bad fixed argv",
            {"phase": "probe", "command": ["/opt/bigeye/decoder_cli"]},
        )),
    ]

    run(first.tick(7, healthy_snapshot(corpus_opportunity=True)))

    recovered_runtime = AsyncMock()
    recovered_runtime.retirement_candidates.return_value = ()
    recovered_runtime.review_context.return_value = SimpleNamespace(project_id=7)
    recovered_runtime.review_evidence.return_value = [{
        "evidence_id": "finding:stable", "kind": "finalized_finding",
        "classification": "true vulnerability", "reproducible": True,
    }]
    recovered_manager = AsyncMock()
    recovered_manager.review.return_value = object()
    recovered = coordinator(
        manager=recovered_manager, runtime=recovered_runtime, events=events,
    )
    recovered_runtime.review_evidence.return_value = [{
        "evidence_id": "finding:stable", "kind": "finalized_finding",
        "classification": "true vulnerability", "reproducible": True,
    }]
    recovered.decision_executor.execute.return_value = []

    run(recovered.tick(7, healthy_snapshot(replayed_crash=True)))

    supplied = recovered_manager.review.await_args.args[1]
    failure = next(item for item in supplied if item.get("kind") == "action_execution_failure")
    assert failure["action_ids"] == ["pipeline_bad_cli"]
    assert "finding:stable" in [item["evidence_id"] for item in supplied], supplied
    assert supplied.index(failure) < next(
        index for index, item in enumerate(supplied) if item["evidence_id"] == "finding:stable"
    )


def test_distinct_successful_target_correction_resolves_retained_action_failure(
    tmp_path,
) -> None:
    from backend.services.campaigns.decision_executor import ActionError, ActionResult
    from backend.services.observability.event_store import ProjectEventStore

    events = ProjectEventStore(tmp_path)
    runtime = AsyncMock()
    runtime.retirement_candidates.return_value = ()
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "repository:inventory"}]
    correction = SimpleNamespace(
        selected_pipeline_operations=(SimpleNamespace(
            action_id="pipeline_corrected_cli", operation="probe",
        ),),
        selected_target_proposals=(),
    )
    manager = AsyncMock()
    manager.review.side_effect = [object(), correction, object()]
    current_time = [NOW]
    subject = coordinator(manager=manager, runtime=runtime, events=events)
    subject._clock = lambda: current_time[0]
    subject.decision_executor.execute.side_effect = [
        [ActionResult("pipeline_bad_cli", None, ActionError(
            "TargetPreparationFailed", "bad fixed argv", {"phase": "probe"},
        ))],
        [ActionResult("pipeline_corrected_cli", SimpleNamespace(campaign_id=2))],
        [],
    ]
    observation = healthy_snapshot(corpus_opportunity=True)

    run(subject.tick(7, observation))
    current_time[0] += timedelta(seconds=30)
    run(subject.tick(7, observation))
    runtime.review_evidence.return_value = [{
        "evidence_id": "finding:stable", "kind": "finalized_finding",
        "classification": "true vulnerability", "reproducible": True,
    }]
    current_time[0] += timedelta(seconds=1)
    run(subject.tick(7, healthy_snapshot(replayed_crash=True)))

    supplied = manager.review.await_args_list[2].args[1]
    assert all(item.get("kind") != "action_execution_failure" for item in supplied)
    resolution = next(
        event.payload for event in run(events.read_latest(7, "debug", -1, 100))
        if event.payload.get("event") == "campaign.action_failures_resolved"
    )
    assert resolution["correction_action_ids"] == ["pipeline_corrected_cli"]


def test_distinct_success_does_not_resolve_two_ambiguous_action_failure_groups(
    tmp_path,
) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    events = ProjectEventStore(tmp_path)
    subject = coordinator(events=events)
    component_failure = {
        "evidence_id": "action-failure:7:component",
        "kind": "action_execution_failure",
        "action_ids": ["component_bad_harness"],
        "error_types": ["TargetPreparationFailed"],
        "failures": [],
    }
    system_failure = {
        "evidence_id": "action-failure:7:system",
        "kind": "action_execution_failure",
        "action_ids": ["system_bad_argv"],
        "error_types": ["TargetPreparationFailed"],
        "failures": [],
    }
    subject._action_failures[7] = {
        component_failure["evidence_id"]: component_failure,
        system_failure["evidence_id"]: system_failure,
    }

    run(subject._resolve_action_failures(
        7,
        [component_failure, system_failure],
        ("component_corrected_harness",),
    ))

    retained = run(subject._unresolved_action_failures(7))
    assert {item["evidence_id"] for item in retained} == {
        "action-failure:7:component",
        "action-failure:7:system",
    }
    assert all(
        event.payload.get("event") != "campaign.action_failures_resolved"
        for event in run(events.read_latest(7, "debug", -1, 100))
    )


def test_distinct_success_does_not_resolve_one_group_with_two_failed_actions(
    tmp_path,
) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    events = ProjectEventStore(tmp_path)
    subject = coordinator(events=events)
    grouped_failure = {
        "evidence_id": "action-failure:7:grouped",
        "kind": "action_execution_failure",
        "action_ids": ["component_bad_harness", "system_bad_argv"],
        "error_types": ["TargetPreparationFailed"],
        "failures": [
            {
                "action_id": "component_bad_harness",
                "error_type": "TargetPreparationFailed",
                "message": "component build failed",
            },
            {
                "action_id": "system_bad_argv",
                "error_type": "TargetPreparationFailed",
                "message": "system probe failed",
            },
        ],
    }
    subject._action_failures[7] = {
        grouped_failure["evidence_id"]: grouped_failure,
    }

    run(subject._resolve_action_failures(
        7,
        [grouped_failure],
        ("component_corrected_harness",),
    ))

    assert run(subject._unresolved_action_failures(7)) == (grouped_failure,)
    assert all(
        event.payload.get("event") != "campaign.action_failures_resolved"
        for event in run(events.read_latest(7, "debug", -1, 100))
    )


def test_next_review_receives_exact_component_path_and_cli_seed_failures() -> None:
    from backend.services.campaigns.decision_executor import ActionError, ActionResult

    manager = AsyncMock(return_value=object())
    current_time = [NOW]
    subject = coordinator(manager=manager)
    subject._clock = lambda: current_time[0]
    subject.decision_executor.execute.return_value = [
        ActionResult("component", None, ActionError(
            "TargetPreparationFailed", "component build failed",
            {
                "phase": "target-build", "exit_code": 1,
                "command": "clang /opt/bigeye/generated-assets/decoder_fuzz.c",
                "stderr": "decoder_fuzz.c: file not found",
                "generated_path_mapping": [{
                    "relative_path": "generated-assets/decoder_fuzz.c",
                    "container_path": (
                        "/opt/bigeye/generated-assets/generated-assets/decoder_fuzz.c"
                    ),
                }],
            },
        )),
        ActionResult("cli", None, ActionError(
            "TargetPreparationFailed", "fixed argv rejected seed",
            {
                "phase": "clean-coverage", "exit_code": 1,
                "command": ["/opt/bigeye/build/decoder_cli", "--file", "{input}"],
                "stderr": "configuration-incompatible seed",
                "failing_seed": "seeds/framed.input",
                "testcase_sha256": "a" * 64,
            },
        )),
    ]
    observation = healthy_snapshot(corpus_opportunity=True)

    run(subject.tick(7, observation))
    current_time[0] += timedelta(seconds=30)
    run(subject.tick(7, observation))

    retry_evidence = manager.review.await_args_list[1].args[1]
    failure = next(item for item in retry_evidence if item.get("kind") == "action_execution_failure")
    by_action = {item["action_id"]: item for item in failure["failures"]}
    assert by_action["component"]["generated_path_mapping"][0]["container_path"] == (
        "/opt/bigeye/generated-assets/generated-assets/decoder_fuzz.c"
    )
    assert by_action["component"]["stderr"] == "decoder_fuzz.c: file not found"
    assert by_action["cli"]["failing_seed"] == "seeds/framed.input"
    assert by_action["cli"]["command"][-1] == "{input}"


def test_sibling_action_failure_persists_a_near_wake_and_recovery_sees_current_evidence() -> None:
    from backend.services.campaigns.decision_executor import ActionError, ActionResult

    project_value = project()
    current_time = [NOW]
    first_manager = AsyncMock()
    first_manager.review.return_value = SimpleNamespace(decision=SimpleNamespace(
        next_review_delay_seconds=180,
        next_review_reason="Review both prepared campaigns.",
    ))
    runtime = AsyncMock()
    runtime.retirement_candidates.return_value = ()
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "repository:inventory"}]
    subject = coordinator(value=project_value, manager=first_manager, runtime=runtime)
    subject._clock = lambda: current_time[0]

    async def execute_siblings(_project, _decision):
        current_time[0] += timedelta(seconds=40)
        return [
            ActionResult("system", SimpleNamespace(campaign_id=1)),
            ActionResult("component", None, ActionError(
                "TargetPreparationFailed", "unsupported compiler frontend", {},
            )),
        ]

    async def schedule(project_id, wake_at, reason):
        assert project_id == 7
        project_value.manager_wake_at = wake_at
        project_value.manager_wake_reason = reason

    subject.decision_executor.execute.side_effect = execute_siblings
    subject.projects.schedule_manager_review.side_effect = schedule

    run(subject.tick(7, healthy_snapshot(corpus_opportunity=True)))

    correction_wake = NOW + timedelta(seconds=70)
    assert project_value.manager_wake_at == correction_wake
    subject.projects.schedule_manager_review.assert_awaited_once_with(
        7,
        correction_wake,
        "Retry after ActionExecutionFailed: validated corpus opportunity",
    )
    runtime.schedule_next_review.assert_awaited_once_with(
        project_value,
        correction_wake,
        "Retry after ActionExecutionFailed: validated corpus opportunity",
    )
    runtime.stop_campaigns.assert_not_awaited()

    current_inventory = {
        "evidence_id": "campaign-strategies:current",
        "kind": "campaign_strategy_inventory",
        "strategies": [{"engine": "afl", "activity": "working"}],
        "required_next_instance_type": "component-level",
    }
    current_failure = {
        "evidence_id": "target-attempt:component:failed",
        "kind": "target_preparation_attempt",
        "status": "failed",
    }
    recovered_runtime = AsyncMock()
    recovered_runtime.retirement_candidates.return_value = ()
    recovered_runtime.review_context.return_value = SimpleNamespace(project_id=7)
    recovered_runtime.review_evidence.return_value = [current_failure, current_inventory]
    recovered_manager = AsyncMock()
    recovered_manager.review.return_value = SimpleNamespace(decision=SimpleNamespace(
        next_review_delay_seconds=900,
        next_review_reason="Review corrected component campaign.",
    ))
    recovered = coordinator(
        value=project_value, manager=recovered_manager, runtime=recovered_runtime,
    )
    recovered_runtime.review_evidence.return_value = [current_failure, current_inventory]
    current_time[0] = correction_wake
    recovered._clock = lambda: current_time[0]
    recovered.decision_executor.execute.return_value = []

    run(recovered.tick(7, healthy_snapshot(active_workers=1, free_slots=0)))

    recovered_manager.review.assert_awaited_once()
    assert recovered_manager.review.await_args.args[1] == [current_failure, current_inventory]
    assert recovered_manager.review.await_args.args[2] == "review window expired"


def test_active_run_retries_failed_sibling_on_durable_deadline_without_restarting() -> None:
    from backend.services.campaigns.decision_executor import ActionError, ActionResult
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    value = project()
    value.manager_wake_reason = None
    projects = AsyncMock()
    projects.get.return_value = value

    async def schedule(_project_id, wake_at, reason):
        value.manager_wake_at = wake_at
        value.manager_wake_reason = reason

    projects.schedule_manager_review.side_effect = schedule
    healthy_campaign = {"running": False}
    full_reconciles = 0
    fast_reconciles = 0
    current_inventory = {
        "evidence_id": "campaign-strategies:current",
        "kind": "campaign_strategy_inventory",
        "strategies": [{"engine": "afl", "activity": "working"}],
        "required_next_instance_type": "component-level",
    }

    class Runtime:
        async def reconcile(self, _project):
            nonlocal full_reconciles
            full_reconciles += 1
            return healthy_snapshot(corpus_opportunity=True, active_workers=int(healthy_campaign["running"]))

        async def reconcile_for_review(self, _project):
            nonlocal fast_reconciles
            fast_reconciles += 1
            assert healthy_campaign["running"] is True
            return healthy_snapshot(active_workers=1, free_slots=1)

        async def review_context(self, _project, _snapshot):
            return SimpleNamespace(project_id=7)

        async def review_evidence(self, _project, _snapshot, _trigger):
            return [current_inventory] if healthy_campaign["running"] else [
                {"evidence_id": "repository:inventory"},
            ]

        async def retirement_candidates(self, _project, _snapshot):
            return ()

        async def schedule_next_review(self, _project, _deadline, _reason):
            return None

        async def apply_cpu_checkpoint(self, _project, _snapshot):
            return None

    runtime = Runtime()
    manager = AsyncMock()
    manager.review.side_effect = [
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=180,
            next_review_reason="Review both prepared campaigns.",
        )),
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=900,
            next_review_reason="Review corrected component campaign.",
        )),
    ]
    executor = AsyncMock()
    repaired = asyncio.Event()

    async def execute(_project, _decision):
        if executor.execute.await_count == 1:
            healthy_campaign["running"] = True
            return [
                ActionResult("system", SimpleNamespace(campaign_id=1)),
                ActionResult("component", None, ActionError(
                    "TargetPreparationFailed", "unsupported compiler frontend", {},
                )),
            ]
        assert healthy_campaign["running"] is True
        repaired.set()
        return [ActionResult("component-repair", SimpleNamespace(campaign_id=2))]

    executor.execute.side_effect = execute
    subject = ProjectCoordinator(
        projects=projects,
        bootstrap=AsyncMock(),
        discovery=AsyncMock(),
        manager=manager,
        decision_executor=executor,
        runtime=runtime,
        advisory_lock=Lock(),
        manager_retry_delay_seconds=0.02,
    )

    async def scenario():
        task = asyncio.create_task(subject.run(7))
        await asyncio.wait_for(repaired.wait(), 1)
        await asyncio.sleep(0.04)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())

    assert manager.review.await_count == 2
    retry_evidence = manager.review.await_args_list[1].args[1]
    assert retry_evidence[0]["kind"] == "action_execution_failure"
    assert current_inventory in retry_evidence
    assert executor.execute.await_count == 2
    assert healthy_campaign["running"] is True
    assert full_reconciles == 1
    assert fast_reconciles == 1


def test_durable_backoff_interrupts_long_reconcile_and_runs_one_manager_review() -> None:
    from backend.services.campaigns.decision_executor import ActionError, ActionResult
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    value = project()
    value.manager_wake_reason = None
    projects = AsyncMock()
    projects.get.return_value = value

    async def schedule(_project_id, wake_at, reason):
        value.manager_wake_at = wake_at
        value.manager_wake_reason = reason

    projects.schedule_manager_review.side_effect = schedule
    healthy_campaign = {"running": False}
    full_reconciles = 0
    fast_reconciles = 0
    long_reconcile_started = asyncio.Event()
    long_reconcile_cancelled = asyncio.Event()
    current_inventory = {
        "evidence_id": "campaign-strategies:current",
        "kind": "campaign_strategy_inventory",
        "strategies": [{"engine": "afl", "activity": "working"}],
        "required_next_instance_type": "component-level",
    }

    class Runtime:
        async def reconcile(self, _project):
            nonlocal full_reconciles
            full_reconciles += 1
            if full_reconciles == 1:
                return healthy_snapshot(corpus_opportunity=True)
            long_reconcile_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                long_reconcile_cancelled.set()

        async def reconcile_for_review(self, _project):
            nonlocal fast_reconciles
            fast_reconciles += 1
            assert healthy_campaign["running"] is True
            return healthy_snapshot(active_workers=1, free_slots=1)

        async def review_context(self, _project, _snapshot):
            return SimpleNamespace(project_id=7)

        async def review_evidence(self, _project, _snapshot, _trigger):
            return [current_inventory] if healthy_campaign["running"] else [
                {"evidence_id": "repository:inventory"},
            ]

        async def retirement_candidates(self, _project, _snapshot):
            return ()

        async def schedule_next_review(self, _project, _deadline, _reason):
            return None

        async def apply_cpu_checkpoint(self, _project, _snapshot):
            return None

    manager = AsyncMock()
    manager.review.side_effect = [
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=180,
            next_review_reason="Review both prepared campaigns.",
        )),
        RuntimeError("bounded manager attempt failed"),
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=900,
            next_review_reason="Review corrected component campaign.",
        )),
    ]
    executor = AsyncMock()
    repaired = asyncio.Event()

    async def execute(_project, _decision):
        if executor.execute.await_count == 1:
            healthy_campaign["running"] = True
            return [
                ActionResult("system", SimpleNamespace(campaign_id=1)),
                ActionResult("component", None, ActionError(
                    "TargetPreparationFailed", "unsupported compiler frontend", {},
                )),
            ]
        repaired.set()
        return [ActionResult("component-repair", SimpleNamespace(campaign_id=2))]

    executor.execute.side_effect = execute
    subject = ProjectCoordinator(
        projects=projects,
        bootstrap=AsyncMock(),
        discovery=AsyncMock(),
        manager=manager,
        decision_executor=executor,
        runtime=Runtime(),
        advisory_lock=Lock(),
        manager_retry_delay_seconds=0.02,
        manager_failure_backoff_seconds=0.03,
    )

    async def scenario():
        task = asyncio.create_task(subject.run(7))
        await asyncio.wait_for(long_reconcile_started.wait(), 1)
        await asyncio.wait_for(repaired.wait(), 1)
        await asyncio.sleep(0.04)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())

    assert long_reconcile_cancelled.is_set()
    assert manager.review.await_count == 3
    final_evidence = manager.review.await_args_list[2].args[1]
    assert final_evidence[0]["kind"] == "action_execution_failure"
    assert current_inventory in final_evidence
    assert executor.execute.await_count == 2
    assert healthy_campaign["running"] is True
    assert full_reconciles == 2
    assert fast_reconciles == 2


def test_reconstructed_coordinator_timer_interrupts_reconcile_for_persisted_wake() -> None:
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    value = project(manager_wake_at=datetime.now(UTC) + timedelta(seconds=0.02))
    value.manager_wake_reason = "Failure backoff after TimeoutError: initial supervision completed"
    projects = AsyncMock()
    projects.get.return_value = value

    async def schedule(_project_id, wake_at, reason):
        value.manager_wake_at = wake_at
        value.manager_wake_reason = reason

    projects.schedule_manager_review.side_effect = schedule
    reconcile_started = asyncio.Event()
    reconcile_cancelled = asyncio.Event()
    fast_reconciles = 0

    class Runtime:
        async def reconcile(self, _project):
            reconcile_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                reconcile_cancelled.set()

        async def reconcile_for_review(self, _project):
            nonlocal fast_reconciles
            fast_reconciles += 1
            return healthy_snapshot(active_workers=1)

        async def review_context(self, _project, _snapshot):
            return SimpleNamespace(project_id=7)

        async def review_evidence(self, _project, _snapshot, _trigger):
            return [{
                "evidence_id": "campaign-strategies:current",
                "kind": "campaign_strategy_inventory",
                "strategies": [{"engine": "afl", "activity": "working"}],
            }]

        async def retirement_candidates(self, _project, _snapshot):
            return ()

        async def schedule_next_review(self, _project, _deadline, _reason):
            return None

        async def apply_cpu_checkpoint(self, _project, _snapshot):
            return None

    reviewed = asyncio.Event()
    manager = AsyncMock()

    async def review(*_args, **_kwargs):
        reviewed.set()
        return SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=900,
            next_review_reason="Review recovered campaign.",
        ))

    manager.review.side_effect = review
    subject = ProjectCoordinator(
        projects=projects,
        bootstrap=AsyncMock(),
        discovery=AsyncMock(),
        manager=manager,
        decision_executor=AsyncMock(execute=AsyncMock(return_value=[])),
        runtime=Runtime(),
        advisory_lock=Lock(),
    )

    async def scenario():
        task = asyncio.create_task(subject.run(7))
        await asyncio.wait_for(reconcile_started.wait(), 1)
        await asyncio.wait_for(reviewed.wait(), 1)
        await asyncio.sleep(0.04)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())

    assert reconcile_cancelled.is_set()
    assert fast_reconciles == 1
    assert manager.review.await_count == 1


def test_successful_manager_review_persists_the_manager_selected_deadline() -> None:
    manager = AsyncMock()
    manager.review.return_value = SimpleNamespace(decision=SimpleNamespace(
        next_review_delay_seconds=900,
        next_review_reason="Recheck clean coverage slope and corpus growth.",
    ))
    runtime = AsyncMock()
    runtime.retirement_candidates.return_value = ()
    runtime.review_context.return_value = SimpleNamespace(project_id=7)
    runtime.review_evidence.return_value = [{"evidence_id": "campaign:3"}]
    subject = coordinator(manager=manager, runtime=runtime)
    subject.decision_executor.execute.return_value = []

    run(subject.tick(7, healthy_snapshot(review_due=True, next_review_after=NOW)))

    subject.projects.schedule_manager_review.assert_awaited_once_with(
        7,
        NOW + timedelta(seconds=900),
        "Recheck clean coverage slope and corpus growth.",
    )


def test_expired_campaign_deadline_advances_with_the_manager_deadline() -> None:
    project_value = project()
    manager = AsyncMock()
    manager.review.side_effect = [
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=900,
            next_review_reason="Recheck clean coverage slope.",
        )),
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=1_200,
            next_review_reason="Recheck corpus growth.",
        )),
    ]
    runtime = AsyncMock()
    campaign_deadline = [NOW]
    current_time = [NOW]
    subject = coordinator(value=project_value, manager=manager, runtime=runtime)
    subject._clock = lambda: current_time[0]
    subject.decision_executor.execute.return_value = []

    async def schedule_project(project_id, wake_at, reason):
        assert project_id == 7
        project_value.manager_wake_at = wake_at

    async def schedule_campaign(project, wake_at, reason):
        assert project is project_value
        campaign_deadline[0] = wake_at

    subject.projects.schedule_manager_review.side_effect = schedule_project
    runtime.schedule_next_review.side_effect = schedule_campaign

    run(subject.tick(7, healthy_snapshot(review_due=True, next_review_after=NOW)))

    runtime.schedule_next_review.assert_awaited_once_with(
        project_value,
        NOW + timedelta(seconds=900),
        "Recheck clean coverage slope.",
    )
    run(subject.tick(7, healthy_snapshot(next_review_after=campaign_deadline[0])))
    assert manager.review.await_count == 1

    current_time[0] += timedelta(seconds=900)
    run(subject.tick(7, healthy_snapshot(
        review_due=True, next_review_after=campaign_deadline[0],
    )))
    assert manager.review.await_count == 2


def test_successive_manager_deadlines_wake_after_each_selected_delay() -> None:
    project_value = project(manager_wake_at=NOW)
    manager = AsyncMock()
    manager.review.side_effect = [
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=900,
            next_review_reason="Recheck clean coverage slope.",
        )),
        SimpleNamespace(decision=SimpleNamespace(
            next_review_delay_seconds=1_200,
            next_review_reason="Recheck corpus growth.",
        )),
    ]
    current_time = [NOW]
    subject = coordinator(value=project_value, manager=manager)
    subject._clock = lambda: current_time[0]
    subject.decision_executor.execute.return_value = []

    async def schedule(project_id, wake_at, reason):
        assert project_id == 7
        project_value.manager_wake_at = wake_at

    subject.projects.schedule_manager_review.side_effect = schedule

    run(subject.tick(7, healthy_snapshot()))
    current_time[0] += timedelta(seconds=900)
    run(subject.tick(7, healthy_snapshot()))

    assert manager.review.await_count == 2
    assert project_value.manager_wake_at == NOW + timedelta(seconds=2_100)


def test_second_manager_failure_starts_a_durable_five_minute_backoff() -> None:
    project_value = project()
    manager = AsyncMock()
    manager.review.side_effect = RuntimeError("unavailable")
    current_time = [NOW]
    subject = coordinator(value=project_value, manager=manager)
    subject._clock = lambda: current_time[0]
    observation = healthy_snapshot(corpus_opportunity=True)

    async def schedule(project_id, wake_at, reason):
        assert project_id == 7
        project_value.manager_wake_at = wake_at

    subject.projects.schedule_manager_review.side_effect = schedule

    run(subject.tick(7, observation))
    current_time[0] += timedelta(seconds=30)
    run(subject.tick(7, observation))

    assert manager.review.await_count == 2
    assert project_value.manager_wake_at == NOW + timedelta(seconds=330)
    assert subject._previous[7].manager_wake_at == NOW + timedelta(seconds=330)
    assert subject._runtime.schedule_next_review.await_args_list[:2] == [
        call(
            project_value,
            NOW + timedelta(seconds=30),
            "Retry after RuntimeError: validated corpus opportunity",
        ),
        call(
            project_value,
            NOW + timedelta(seconds=330),
            "Failure backoff after RuntimeError: validated corpus opportunity",
        ),
    ]

    current_time[0] += timedelta(seconds=30)
    assert run(subject.tick(7, observation)) is None
    assert manager.review.await_count == 2

    current_time[0] += timedelta(seconds=270)
    run(subject.tick(7, observation))
    assert manager.review.await_count == 3


def test_current_deterministic_progression_is_a_prepared_manager_action() -> None:
    from backend.agents.outputs.campaign_review import ProgressionActionRecord
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    action = ProgressionActionRecord(
        action_id="campaign-progression:7:9:abcd1234abcd1234",
        project_id=7, base_campaign_id=9, target_asset_id=31,
        action_name="enable dictionary", evidence_ids=("source:parser.c:8",),
        dictionary_content='token_000="MAGIC"\n',
    )
    context = SimpleNamespace(project_id=7, commit_sha="a" * 40)
    campaigns = AsyncMock()
    campaigns.schedule_next_reviews.return_value = True
    runtime = RepositoryCampaignRuntime(
        tasks=AsyncMock(), assets=AsyncMock(), campaigns=campaigns,
        discovery=SimpleNamespace(context=lambda _project_id: context),
        containers=AsyncMock(),
    )
    runtime._progression_records[7] = (action,)
    runtime._review_evidence[7] = ({
        "evidence_id": action.action_id, "trusted_instructions": False,
    },)
    manager = AsyncMock()
    manager.review.return_value = object()
    projects = AsyncMock()
    projects.get.return_value = project()
    decision_executor = AsyncMock()
    decision_executor.execute.return_value = []
    subject = ProjectCoordinator(
        projects=projects, bootstrap=AsyncMock(), discovery=AsyncMock(),
        manager=manager, decision_executor=decision_executor,
        runtime=runtime, advisory_lock=Lock(), clock=lambda: NOW,
    )

    run(subject.tick(7, healthy_snapshot(corpus_opportunity=True)))

    assert manager.review.await_args.kwargs["prepared_actions"] == (action,)


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
    acquire_call, release_call = connection.fetchval.await_args_list
    assert "pg_try_advisory_lock($1::integer, $2::integer)" in acquire_call.args[0]
    assert "pg_advisory_unlock($1::integer, $2::integer)" in release_call.args[0]
    assert acquire_call.args[1:] == (0, 7)
    assert release_call.args[1:] == acquire_call.args[1:]


@pytest.mark.parametrize(("project_id", "expected_keys"), (
    (1, (0, 1)),
    (0xFFFF_FFFF, (0, -1)),
    (0x1_0000_0000, (1, 0)),
    (0x7FFF_FFFF_FFFF_FFFF, (0x7FFF_FFFF, -1)),
))
def test_postgres_advisory_lock_losslessly_splits_signed_bigint_keys(
    project_id: int, expected_keys: tuple[int, int],
) -> None:
    from backend.services.campaigns.project_coordinator import PostgresProjectLock

    connection = AsyncMock()
    connection.fetchval.side_effect = [True, True]

    class Acquisition:
        async def __aenter__(self): return connection
        async def __aexit__(self, *args): return False

    async def scenario():
        async with PostgresProjectLock(SimpleNamespace(acquire=lambda: Acquisition())).acquire(
            project_id,
        ):
            pass

    run(scenario())

    acquire_call, release_call = connection.fetchval.await_args_list
    assert acquire_call.args[1:] == expected_keys
    assert release_call.args[1:] == acquire_call.args[1:]


def test_postgres_advisory_lock_rejects_ids_outside_postgresql_bigint() -> None:
    from backend.services.campaigns.project_coordinator import PostgresProjectLock

    class Pool:
        def acquire(self):
            raise AssertionError("invalid project ID must not acquire a PostgreSQL connection")

    async def scenario():
        async with PostgresProjectLock(Pool()).acquire(0x8000_0000_0000_0000):
            pass

    with pytest.raises(ValueError, match="PostgreSQL BIGINT"):
        run(scenario())


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

        async def run(self, identifier):
            assert identifier == self.identifier
            started[identifier].set()
            await asyncio.Future()

        def notify(self, identifier):
            assert identifier == self.identifier
            self.changed()

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
        await registry.close()
        assert not registry.tasks

    run(scenario())

    coordinators[1].changed.assert_called()


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


def test_registry_retries_transient_coordinator_failures_with_bounded_exponential_backoff() -> None:
    from backend.services.campaigns.coordinator_registry import CoordinatorRegistry

    attempts = []
    delays = []

    class Failing:
        async def run(self, identifier):
            attempts.append(identifier)
            raise RuntimeError("coordinator crashed")
        def notify(self, _identifier): pass

    async def sleep(delay):
        delays.append(delay)
        await asyncio.sleep(0)

    projects = AsyncMock()
    projects.get.return_value = project(identifier=7)
    registry = CoordinatorRegistry(
        projects,
        lambda _identifier: Failing(),
        restart_base_delay_seconds=1,
        restart_max_delay_seconds=4,
        sleep=sleep,
    )

    async def scenario():
        registry.start(7)
        for _ in range(100):
            await asyncio.sleep(0)
            if len(attempts) >= 5:
                break
        await registry.close()

    run(scenario())

    assert len(attempts) >= 5
    assert delays[:4] == [1, 2, 4, 4]
    projects.finish.assert_not_awaited()


def test_registry_terminalises_only_an_explicit_permanent_project_failure() -> None:
    from backend.services.campaigns.coordinator_registry import (
        CoordinatorRegistry,
        PermanentCoordinatorFailure,
    )

    class Failing:
        async def run(self, _identifier):
            raise PermanentCoordinatorFailure("bootstrap project state is corrupt")
        def notify(self, _identifier): pass

    projects = AsyncMock()
    projects.get.return_value = project(identifier=7)
    registry = CoordinatorRegistry(projects, lambda _identifier: Failing())

    async def scenario():
        registry.start(7)
        for _ in range(20):
            await asyncio.sleep(0)
            if projects.finish.await_count:
                break
        await registry.close()

    run(scenario())

    projects.finish.assert_awaited_once_with(
        7, "coordinator failed (PermanentCoordinatorFailure)",
    )


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
