"""Durable campaign progression and recurring review regression contracts."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock


NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


class _Lock:
    @asynccontextmanager
    async def acquire(self, _project_id):
        yield True


def test_fresh_runtime_and_coordinator_recover_the_same_partial_progression() -> None:
    from backend.agents.outputs.campaign_decision import CampaignDecision
    from backend.agents.outputs.campaign_review import CampaignReviewCollection
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.decision_executor import DecisionExecutor
    from backend.services.campaigns.production_runtime import (
        CampaignProgressObservation,
        ContainerObservation,
        RepositoryCampaignRuntime,
    )
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    project = SimpleNamespace(
        id=7, commit_sha="a" * 40, worker_count=2, paused_at=None, error=None,
    )
    base = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", started_at=NOW, stopped_at=None, last_heartbeat_at=NOW,
        cpu_seconds=1.0, next_review_after=NOW, next_review_reason="periodic",
        error=None,
    )
    partial = SimpleNamespace(
        id=12, project_id=7, target_asset_id=31, configuration_asset_id=41,
        engine="afl", started_at=NOW, stopped_at=None, last_heartbeat_at=None,
        cpu_seconds=0.0, next_review_after=NOW,
        next_review_reason="initial campaign supervision",
        error="variant publication interrupted",
    )
    progress = CampaignProgressObservation(
        9, 1.0, NOW, 2, 0, "progress:9", "container-9",
        executions=100, executions_per_second=20.0,
    )
    tasks = AsyncMock()
    tasks.list_for_project.return_value = [
        SimpleNamespace(name="repository clone", finished_at=NOW, error=None),
        SimpleNamespace(name="LLVM toolchain preparation", finished_at=NOW, error=None),
    ]
    assets = AsyncMock()
    assets.list_for_project.return_value = []
    campaigns = AsyncMock()
    campaigns.list_for_project.return_value = [base, partial]
    campaigns.get.return_value = base
    campaigns.get_progression.return_value = partial
    campaigns.create_progression.return_value = partial
    campaigns.clear_progression_error.return_value = True
    campaigns.schedule_next_reviews.return_value = True
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation(
        active_campaign_ids=(9,), progress=(progress,),
    )
    context = SimpleNamespace(project_id=7, commit_sha=project.commit_sha)
    discovery = SimpleNamespace(
        context=lambda _project_id: context,
        evidence=lambda _project_id: ({
            "evidence_id": "source:parser.c:8",
            "path": "parser.c",
            "excerpt": 'strcmp(input, "MAGIC")',
            "trusted_instructions": False,
        },),
    )
    campaign_contexts = AsyncMock()
    campaign_contexts.list_contexts_for_project.return_value = {
        9: {"configuration_purpose": "default", "retirement_reason": None},
        12: {
            "configuration_purpose": "enable dictionary",
            "retirement_reason": None,
        },
    }
    invocation = ContainerInvocation(
        engine="afl", image_id="sha256:" + "b" * 64,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--",
            "/opt/bigeye/parser", "@@",
        ],
        environment={"AFL_NO_UI": "1"}, campaign_labels={},
        network_disabled=True, read_only_source=True,
        timeout_ms=1_000, memory_limit_mb=1_024,
    )
    invocations = SimpleNamespace(
        load=lambda *_args: invocation,
        clone_variant=AsyncMock(),
    )
    progression_assets = AsyncMock()
    progression_assets.publish.return_value = SimpleNamespace(
        id=41, project_id=7, parent_id=32, validated_at=NOW, error=None,
    )
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=discovery, containers=containers, invocations=invocations,
        campaign_contexts=campaign_contexts,
        progression_assets=progression_assets,
        clock=lambda: NOW,
    )

    snapshot = run(runtime.reconcile(project))
    recovered_actions = runtime.progression_actions(project.id)
    assert len(recovered_actions) == 1
    recovered = recovered_actions[0]
    assert recovered.base_campaign_id == base.id
    assert recovered.action_name == "enable dictionary"

    async def review(_context, _evidence, _reason, *, prepared_actions):
        assert prepared_actions == (recovered,)
        collection = CampaignReviewCollection()
        collection.record_progression(recovered)
        return collection.result(CampaignDecision(
            decision="recover partial progression",
            motivation="the durable action did not start",
            evidence_ids=[recovered.action_id],
            bounded_actions=[recovered.action_id],
            next_review_condition="after the recovered worker starts",
            uncertainty="worker health is not observed yet",
        ))

    manager = AsyncMock()
    manager.review.side_effect = review
    projects = AsyncMock()
    projects.get.return_value = project
    executor = DecisionExecutor(
        AsyncMock(), campaign_control=runtime,
    )
    coordinator = ProjectCoordinator(
        projects=projects, bootstrap=AsyncMock(), discovery=AsyncMock(),
        manager=manager, decision_executor=executor, runtime=runtime,
        advisory_lock=_Lock(), clock=lambda: NOW,
    )

    trigger = run(coordinator.tick(project.id, snapshot))

    assert trigger is not None
    assert campaigns.create_progression.await_args.kwargs["action_id"] == recovered.action_id
    assert campaigns.create_progression.await_args.kwargs["configuration_asset_id"] == 41
    invocations.clone_variant.assert_awaited_once()
    containers.start_exact.assert_awaited_once_with(project, partial)
    campaigns.clear_progression_error.assert_awaited_once_with(recovered.action_id, partial.id)


def test_review_schedule_preserves_future_earlier_deadlines_but_advances_expired_ones() -> None:
    from backend.repositories.campaign_repository import CampaignRepository

    pool = AsyncMock()
    pool.fetchval.return_value = 2
    repository = CampaignRepository(pool)

    assert run(repository.schedule_next_reviews(
        7, NOW, "periodic campaign supervision",
    )) is True

    query = " ".join(pool.fetchval.await_args.args[0].split())
    assert "next_review_after <= CURRENT_TIMESTAMP THEN $2" in query
    assert "ELSE LEAST(next_review_after, $2)" in query
    assert "OR next_review_after <= CURRENT_TIMESTAMP THEN $3" in query
