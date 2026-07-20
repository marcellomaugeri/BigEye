from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock


NOW = datetime(2026, 7, 20, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


def test_build_services_creates_real_continuous_project_coordinator(tmp_path) -> None:
    from backend.agents.workflow import CampaignWorkflow
    from backend.api.dependencies import build_services
    from backend.services.campaigns.coordinator_registry import CoordinatorRegistry
    from backend.services.campaigns.decision_executor import DecisionExecutor
    from backend.services.campaigns.production_runtime import ProjectDiscovery, RepositoryCampaignRuntime
    from backend.services.campaigns.production_preparation import (
        CampaignTargetPreparation,
        DeferredTargetPreparationGraph,
    )
    from backend.services.campaigns.project_coordinator import ProjectCoordinator

    services = build_services(AsyncMock(), tmp_path)
    coordinator = services.recovery._coordinator_factory(7)

    assert isinstance(services.recovery, CoordinatorRegistry)
    assert isinstance(coordinator, ProjectCoordinator)
    assert coordinator._bootstrap is services.recovery._scheduler
    assert isinstance(coordinator._discovery, ProjectDiscovery)
    assert isinstance(coordinator._runtime, RepositoryCampaignRuntime)
    assert isinstance(coordinator.manager, CampaignWorkflow)
    assert isinstance(coordinator.decision_executor, DecisionExecutor)
    assert isinstance(
        coordinator.decision_executor._target_preparation, CampaignTargetPreparation,
    )
    assert isinstance(
        coordinator.decision_executor._target_preparation._preparation,
        DeferredTargetPreparationGraph,
    )
    assert coordinator.decision_executor._campaign_control is coordinator._runtime
    assert services.project_settings._coordinator_registry is services.recovery


def test_validated_prepared_target_is_published_and_started(tmp_path) -> None:
    from backend.agents.outputs.campaign_review import TargetProposalRecord
    from backend.agents.outputs.target_proposal import TargetProposal
    from backend.services.campaigns.production_preparation import CampaignTargetPreparation

    proposal = TargetProposal(
        target_name="parser", instance_type="system-level",
        byte_path="bytes to parser", expected_project_reach="src/parser.c",
        build_command="cmake --build build", run_command="/opt/bigeye/parser {input}",
        seeds=[{"path": "test.seed", "provenance": "repository"}],
        configuration="default", sanitizer_plan="address and undefined",
        generated_asset_intents=[], probe_assertions=["seed reaches project code"],
        evidence_ids=["source:parser"], uncertainty="probe required",
    )
    record = TargetProposalRecord(
        result_id="target_1", specialist="system", tool_call_id="call_1",
        attempt=1, model="gpt-5.6-luna", proposal=proposal,
    )
    prepared = SimpleNamespace(
        project_id=7, commit_sha="a" * 40,
        target_image_id="sha256:" + "b" * 64,
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        coverage_manifest=SimpleNamespace(labels={
            "bigeye.configuration-asset-id": "32",
            "bigeye.coverage-asset-id": "34",
        }),
        probe_invocations=(SimpleNamespace(role="seed", testcase_bytes=b"seed"),),
    )
    preparation = AsyncMock()
    preparation.prepare.return_value = prepared
    campaigns = AsyncMock()
    campaign = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        stopped_at=None,
    )
    campaigns.create.return_value = campaign
    invocations = AsyncMock()
    containers = AsyncMock()
    events = AsyncMock()
    service = CampaignTargetPreparation(
        preparation=preparation, campaigns=campaigns,
        invocation_store=invocations, containers=containers, events=events,
    )
    project = SimpleNamespace(id=7, commit_sha="a" * 40)

    result = run(service.prepare(project, record))

    campaigns.create.assert_awaited_once()
    assert campaigns.create.await_args.kwargs["configuration_purpose"] == "default"
    invocations.publish.assert_awaited_once()
    sanitizer_evidence = json.loads(
        invocations.publish.await_args.kwargs["configuration_files"]["sanitizer-intent.json"]
    )
    assert sanitizer_evidence["proposal_intent"] == "address and undefined"
    assert sanitizer_evidence["applied_primary"] == ["address", "undefined"]
    assert sanitizer_evidence["trusted_instructions"] is False
    containers.start_exact.assert_awaited_once_with(project, campaign)
    events.append.assert_awaited_once_with(7, "events", {"name": "campaigns"})
    assert result is campaign


def test_system_campaign_uses_file_mode_only_for_an_explicit_input_placeholder() -> None:
    from backend.agents.outputs.campaign_review import TargetProposalRecord
    from backend.agents.outputs.target_proposal import TargetProposal
    from backend.services.campaigns.production_preparation import CampaignTargetPreparation

    def record(run_command: str) -> TargetProposalRecord:
        proposal = TargetProposal(
            target_name="parser", instance_type="system-level",
            byte_path="bytes to parser", expected_project_reach="src/parser.c",
            build_command="cmake --build build", run_command=run_command,
            seeds=[{"path": "test.seed", "provenance": "repository"}],
            configuration="default", sanitizer_plan="address and undefined",
            generated_asset_intents=[], probe_assertions=["seed reaches project code"],
            evidence_ids=["source:parser"], uncertainty="probe required",
        )
        return TargetProposalRecord(
            result_id="target_1", specialist="system", tool_call_id="call_1",
            attempt=1, model="gpt-5.6-luna", proposal=proposal,
        )

    prepared = SimpleNamespace(target_image_id="sha256:" + "b" * 64)
    _, file_invocation = CampaignTargetPreparation._invocation(
        record("/opt/bigeye/parser {input}"), prepared,
    )
    _, stdin_invocation = CampaignTargetPreparation._invocation(
        record("/opt/bigeye/parser --stream"), prepared,
    )

    assert file_invocation.command[-1] == "@@"
    assert "@@" not in stdin_invocation.command


def test_campaign_run_command_rejects_noncontained_or_shell_argv() -> None:
    import pytest

    from backend.agents.outputs.campaign_review import TargetProposalRecord
    from backend.agents.outputs.target_proposal import TargetProposal
    from backend.services.campaigns.production_preparation import CampaignTargetPreparation

    def record(run_command: str) -> TargetProposalRecord:
        proposal = TargetProposal(
            target_name="parser", instance_type="system-level",
            byte_path="bytes to parser", expected_project_reach="src/parser.c",
            build_command="cmake --build build", run_command=run_command,
            seeds=[{"path": "test.seed", "provenance": "repository"}],
            configuration="default", sanitizer_plan="address and undefined",
            generated_asset_intents=[], probe_assertions=["seed reaches project code"],
            evidence_ids=["source:parser"], uncertainty="probe required",
        )
        return TargetProposalRecord(
            result_id="target_1", specialist="system", tool_call_id="call_1",
            attempt=1, model="gpt-5.6-luna", proposal=proposal,
        )

    prepared = SimpleNamespace(target_image_id="sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="/opt/bigeye"):
        CampaignTargetPreparation._invocation(record("/src/parser {input}"), prepared)
    with pytest.raises(ValueError, match="shell operators"):
        CampaignTargetPreparation._invocation(
            record("/opt/bigeye/parser {input} ; /opt/bigeye/other"), prepared,
        )


def test_runtime_reconciles_persisted_state_and_builds_real_agent_context(tmp_path) -> None:
    from backend.services.campaigns.production_runtime import (
        ContainerObservation,
        ProjectDiscovery,
        RepositoryCampaignRuntime,
    )

    repository = tmp_path / "projects/7/repository"
    repository.mkdir(parents=True)
    (repository / "CMakeLists.txt").write_text("add_library(parser parser.c)\n")
    (repository / "parser.c").write_text("int parse(const char *p) { return *p; }\n")
    value = SimpleNamespace(
        id=7, commit_sha="a" * 40, worker_count=2, paused_at=None, error=None,
    )
    tasks = AsyncMock()
    tasks.list_for_project.return_value = [
        SimpleNamespace(id=1, name="repository clone", finished_at=NOW, error=None),
        SimpleNamespace(id=2, name="LLVM toolchain preparation", finished_at=NOW, error=None),
        SimpleNamespace(id=3, name="repository analysis", finished_at=NOW, error=None),
    ]
    assets = AsyncMock()
    assets.list_for_project.return_value = []
    campaigns = AsyncMock()
    campaigns.list_for_project.return_value = []
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation()
    discovery = ProjectDiscovery(tmp_path)
    awaitable = discovery.discover(value)
    run(awaitable)
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=discovery, containers=containers,
    )

    snapshot = run(runtime.reconcile(value))
    context = run(runtime.review_context(value, snapshot))
    evidence = run(runtime.review_evidence(value, snapshot, SimpleNamespace(evidence_ids=snapshot.evidence_ids)))

    assert snapshot.initial_supervision_complete is True
    assert snapshot.free_slots == 2
    assert context.project_id == 7 and context.commit_sha == "a" * 40
    assert context.repository_root == repository.resolve()
    assert evidence and all(item["trusted_instructions"] is False for item in evidence)


def test_runtime_publishes_one_typed_current_progression_action(tmp_path) -> None:
    import pytest

    from backend.services.campaigns.production_runtime import (
        CampaignProgressObservation,
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=2)
    campaign = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, engine="afl", stopped_at=None,
        next_review_after=None, error=None,
    )
    progress_value = CampaignProgressObservation(
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
    campaigns.list_for_project.return_value = [campaign]
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation(
        active_campaign_ids=(9,), progress=(progress_value,),
    )
    discovery = SimpleNamespace(
        evidence=lambda _project_id: ({
            "evidence_id": "source:parser.c:8", "path": "parser.c",
            "excerpt": 'strcmp(input, "MAGIC")', "trusted_instructions": False,
        },),
    )
    contexts = AsyncMock()
    contexts.list_contexts_for_project.return_value = {}
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=discovery, containers=containers, campaign_contexts=contexts,
    )

    snapshot = run(runtime.reconcile(project))
    evidence = run(runtime.review_evidence(project, snapshot, None))
    recommendation = next(item for item in evidence if item.get("kind") == "campaign_progression")

    assert recommendation["action"] == "enable dictionary"
    assert snapshot.corpus_opportunity is True
    actions = runtime.progression_actions(7)
    assert len(actions) == 1
    assert actions[0].action_id == recommendation["evidence_id"]
    assert actions[0].dictionary_content == 'token_000="MAGIC"\n'


def test_progression_completion_is_scoped_to_the_same_target_lineage() -> None:
    from backend.services.campaigns.production_runtime import (
        CampaignProgressObservation,
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=2)
    campaigns_values = [
        SimpleNamespace(
            id=9, project_id=7, target_asset_id=31, engine="afl",
            stopped_at=None, next_review_after=None, error=None,
        ),
        SimpleNamespace(
            id=10, project_id=7, target_asset_id=41, engine="afl",
            stopped_at=None, next_review_after=None, error=None,
        ),
        SimpleNamespace(
            id=11, project_id=7, target_asset_id=31, engine="afl",
            stopped_at=NOW, next_review_after=None, error=None,
        ),
    ]
    tasks = AsyncMock()
    tasks.list_for_project.return_value = [
        SimpleNamespace(name="repository clone", finished_at=NOW, error=None),
        SimpleNamespace(name="LLVM toolchain preparation", finished_at=NOW, error=None),
    ]
    assets = AsyncMock()
    assets.list_for_project.return_value = []
    campaigns = AsyncMock()
    campaigns.list_for_project.return_value = campaigns_values
    progresses = tuple(
        CampaignProgressObservation(
            identifier, 1.0, NOW, 2, 0, f"progress:{identifier}",
            f"container-{identifier}", executions=100, executions_per_second=20.0,
        )
        for identifier in (9, 10)
    )
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation(
        active_campaign_ids=(9, 10), progress=progresses,
    )
    contexts = AsyncMock()
    contexts.list_contexts_for_project.return_value = {
        9: {"configuration_purpose": "default", "retirement_reason": None},
        10: {"configuration_purpose": "default", "retirement_reason": None},
        11: {"configuration_purpose": "enable dictionary", "retirement_reason": None},
    }
    discovery = SimpleNamespace(evidence=lambda _project_id: ({
        "evidence_id": "source:parser.c:8", "path": "parser.c",
        "excerpt": 'strcmp(input, "MAGIC")', "trusted_instructions": False,
    },))
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=discovery, containers=containers, campaign_contexts=contexts,
    )

    snapshot = run(runtime.reconcile(project))
    evidence = run(runtime.review_evidence(project, snapshot, None))
    actions = {
        item["campaign_id"]: item["action"]
        for item in evidence if item.get("kind") == "campaign_progression"
    }

    assert actions == {9: "enable CmpLog", 10: "enable dictionary"}


def test_deterministic_progression_action_starts_a_sibling_without_target_preparation() -> None:
    from backend.agents.outputs.campaign_decision import CampaignDecision
    from backend.agents.outputs.campaign_review import (
        CampaignReviewCollection,
        ProgressionActionRecord,
    )
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.decision_executor import DecisionExecutor
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=2)
    base = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", stopped_at=None, error=None,
    )
    sibling = SimpleNamespace(
        id=12, project_id=7, target_asset_id=31, configuration_asset_id=41,
        engine="afl", stopped_at=None, error=None,
    )
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
    campaigns = AsyncMock()
    campaigns.create_progression.return_value = sibling
    campaigns.get.return_value = base
    campaigns.get_progression.return_value = None
    campaigns.clear_progression_error.return_value = True
    progression_assets = AsyncMock()
    progression_assets.publish.return_value = SimpleNamespace(
        id=41, project_id=7, parent_id=32, validated_at=NOW, error=None,
    )
    clone_variant = AsyncMock()
    invocations = SimpleNamespace(
        load=lambda *_args: invocation,
        clone_variant=clone_variant,
    )
    containers = AsyncMock()
    runtime = RepositoryCampaignRuntime(
        tasks=AsyncMock(), assets=AsyncMock(), campaigns=campaigns,
        discovery=SimpleNamespace(context=lambda _project_id: SimpleNamespace(project_id=7)),
        containers=containers, invocations=invocations,
        progression_assets=progression_assets,
    )
    runtime._persisted_campaigns[7] = (base,)
    action = ProgressionActionRecord(
        action_id="campaign-progression:7:9:abcd1234abcd1234",
        project_id=7, base_campaign_id=9, target_asset_id=31,
        action_name="enable dictionary",
        evidence_ids=("source:parser.c:8",),
        dictionary_content='token_000="MAGIC"\n',
    )
    collection = CampaignReviewCollection()
    collection.record_progression(action)
    review = collection.result(CampaignDecision(
        decision="add dictionary sibling", motivation="comparison evidence",
        evidence_ids=[action.action_id], bounded_actions=[action.action_id],
        next_review_condition="after sibling health probe", uncertainty="coverage delta unknown",
    ))
    target_preparation = AsyncMock()
    executor = DecisionExecutor(target_preparation, campaign_control=runtime)

    results = run(executor.execute(project, review))

    assert results[0].succeeded is True
    target_preparation.prepare.assert_not_awaited()
    campaigns.create_progression.assert_awaited_once()
    assert campaigns.create_progression.await_args.kwargs["target_asset_id"] == 31
    assert campaigns.create_progression.await_args.kwargs["configuration_asset_id"] == 41
    clone_variant.assert_awaited_once()
    clone = clone_variant.await_args
    assert clone.args[:3] == (7, 9, 12)
    assert clone.kwargs["configuration_files"] == {
        "tokens.dict": b'token_000="MAGIC"\n',
    }
    containers.start_exact.assert_awaited_once_with(project, sibling)


def test_configuration_progression_never_splits_an_input_option_from_its_placeholder() -> None:
    from backend.agents.outputs.campaign_review import ProgressionActionRecord
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=2)
    base = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", stopped_at=None, error=None,
    )
    sibling = SimpleNamespace(
        id=12, project_id=7, target_asset_id=31, configuration_asset_id=41,
        engine="afl", stopped_at=None, error=None,
    )
    invocation = ContainerInvocation(
        engine="afl", image_id="sha256:" + "b" * 64,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--",
            "/opt/bigeye/parser", "--file", "@@",
        ],
        environment={"AFL_NO_UI": "1"}, campaign_labels={},
        network_disabled=True, read_only_source=True,
        timeout_ms=1_000, memory_limit_mb=1_024,
    )
    campaigns = AsyncMock()
    campaigns.get.return_value = base
    campaigns.create_progression.return_value = sibling
    campaigns.get_progression.return_value = None
    campaigns.clear_progression_error.return_value = True
    progression_assets = AsyncMock()
    progression_assets.publish.return_value = SimpleNamespace(
        id=41, project_id=7, parent_id=32, validated_at=NOW, error=None,
    )
    clone_variant = AsyncMock()
    invocations = SimpleNamespace(
        load=lambda *_args: invocation, clone_variant=clone_variant,
    )
    runtime = RepositoryCampaignRuntime(
        tasks=AsyncMock(), assets=AsyncMock(), campaigns=campaigns,
        discovery=SimpleNamespace(context=lambda _project_id: SimpleNamespace(project_id=7)),
        containers=AsyncMock(), invocations=invocations,
        progression_assets=progression_assets,
    )
    action = ProgressionActionRecord(
        action_id="campaign-progression:7:9:abcd1234abcd1234",
        project_id=7, base_campaign_id=9, target_asset_id=31,
        action_name="try configuration", evidence_ids=("docs:README:42",),
        arguments=("--encrypt",), detail="--encrypt",
    )

    run(runtime.progress(project, action))

    variant = clone_variant.await_args.args[3]
    assert variant.command[-4:] == [
        "/opt/bigeye/parser", "--file", "@@", "--encrypt",
    ]
    assert clone_variant.await_args.kwargs["coverage_arguments"] == ("--encrypt",)
    assert clone_variant.await_args.kwargs["configuration_asset_id"] == 41


def test_retirement_is_a_known_typed_action_and_executes_only_after_selection() -> None:
    from backend.agents.outputs.campaign_decision import CampaignDecision
    from backend.agents.outputs.campaign_review import CampaignReviewCollection, RetirementActionRecord
    from backend.services.campaigns.decision_executor import DecisionExecutor

    record = RetirementActionRecord(
        action_id="retirement:7:9:90:4:40",
        project_id=7,
        campaign_id=9,
        strategy_asset_id=90,
        retained_campaign_id=4,
        retained_strategy_asset_id=40,
        evidence_ids=("candidate:1", "retained:1", "candidate:2", "retained:2"),
        reason="clean coverage remained a subset for two consecutive checkpoints",
        reversible=True,
    )
    collection = CampaignReviewCollection()
    collection.record_retirement(record)
    decision = CampaignDecision(
        decision="retire redundant strategy",
        motivation="two clean checkpoints prove a reversible subset",
        evidence_ids=[record.action_id],
        bounded_actions=[record.action_id],
        next_review_condition="after retained campaign checkpoint",
        uncertainty="future coverage may diverge",
    )
    review = collection.result(decision)
    campaign_control = AsyncMock()
    executor = DecisionExecutor(AsyncMock(), campaign_control=campaign_control)
    project = SimpleNamespace(id=7)

    results = run(executor.execute(project, review))

    campaign_control.retire.assert_awaited_once_with(project, record)
    assert results[0].succeeded is True
    assert review.known_action_ids == review.selected_action_ids == (record.action_id,)


def test_runtime_retirement_stops_only_the_exact_selected_campaign_identity() -> None:
    from backend.agents.outputs.campaign_review import RetirementActionRecord
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    selected = SimpleNamespace(
        id=9, project_id=7, target_asset_id=90, configuration_asset_id=None,
        stopped_at=None,
    )
    retained = SimpleNamespace(
        id=4, project_id=7, target_asset_id=40, configuration_asset_id=None,
        stopped_at=None,
    )
    campaigns = AsyncMock()
    campaigns.get.side_effect = [selected, retained]
    campaigns.stop_redundant.return_value = True
    containers = AsyncMock()
    events = AsyncMock()
    runtime = RepositoryCampaignRuntime(
        tasks=AsyncMock(), assets=AsyncMock(), campaigns=campaigns,
        discovery=AsyncMock(), containers=containers, events=events,
    )
    record = RetirementActionRecord(
        action_id="retirement:7:9:90:4:40", project_id=7, campaign_id=9,
        strategy_asset_id=90, retained_campaign_id=4,
        retained_strategy_asset_id=40,
        evidence_ids=("checkpoint:1", "checkpoint:2"),
        reason="clean subset at two checkpoints", reversible=True,
    )

    result = run(runtime.retire(project, record))

    containers.stop_exact.assert_awaited_once_with(project, selected)
    campaigns.stop_redundant.assert_awaited_once_with(
        project_id=7, campaign_id=9, strategy_asset_id=90,
        retained_campaign_id=4, retained_strategy_asset_id=40,
        retirement_reason="clean subset at two checkpoints",
    )
    events.append.assert_awaited_once_with(7, "events", {"name": "campaigns"})
    assert result == record.action_id


def test_runtime_retirement_rejects_changed_strategy_before_container_control() -> None:
    import pytest

    from backend.agents.outputs.campaign_review import RetirementActionRecord
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    campaigns = AsyncMock()
    campaigns.get.side_effect = [
        SimpleNamespace(id=9, project_id=7, target_asset_id=91, configuration_asset_id=None, stopped_at=None),
        SimpleNamespace(id=4, project_id=7, target_asset_id=40, configuration_asset_id=None, stopped_at=None),
    ]
    containers = AsyncMock()
    runtime = RepositoryCampaignRuntime(
        tasks=AsyncMock(), assets=AsyncMock(), campaigns=campaigns,
        discovery=AsyncMock(), containers=containers,
    )
    record = RetirementActionRecord(
        action_id="retirement:7:9:90:4:40", project_id=7, campaign_id=9,
        strategy_asset_id=90, retained_campaign_id=4,
        retained_strategy_asset_id=40,
        evidence_ids=("checkpoint:1", "checkpoint:2"),
        reason="clean subset at two checkpoints", reversible=True,
    )

    with pytest.raises(ValueError, match="strategy"):
        run(runtime.retire(project, record))
    containers.stop_exact.assert_not_awaited()


def test_unchanged_reconciliation_does_not_emit_campaign_invalidation() -> None:
    from backend.services.campaigns.production_runtime import (
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, worker_count=2)
    tasks = AsyncMock()
    tasks.list_for_project.return_value = []
    assets = AsyncMock()
    assets.list_for_project.return_value = []
    campaigns = AsyncMock()
    campaigns.list_for_project.return_value = []
    discovery = SimpleNamespace(evidence=lambda _project_id: ())
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation()
    events = AsyncMock()
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=discovery, containers=containers, events=events,
    )

    run(runtime.reconcile(project))
    run(runtime.reconcile(project))

    events.append.assert_not_awaited()


def test_missing_worker_is_unhealthy_but_does_not_consume_a_worker_slot() -> None:
    from backend.services.campaigns.production_runtime import (
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=1)
    campaign = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        stopped_at=None, next_review_after=None, error=None,
    )
    tasks, assets, campaigns = AsyncMock(), AsyncMock(), AsyncMock()
    tasks.list_for_project.return_value = []
    assets.list_for_project.return_value = []
    campaigns.list_for_project.return_value = [campaign]
    campaigns.record_heartbeat.return_value = False
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation((), (9,), (), ())
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=SimpleNamespace(evidence=lambda _project_id: ()), containers=containers,
    )

    snapshot = run(runtime.reconcile(project))

    assert snapshot.active_workers == 0
    assert snapshot.free_slots == 1
    assert snapshot.unhealthy_worker is True


def test_worker_limit_stops_and_durably_retires_lowest_investment_campaigns() -> None:
    from backend.services.campaigns.production_runtime import (
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=1)
    values = [
        SimpleNamespace(id=9, project_id=7, stopped_at=None, cpu_seconds=100.0, error=None),
        SimpleNamespace(id=10, project_id=7, stopped_at=None, cpu_seconds=2.0, error=None),
        SimpleNamespace(id=11, project_id=7, stopped_at=None, cpu_seconds=2.0, error=None),
    ]
    campaigns = AsyncMock()
    campaigns.list_for_project.return_value = values
    campaigns.stop_for_worker_limit.return_value = True
    containers = AsyncMock()
    runtime = RepositoryCampaignRuntime(
        tasks=None, assets=None, campaigns=campaigns, discovery=None, containers=containers,
    )
    runtime._observations[7] = ContainerObservation((9, 10, 11), (), (), ())

    run(runtime.enforce_worker_count(project, 2))

    assert [call.args[1].id for call in containers.stop_exact.await_args_list] == [11, 10]
    assert [call.args[1] for call in campaigns.stop_for_worker_limit.await_args_list] == [11, 10]
    assert all(call.args[0] == 7 for call in campaigns.stop_for_worker_limit.await_args_list)


def test_campaign_project_read_uses_a_hard_sql_sentinel_limit() -> None:
    import pytest

    from backend.repositories.campaign_repository import CampaignRepository

    pool = AsyncMock()
    pool.fetch.return_value = [object()] * 257

    with pytest.raises(OverflowError, match="campaign read limit"):
        run(CampaignRepository(pool).list_for_project(7))
    query, project_id, sentinel = pool.fetch.await_args.args
    assert "LIMIT $2" in query
    assert (project_id, sentinel) == (7, 257)


def test_runtime_accounts_observed_cpu_and_analyzes_persisted_histories() -> None:
    from backend.fuzzing.coverage.exposure import ReachedLine
    from backend.fuzzing.coverage.overlap import RetirementCandidate
    from backend.services.campaigns.production_runtime import (
        CampaignProgressObservation,
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=1)
    campaign = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", stopped_at=None, next_review_after=NOW, cpu_seconds=5.0, error=None,
    )
    tasks, assets, campaigns = AsyncMock(), AsyncMock(), AsyncMock()
    tasks.list_for_project.return_value = []
    assets.list_for_project.return_value = [
        SimpleNamespace(id=31, content_hash="1" * 64, validated_at=NOW, error=None),
        SimpleNamespace(id=32, content_hash="2" * 64, validated_at=NOW, error=None),
    ]
    campaigns.list_for_project.return_value = [campaign]
    progress = CampaignProgressObservation(
        campaign_id=9, cpu_seconds=20.0, heartbeat_at=NOW,
        queue_files=3, crash_files=0, evidence_id="campaign-progress:9:exact",
        container_id="container-9",
    )
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation(
        (9,), (), ({"evidence_id": progress.evidence_id, "trusted_instructions": False},),
        (progress,),
    )
    coverage_history = AsyncMock()
    reached = (ReachedLine("src/a.c", 10, "parse"),)
    coverage_history.reached_lines.return_value = (32, reached)
    coverage_history.histories.return_value = ("persisted-history",)
    retirement = RetirementCandidate(
        project_id=7, campaign_id=9, strategy_asset_id=32,
        retained_campaign_id=4, retained_strategy_asset_id=40,
        evidence_ids=("checkpoint:1", "checkpoint:2"),
        reason="clean subset", reversible=True,
    )
    exposure, overlap = AsyncMock(), MagicMock()
    overlap.compare.return_value = [retirement]
    from backend.fuzzing.engines.contracts import ContainerInvocation
    invocation = ContainerInvocation(
        engine="afl", image_id="sha256:" + "b" * 64,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--",
            "/opt/bigeye/parser", "@@",
        ],
        environment={
            "AFL_NO_UI": "1", "ASAN_OPTIONS": "abort_on_error=1:symbolize=0",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        },
        campaign_labels={}, network_disabled=True, read_only_source=True,
        timeout_ms=1000, memory_limit_mb=1024,
    )
    invocations = SimpleNamespace(load=lambda *_args: invocation)
    crash_groups = AsyncMock()
    crash_groups.groups_for_campaign.return_value = ("f" * 64,)
    campaign_contexts = AsyncMock()
    campaign_contexts.list_contexts_for_project.return_value = {
        9: {"configuration_purpose": "encrypted protocol", "retirement_reason": None},
    }
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=SimpleNamespace(evidence=lambda _project_id: ()), containers=containers,
        exposure=exposure, coverage_history=coverage_history,
        overlap=overlap, invocations=invocations,
        crash_groups=crash_groups, campaign_contexts=campaign_contexts,
    )

    snapshot = run(runtime.reconcile(project))
    run(runtime.apply_cpu_checkpoint(project, snapshot))
    result = run(runtime.retirement_candidates(project, snapshot))

    assert progress.evidence_id in snapshot.evidence_ids
    assert "campaign-context:7:9" in snapshot.evidence_ids
    exposure.apply.assert_awaited_once_with(9, 20.0, reached)
    coverage_history.append.assert_awaited_once()
    assert coverage_history.append.await_args.kwargs["strategy_asset_id"] == 32
    assert len(coverage_history.append.await_args.kwargs["compatibility_group_id"]) == 64
    assert coverage_history.append.await_args.kwargs["crash_group_ids"] == ("f" * 64,)
    assert coverage_history.append.await_args.kwargs["configuration_purpose"] == "encrypted protocol"
    overlap.compare.assert_called_once_with(("persisted-history",))
    assert result == (retirement,)


def test_compatibility_identity_includes_exact_immutable_fuzz_image() -> None:
    from dataclasses import replace

    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    invocation = ContainerInvocation(
        engine="libfuzzer", image_id="sha256:" + "a" * 64,
        command=["/opt/bigeye/harness", "/campaign/corpus", "-artifact_prefix=/campaign/output/", "-timeout=1", "-rss_limit_mb=1024"],
        environment={}, campaign_labels={}, network_disabled=True, read_only_source=True,
        timeout_ms=1000, memory_limit_mb=1024,
    )
    project = SimpleNamespace(id=7, commit_sha="b" * 40)
    campaign = SimpleNamespace(target_asset_id=31, configuration_asset_id=32)
    assets = {
        31: SimpleNamespace(content_hash="1" * 64, validated_at=NOW, error=None),
        32: SimpleNamespace(content_hash="2" * 64, validated_at=NOW, error=None),
    }

    first = RepositoryCampaignRuntime._compatibility_group(project, campaign, assets, invocation)
    second = RepositoryCampaignRuntime._compatibility_group(
        project, campaign, assets, replace(invocation, image_id="sha256:" + "c" * 64),
    )

    assert first != second


def test_dependency_script_is_a_reusable_project_layer_boundary(tmp_path) -> None:
    from backend.fuzzing.campaigns.production_factory import NormalBuildPreparation

    root = tmp_path / "projects/7"
    (root / "repository").mkdir(parents=True)
    drafts = root / "assets-drafts"
    drafts.mkdir()
    dependency = drafts / "dependencies.sh"
    dependency.write_text("#!/bin/sh\nset -eu\ncmake -S /src -B /opt/bigeye/build\n")
    context = SimpleNamespace(generated_assets_root=drafts, repository_root=root / "repository")
    discovery = SimpleNamespace(context=lambda _project_id: context)
    store = AsyncMock()
    dependency_asset = SimpleNamespace(id=10)
    store.create_reusable.return_value = dependency_asset
    repository_layers, project_layers = MagicMock(), MagicMock()
    repository_layers.prepare.return_value = "repository-layer"
    project_layers.prepare.return_value = "project-layer"
    proposal = SimpleNamespace(generated_asset_intents=[SimpleNamespace(
        relative_path="dependencies.sh", purpose="project dependency installation",
    )])
    service = NormalBuildPreparation(
        discovery=discovery, asset_store=store, repository_layers=repository_layers,
        project_layers=project_layers, toolchain_tag="toolchain", sink=lambda _text: None,
    )

    result = run(service.validate(SimpleNamespace(id=7, commit_sha="a" * 40), proposal))

    store.create_reusable.assert_awaited_once()
    assert store.create_reusable.await_args.args[2] == "project-dependencies.sh"
    assert store.create_reusable.await_args.args[3]["project-dependencies.sh"] == dependency
    project_layers.prepare.assert_called_once()
    assert result == "project-layer"


def test_missing_dependency_command_is_an_explicit_noop_not_fake_compilation(tmp_path) -> None:
    from backend.fuzzing.campaigns.production_factory import NormalBuildPreparation

    root = tmp_path / "projects/7"
    (root / "repository").mkdir(parents=True)
    drafts = root / "assets-drafts"
    drafts.mkdir()
    context = SimpleNamespace(generated_assets_root=drafts, repository_root=root / "repository")
    store = AsyncMock()
    store.create_reusable.return_value = SimpleNamespace(id=10)
    repository_layers, project_layers = MagicMock(), MagicMock()
    repository_layers.prepare.return_value = "repository-layer"
    project_layers.prepare.return_value = "project-layer"
    service = NormalBuildPreparation(
        discovery=SimpleNamespace(context=lambda _project_id: context), asset_store=store,
        repository_layers=repository_layers, project_layers=project_layers,
        toolchain_tag="toolchain", sink=lambda _text: None,
    )

    run(service.validate(
        SimpleNamespace(id=7, commit_sha="a" * 40),
        SimpleNamespace(generated_asset_intents=[]),
    ))

    source = store.create_reusable.await_args.args[3]["project-dependencies.sh"]
    text = source.read_text()
    assert "intentionally has no project dependency command" in text
    assert "cmake" not in text and "make" not in text


def test_production_factory_wires_one_bounded_terra_asset_repair(tmp_path) -> None:
    from backend.agents.target_repair import TargetRepairAgent
    from backend.fuzzing.campaigns.production_factory import ProductionTargetPreparationFactory

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM debian:bookworm\n")
    factory = ProductionTargetPreparationFactory(
        workspace=tmp_path,
        discovery=SimpleNamespace(),
        assets=AsyncMock(),
        dockerfile=dockerfile,
    )
    client = MagicMock()
    client.api.inspect_image.return_value = {
        "Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": "amd64",
    }
    service = factory(client)

    assert isinstance(service._repairer, TargetRepairAgent)


def test_production_onboarding_uses_repository_layer_not_standalone_analysis(tmp_path) -> None:
    from backend.services.execute_project_backbone import ExecuteProjectBackbone
    from backend.services.initial_tasks import InitialTaskService

    order = []
    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    projects = AsyncMock()
    projects.get.return_value = project
    tasks = AsyncMock()
    records = [
        SimpleNamespace(id=1, project_id=7, name="repository clone", finished_at=None, error=None),
        SimpleNamespace(id=2, project_id=7, name="LLVM toolchain preparation", finished_at=None, error=None),
        SimpleNamespace(id=3, project_id=7, name="repository layer", finished_at=None, error=None),
    ]
    tasks.list_for_project.return_value = records

    class Clone:
        async def clone(self, _project, _task): order.append("clone")

    class Toolchain:
        async def prepare(self, _task): order.append("toolchain")

    class RepositoryLayer:
        async def prepare(self, _project, _task):
            assert "clone" in order and "toolchain" in order
            order.append("repository-layer")

    analysis = AsyncMock()
    service = ExecuteProjectBackbone(
        projects, tasks, Clone(), Toolchain(), analysis, AsyncMock(), tmp_path,
        repository_layer=RepositoryLayer(),
    )

    run(service.schedule(7))

    assert InitialTaskService(repository_analysis=False).names() == [
        "repository clone", "LLVM toolchain preparation", "repository layer",
    ]
    assert order[-1] == "repository-layer"
    analysis.analyse.assert_not_awaited()


def test_concrete_monitor_reads_cpu_queue_and_crash_facts_into_typed_evidence(tmp_path) -> None:
    from backend.services.campaigns.production_runtime import DockerCampaignMonitor

    output = tmp_path / "projects/7/campaigns/9/output/main"
    (output / "queue").mkdir(parents=True)
    (output / "crashes").mkdir()
    (output / "queue/id:000001").write_bytes(b"seed")
    (output / "crashes/id:000002").write_bytes(b"crash")
    container = SimpleNamespace(stats=lambda stream=False: {
        "cpu_stats": {"cpu_usage": {"total_usage": 3_500_000_000}},
    })
    client = SimpleNamespace(containers=SimpleNamespace(get=lambda _identity: container))

    observed = DockerCampaignMonitor(tmp_path, clock=lambda: NOW).observe(
        client,
        SimpleNamespace(id=7),
        SimpleNamespace(id=9),
        SimpleNamespace(container_id="container-9"),
        SimpleNamespace(engine="afl"),
    )

    assert observed.cpu_seconds == 3.5
    assert observed.queue_files == 1
    assert observed.crash_files == 1
    assert observed.evidence_id.startswith("campaign-progress:9:")


def test_terra_repair_edits_exactly_one_isolated_existing_draft(tmp_path) -> None:
    from backend.agents.context import AgentContext
    from backend.agents.outputs.target_proposal import TargetProposal
    from backend.agents.target_repair import TargetRepairAgent
    from backend.agents.tools.generated_assets import read_asset_file, write_asset_file
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever

    repository = tmp_path / "projects/7/repository"
    repository.mkdir(parents=True)
    (repository / "parser.c").write_text("int parse(void) { return 0; }\n")
    drafts = tmp_path / "projects/7/drafts"
    context = AgentContext(7, "a" * 40, repository, drafts, EvidenceRetriever(repository))
    write_asset_file(context, "harness.cc", "int broken;\n", None)
    proposal = TargetProposal(
        target_name="parser", instance_type="component-level",
        byte_path="bytes to parser", expected_project_reach="parser.c",
        build_command="clang++ harness.cc", run_command="/opt/bigeye/parser {input}",
        seeds=[{"path": "parser.c", "provenance": "repository"}],
        configuration="default", sanitizer_plan="address and undefined",
        generated_asset_intents=[{
            "relative_path": "harness.cc", "purpose": "component harness",
        }],
        probe_assertions=["seed reaches parser"], evidence_ids=["source:parser"],
        uncertainty="probe required",
    )

    async def runner(_agent, _prompt, *, context, **_kwargs):
        record = read_asset_file(context, "harness.cc")
        write_asset_file(context, "harness.cc", "int repaired;\n", record["sha256"])
        return SimpleNamespace(final_output=proposal)

    repairer = TargetRepairAgent(
        SimpleNamespace(context=lambda _project_id: context), runner=runner,
    )
    result = run(repairer.repair(
        SimpleNamespace(id=7, commit_sha="a" * 40), proposal,
        ValueError("deterministic compile failure"), "gpt-5.6-terra",
    ))

    assert result.model == "gpt-5.6-terra"
    assert read_asset_file(context, "harness.cc")["content"] == "int repaired;\n"
    assert not tuple((tmp_path / "projects/7").glob("repair-sandbox-*"))


def test_target_planner_rejects_agent_authored_dockerfile_parent(tmp_path) -> None:
    import pytest

    from backend.agents.context import AgentContext
    from backend.agents.outputs.target_proposal import TargetProposal
    from backend.agents.tools.generated_assets import write_asset_file
    from backend.fuzzing.campaigns.production_factory import ProposalPreparationPlanner
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever

    repository = tmp_path / "projects/7/repository"
    repository.mkdir(parents=True)
    (repository / "seed").write_bytes(b"seed")
    context = AgentContext(
        7, "a" * 40, repository, tmp_path / "projects/7/drafts",
        EvidenceRetriever(repository),
    )
    write_asset_file(context, "Dockerfile", "FROM unknown-parent:latest\n", None)
    proposal = TargetProposal(
        target_name="parser", instance_type="system-level", byte_path="stdin",
        expected_project_reach="parser", build_command="true",
        run_command="/opt/bigeye/parser", seeds=[{
            "path": "seed", "provenance": "repository",
        }], configuration="default", sanitizer_plan="address and undefined",
        generated_asset_intents=[{
            "relative_path": "Dockerfile", "purpose": "target build",
        }], probe_assertions=["seed reaches parser"], evidence_ids=["source:parser"],
        uncertainty="probe required",
    )
    planner = ProposalPreparationPlanner(
        discovery=SimpleNamespace(context=lambda _project_id: context),
        asset_store=AsyncMock(),
    )

    with pytest.raises(ValueError, match="owns generated layer Dockerfiles"):
        run(planner.plan(SimpleNamespace(id=7), proposal))


def test_retirement_action_identity_and_evidence_are_self_validating() -> None:
    import pytest

    from backend.agents.outputs.campaign_review import RetirementActionRecord

    values = {
        "action_id": "retirement:7:9:90:4:40", "project_id": 7,
        "campaign_id": 9, "strategy_asset_id": 90,
        "retained_campaign_id": 4, "retained_strategy_asset_id": 40,
        "evidence_ids": ("checkpoint:1", "checkpoint:2"),
        "reason": "clean subset at two checkpoints", "reversible": True,
    }
    RetirementActionRecord(**values)
    with pytest.raises(ValueError, match="identity"):
        RetirementActionRecord(**{**values, "action_id": "retirement:9:90:4:40"})
    with pytest.raises(ValueError, match="evidence"):
        RetirementActionRecord(**{**values, "evidence_ids": ("same", "same")})
    with pytest.raises(ValueError, match="reversible"):
        RetirementActionRecord(**{**values, "reversible": False})


def test_campaign_manager_can_select_prevalidated_retirement_action(tmp_path) -> None:
    from backend.agents.context import AgentContext
    from backend.agents.manager import CampaignManager
    from backend.agents.outputs.campaign_decision import CampaignDecision
    from backend.agents.outputs.campaign_review import RetirementActionRecord
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "main.c").write_text("int main(void) { return 0; }\n")
    record = RetirementActionRecord(
        action_id="retirement:7:9:90:4:40", project_id=7, campaign_id=9,
        strategy_asset_id=90, retained_campaign_id=4, retained_strategy_asset_id=40,
        evidence_ids=("checkpoint:1", "checkpoint:2"),
        reason="clean subset at two checkpoints", reversible=True,
    )

    async def runner(_agent, _prompt, **_kwargs):
        return SimpleNamespace(
            final_output=CampaignDecision(
                decision="retire redundant strategy", motivation="validated subset",
                evidence_ids=[record.action_id], bounded_actions=[record.action_id],
                next_review_condition="after another checkpoint", uncertainty="may diverge later",
            ),
            raw_responses=[], new_items=[],
        )

    context = AgentContext(
        7, "a" * 40, repository, tmp_path / "assets", EvidenceRetriever(repository),
    )
    review = run(CampaignManager(runner=runner).review(
        context,
        [{"evidence_id": record.action_id, "trusted_instructions": False}],
        "overlap retirement candidate",
        prepared_actions=(record,),
    ))

    assert review.selected_retirement_actions == (record,)
