"""Selected worker requests execute only through deterministic pipeline services."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError


def run(awaitable):
    return asyncio.run(awaitable)


def record(operation: str = "build", *, asset_paths=()):
    from backend.agents.outputs.campaign_review import (
        PipelineArtifactSnapshot,
        PipelineCampaignSnapshot,
        PipelineOperationRecord,
        _record_id,
    )

    values = dict(
        project_id=7,
        project_commit_sha="a" * 40,
        operation=operation,
        asset_paths=asset_paths,
        draft_sha256s=tuple((path, "b" * 64) for path in asset_paths),
        assertions=("seed reaches parser project code",),
        worker_tool_call_id="call-parser",
        evidence_ids=("source:parser.c:42",),
        target_proposal=_proposal_record() if operation in {"build", "probe"} else None,
        campaign_snapshot=(
            PipelineCampaignSnapshot(
                operation=operation, campaign_id=9, target_asset_id=31,
                configuration_asset_id=32, progress_evidence_id="progress:9",
                artifacts=(PipelineArtifactSnapshot(
                    kind="crash" if operation == "replay" else "corpus",
                    relative_path="output/input", content_sha256="c" * 64,
                    size_bytes=4,
                ),),
            ) if operation in {"replay", "coverage"} else None
        ),
    )
    canonical = {
        **values,
        "target_proposal": values["target_proposal"].model_dump(mode="json")
        if values["target_proposal"] else None,
        "campaign_snapshot": values["campaign_snapshot"].model_dump(mode="json")
        if values["campaign_snapshot"] else None,
    }
    return PipelineOperationRecord(
        action_id=_record_id("pipeline", canonical),
        **values,
    )


def test_pipeline_record_uses_plain_validated_operation_strings() -> None:
    selected = record("probe")

    assert selected.operation == "probe"
    assert set(type(selected).model_fields) == {
        "action_id", "project_id", "project_commit_sha", "operation", "asset_paths",
        "draft_sha256s", "assertions", "worker_tool_call_id", "evidence_ids",
        "target_proposal", "campaign_snapshot",
    }
    with pytest.raises(ValidationError, match="operation"):
        record("shell")


def test_manager_selection_promotes_an_inert_worker_request_to_one_stable_action() -> None:
    from backend.agents.outputs.campaign_decision import CampaignDecision
    from backend.agents.outputs.campaign_review import CampaignReviewCollection, WorkerInvocation

    collection = CampaignReviewCollection()
    invocation = WorkerInvocation("prepare parser", "call-parser", 1, "gpt-5.6-luna")
    request = {
        "project_id": 7,
        "operation": "probe",
        "asset_paths": ["targets/parser/harness.c"],
        "assertions": ["seed reaches parser project code"],
        "executed": False,
        "provenance": "agent_request",
        "trusted_instructions": False,
    }
    audit = collection.record_operation(
        invocation, request, project_commit_sha="a" * 40,
        draft_sha256s=(("targets/parser/harness.c", "b" * 64),),
        evidence_ids=("source:parser.c:42",),
    )
    proposal = collection.record_worker_outcome(invocation, _proposal_record().proposal)
    collection.complete_attempt(invocation, accepted=True)
    action_id = collection.pipeline_action_id(audit.request_id)

    review = collection.result(CampaignDecision(
        decision="probe parser", motivation="the draft is ready",
        evidence_ids=["source:parser.c:42"], bounded_actions=[action_id],
        next_review_delay_seconds=120,
        next_review_reason="inspect deterministic probe evidence",
        uncertainty="the probe has not run",
    ))

    assert review.selected_pipeline_operations == review.known_pipeline_operations
    assert review.selected_pipeline_operations[0].action_id == action_id
    assert review.known_operation_requests[0].executed is False
    assert proposal.result_id not in collection.actionable_ids()
    assert action_id in collection.actionable_ids()
    assert review.known_target_proposals == ()
    assert review.known_action_ids == (action_id,)

    with pytest.raises(ValueError, match="outside this review"):
        collection.result(CampaignDecision(
            decision="bypass immutable action", motivation="select raw proposal",
            evidence_ids=["source:parser.c:42"], bounded_actions=[proposal.result_id],
            next_review_delay_seconds=120,
            next_review_reason="inspect deterministic probe evidence",
            uncertainty="the probe has not run",
        ))


@pytest.mark.parametrize(
    ("proposal_paths", "request_paths"),
    [
        (("targets/parser/harness.c",), ()),
        (("targets/parser/harness.c", "targets/parser/config.sh"),
         ("targets/parser/harness.c",)),
        (("targets/parser/harness.c",),
         ("targets/parser/harness.c", "targets/parser/extra.sh")),
    ],
    ids=("empty", "subset", "extra"),
)
def test_pipeline_promotion_rejects_incomplete_or_extra_generated_path_snapshots(
    proposal_paths, request_paths,
) -> None:
    from backend.agents.outputs.campaign_review import CampaignReviewCollection, WorkerInvocation
    from backend.agents.outputs.target_proposal import TargetProposal

    collection = CampaignReviewCollection()
    invocation = WorkerInvocation("prepare parser", "call-parser", 1, "gpt-5.6-luna")
    proposal_values = _proposal_record().proposal.model_dump(mode="json")
    proposal_values["generated_asset_intents"] = [
        {"relative_path": path, "purpose": "target preparation"}
        for path in proposal_paths
    ]
    proposal = TargetProposal.model_validate(proposal_values)
    collection.record_operation(
        invocation,
        {
            "project_id": 7, "operation": "probe", "asset_paths": list(request_paths),
            "assertions": ["seed reaches parser project code"], "executed": False,
            "provenance": "agent_request", "trusted_instructions": False,
        },
        project_commit_sha="a" * 40,
        draft_sha256s=tuple((path, "b" * 64) for path in request_paths),
        evidence_ids=("source:parser.c:42",),
    )
    collection.record_worker_outcome(invocation, proposal)

    with pytest.raises(ValueError, match="exact target proposal"):
        collection.complete_attempt(invocation, accepted=True)


def test_one_build_or_probe_is_valid_but_both_for_one_proposal_are_rejected() -> None:
    from backend.agents.outputs.campaign_review import CampaignReviewCollection, WorkerInvocation

    invocation = WorkerInvocation("prepare parser", "call-parser", 1, "gpt-5.6-luna")

    def add_request(collection, operation):
        return collection.record_operation(
            invocation,
            {
                "project_id": 7, "operation": operation,
                "asset_paths": ["targets/parser/harness.c"],
                "assertions": ["seed reaches parser project code"], "executed": False,
                "provenance": "agent_request", "trusted_instructions": False,
            },
            project_commit_sha="a" * 40,
            draft_sha256s=(("targets/parser/harness.c", "b" * 64),),
            evidence_ids=("source:parser.c:42",),
        )

    for operation in ("build", "probe"):
        collection = CampaignReviewCollection()
        request = add_request(collection, operation)
        collection.record_worker_outcome(invocation, _proposal_record().proposal)
        collection.complete_attempt(invocation, accepted=True)
        assert collection.actionable_ids() == frozenset({
            collection.pipeline_action_id(request.request_id),
        })

    ambiguous = CampaignReviewCollection()
    add_request(ambiguous, "build")
    add_request(ambiguous, "probe")
    ambiguous.record_worker_outcome(invocation, _proposal_record().proposal)

    with pytest.raises(ValueError, match="multiple build/probe"):
        ambiguous.complete_attempt(invocation, accepted=True)
    assert ambiguous.actionable_ids() == frozenset()


def test_real_typed_production_adapters_execute_all_four_operation_shapes() -> None:
    from datetime import UTC, datetime
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.services.campaigns.pipeline_operations import (
        CampaignArtifactPipelineAdapter, TargetProposalPipelineAdapter,
    )
    from backend.services.campaigns.production_runtime import CampaignProgressObservation

    class Preparation:
        def __init__(self): self.calls = []
        async def prepare(self, project, proposal):
            self.calls.append((project.id, proposal.result_id))
            return {"summary": "target prepared"}

    class Campaigns:
        async def get(self, campaign_id):
            return SimpleNamespace(id=campaign_id, project_id=7, target_asset_id=31, configuration_asset_id=32)

    class Assets:
        async def list_for_project(self, _project_id): return []

    class Invocations:
        def load(self, _project_id, _campaign_id): return SimpleNamespace(engine="afl")

    class Progress:
        def __init__(self, kind): self.kind = kind
        def pipeline_progress(self, _project_id, _campaign_id):
            return CampaignProgressObservation(
                9, 1.0, datetime.now(UTC), 1, 1, "progress:9", "container",
                artifacts=(CampaignArtifactObservation(self.kind, "output/input", "c" * 64, 4),),
            )

    class Processor:
        def __init__(self): self.calls = []
        async def process(self, **values):
            self.calls.append(values)
            return {"summary": "artifact processed"}

    preparation = Preparation()
    replay_processor, coverage_processor = Processor(), Processor()
    adapters = {
        "build": TargetProposalPipelineAdapter(preparation, "build"),
        "probe": TargetProposalPipelineAdapter(preparation, "probe"),
        "replay": CampaignArtifactPipelineAdapter(
            operation="replay", campaigns=Campaigns(), assets=Assets(),
            invocations=Invocations(), progress=Progress("crash"), processor=replay_processor,
        ),
        "coverage": CampaignArtifactPipelineAdapter(
            operation="coverage", campaigns=Campaigns(), assets=Assets(),
            invocations=Invocations(), progress=Progress("corpus"), processor=coverage_processor,
        ),
    }
    project = SimpleNamespace(id=7, commit_sha="a" * 40)

    for operation, adapter in adapters.items():
        output = run(adapter.execute(project, record(operation)))
        assert output["summary"] in {"target prepared", "artifact processed"}

    assert len(preparation.calls) == 2
    assert len(replay_processor.calls) == len(coverage_processor.calls) == 1


def test_unselected_pipeline_operation_is_not_run_by_decision_executor() -> None:
    from backend.agents.outputs.campaign_decision import CampaignDecision
    from backend.agents.outputs.campaign_review import CampaignReviewResult
    from backend.services.campaigns.decision_executor import DecisionExecutor

    operation = record()
    review = CampaignReviewResult(
        decision=CampaignDecision(
            decision="wait", motivation="no operation selected",
            evidence_ids=["source:parser.c:42"], bounded_actions=[],
            next_review_delay_seconds=120, next_review_reason="collect more evidence",
            uncertainty="build is pending selection",
        ),
        known_action_ids=(operation.action_id,), selected_action_ids=(),
        known_target_proposals=(), selected_target_proposals=(),
        known_triage_results=(), selected_triage_results=(),
        known_operation_requests=(), selected_operation_requests=(),
        quarantined_operation_requests=(),
        known_pipeline_operations=(operation,), selected_pipeline_operations=(),
    )
    pipeline = AsyncMock()

    result = run(DecisionExecutor(AsyncMock(), pipeline_operations=pipeline).execute(
        SimpleNamespace(id=7, commit_sha="a" * 40), review,
    ))

    assert result == []
    pipeline.execute.assert_not_awaited()


def _proposal_record():
    from backend.agents.outputs.campaign_review import TargetProposalRecord
    from backend.agents.outputs.target_proposal import GeneratedAssetIntent, TargetProposal

    return TargetProposalRecord(
        result_id="target_" + "1" * 24,
        worker_assignment="prepare parser",
        tool_call_id="call-parser",
        attempt=1,
        model="gpt-5.6-luna",
        proposal=TargetProposal(
            target_name="parser",
            instance_type="system-level",
            byte_path="stdin to parser",
            expected_project_reach="parser.c",
            build_command="cc parser.c",
            run_command="/opt/bigeye/parser",
            seeds=[],
            configuration="default parser target",
            sanitizer_plan="ASan and UBSan",
            generated_asset_intents=[
                GeneratedAssetIntent(
                    relative_path="targets/parser/harness.c",
                    purpose="system harness",
                ),
            ],
            probe_assertions=["seed reaches parser project code"],
            evidence_ids=["source:parser.c:42"],
            uncertainty="not probed",
        ),
    )


def test_pipeline_action_snapshots_draft_and_exact_proposal_identity(tmp_path) -> None:
    from backend.agents.context import AgentContext
    from backend.agents.outputs.campaign_review import CampaignReviewCollection, WorkerInvocation
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever

    repository = tmp_path / "repository"
    repository.mkdir()
    draft_root = tmp_path / "generated"
    draft = draft_root / "targets/parser/harness.c"
    draft.parent.mkdir(parents=True)
    draft.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
    context = AgentContext(7, "a" * 40, repository, draft_root, EvidenceRetriever(repository))
    collection = CampaignReviewCollection()
    invocation = WorkerInvocation("prepare parser", "call-parser", 1, "gpt-5.6-luna")
    request = {
        "operation": "probe",
        "asset_paths": ["targets/parser/harness.c"],
        "assertions": ["seed reaches parser project code"],
        "executed": False,
        "provenance": "agent_request",
        "trusted_instructions": False,
    }
    audit = collection.record_operation(
        invocation,
        request,
        project_id=7,
        project_commit_sha=context.commit_sha,
        draft_sha256s=(("targets/parser/harness.c", "b" * 64),),
        evidence_ids=("source:parser.c:42",),
    )
    proposal = collection.record_worker_outcome(invocation, _proposal_record().proposal)
    collection.complete_attempt(invocation, accepted=True)

    action = collection.pipeline_operation(audit.request_id)

    assert action.project_commit_sha == "a" * 40
    assert action.draft_sha256s == (("targets/parser/harness.c", "b" * 64),)
    assert action.target_proposal.result_id == proposal.result_id
    assert action.action_id != record("probe").action_id


def test_pipeline_cas_rejects_later_sibling_edit_before_any_adapter_side_effect(tmp_path) -> None:
    from backend.agents.outputs.campaign_review import PipelineOperationRecord, _record_id
    from backend.services.campaigns.pipeline_operations import PipelineOperationService
    from backend.services.campaigns.action_journal import ActionJournal

    draft = tmp_path / "projects/7/generated-assets/targets/parser/harness.c"
    draft.parent.mkdir(parents=True)
    draft.write_text("changed sibling\n")
    repository = tmp_path / "projects/7/repository"
    repository.mkdir()
    proposal = _proposal_record()
    values = {
        "project_id": 7,
        "project_commit_sha": "a" * 40,
        "operation": "probe",
        "asset_paths": ("targets/parser/harness.c",),
        "draft_sha256s": (("targets/parser/harness.c", "b" * 64),),
        "assertions": ("seed reaches parser project code",),
        "worker_tool_call_id": "call-parser",
        "evidence_ids": ("source:parser.c:42",),
        "target_proposal": proposal.model_dump(mode="json"),
        "campaign_snapshot": None,
    }
    action = PipelineOperationRecord(
        action_id=_record_id("pipeline", values),
        **{**values, "target_proposal": proposal},
    )

    class Discovery:
        def context(self, _project_id):
            from backend.agents.context import AgentContext
            from backend.fuzzing.discovery.retrieval import EvidenceRetriever
            return AgentContext(
                7, "a" * 40, repository, draft.parents[2], EvidenceRetriever(repository),
            )

    class Adapter:
        def __init__(self):
            self.calls = 0

        async def execute(self, _project, _record):
            self.calls += 1
            return {"summary": "must not execute"}

    adapters = {name: Adapter() for name in ("build", "probe", "replay", "coverage")}
    events = AsyncMock()
    service = PipelineOperationService(
        build=adapters["build"], probe=adapters["probe"], replay=adapters["replay"],
        coverage=adapters["coverage"], discovery=Discovery(), events=events,
        journal=ActionJournal(tmp_path),
    )

    with pytest.raises(ValueError, match="draft.*changed"):
        run(service.execute(SimpleNamespace(id=7, commit_sha="a" * 40), action))

    assert sum(adapter.calls for adapter in adapters.values()) == 0
    assert any(call.args[1] == "debug" for call in events.append.await_args_list)


def test_pipeline_failure_records_original_error_and_emits_valid_manager_wake(tmp_path) -> None:
    from backend.fuzzing.campaigns.target_preparation import TargetPreparationFailed
    from backend.services.campaigns.pipeline_operations import PipelineOperationService
    from backend.services.observability.event_store import ProjectEventStore

    class FailingAdapter:
        async def execute(self, _project, _record):
            raise TargetPreparationFailed(
                "asset script name is unsafe for a Dockerfile",
                agent_attempts=("gpt-5.6-luna",), retained_target=None,
            )

    class UnusedAdapter:
        async def execute(self, _project, _record):
            raise AssertionError("unexpected adapter")

    events = ProjectEventStore(tmp_path)
    service = PipelineOperationService(
        build=FailingAdapter(), probe=UnusedAdapter(), replay=UnusedAdapter(),
        coverage=UnusedAdapter(), events=events,
    )

    with pytest.raises(TargetPreparationFailed, match="asset script name"):
        run(service.execute(SimpleNamespace(id=7, commit_sha="a" * 40), record("build")))

    debug = run(events.read(7, "debug", -1, 20))
    operation = next(event.payload for event in debug if event.payload.get("event") == "pipeline.operation")
    assert operation["status"] == "failed"
    assert operation["error_type"] == "TargetPreparationFailed"
    assert operation["error"] == "asset script name is unsafe for a Dockerfile"
    invalidations = run(events.read(7, "events", -1, 20))
    assert invalidations[-1].payload == {"name": "campaigns"}


def test_manager_worker_result_exposes_pipeline_ids_without_audit_ids() -> None:
    from pathlib import Path

    source = Path("backend/agents/tools/agent_dispatch.py").read_text(encoding="utf-8")

    assert '"pipeline_action_ids": operation_action_ids' in source
    assert '"operation_request_ids": operation_action_ids' not in source
    assert 'exclude={"operation_request_ids"}' in source
    assert 'if record.result_id not in bound_target_ids' in source


def test_pipeline_service_uses_explicit_operation_adapters_only() -> None:
    from pathlib import Path

    source = Path("backend/services/campaigns/pipeline_operations.py").read_text(encoding="utf-8")

    assert "inspect.getattr_static" not in source
    assert "instance_values" not in source
    assert "self._adapters[record.operation].execute" in source
