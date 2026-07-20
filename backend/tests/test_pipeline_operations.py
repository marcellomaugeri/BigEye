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


def record(operation: str = "build", *, asset_paths=("targets/parser/harness.c",)):
    from backend.agents.outputs.campaign_review import PipelineOperationRecord, _record_id

    values = dict(
        project_id=7,
        operation=operation,
        asset_paths=asset_paths,
        assertions=("seed reaches parser project code",),
        worker_tool_call_id="call-parser",
        evidence_ids=("source:parser.c:42",),
    )
    return PipelineOperationRecord(
        action_id=_record_id("pipeline", values),
        **values,
    )


def test_pipeline_record_uses_plain_validated_operation_strings() -> None:
    selected = record("probe")

    assert selected.operation == "probe"
    assert set(type(selected).model_fields) == {
        "action_id", "project_id", "operation", "asset_paths", "assertions",
        "worker_tool_call_id", "evidence_ids",
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
        invocation, request, evidence_ids=("source:parser.c:42",),
    )
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


class Slots:
    def __init__(self):
        self.operations = []

    @asynccontextmanager
    async def compilation(self, project, operation_id):
        self.operations.append((project.id, operation_id))
        yield SimpleNamespace()


@pytest.mark.parametrize(
    ("operation", "asset_paths", "uses_slot"),
    [
        ("build", ("targets/parser/build.sh",), True),
        ("probe", ("targets/parser/harness.c",), True),
        ("probe", (), False),
        ("replay", (), False),
        ("coverage", (), False),
    ],
)
def test_only_compiling_pipeline_operations_take_a_heavy_slot(
    operation: str, asset_paths: tuple[str, ...], uses_slot: bool,
) -> None:
    from backend.services.campaigns.pipeline_operations import PipelineOperationService

    slots = Slots()
    preparation = AsyncMock(return_value={
        "summary": "bounded deterministic operation completed",
        "image_id": "sha256:" + "b" * 64,
    })
    replay = AsyncMock(return_value={"summary": "replay completed"})
    coverage = AsyncMock(return_value={"summary": "coverage processed"})
    events = AsyncMock()
    service = PipelineOperationService(
        target_preparation=preparation,
        replay=replay,
        coverage=coverage,
        execution_slots=slots,
        events=events,
    )
    selected = record(operation, asset_paths=asset_paths)

    result = run(service.execute(SimpleNamespace(id=7), selected))

    assert result.action_id == selected.action_id
    assert result.evidence_id.startswith("pipeline-evidence:7:")
    assert bool(slots.operations) is uses_slot
    if operation in {"build", "probe"}:
        preparation.assert_awaited_once_with(SimpleNamespace(id=7), selected)
    elif operation == "replay":
        replay.assert_awaited_once_with(SimpleNamespace(id=7), selected)
    else:
        coverage.assert_awaited_once_with(SimpleNamespace(id=7), selected)
    assert [call.args[1] for call in events.append.await_args_list] == ["debug", "events"]


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
        SimpleNamespace(id=7), review,
    ))

    assert result == []
    pipeline.execute.assert_not_awaited()
