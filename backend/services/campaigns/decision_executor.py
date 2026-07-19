"""Execute only typed action IDs selected by one validated manager review."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Generic, TypeVar

from backend.agents.outputs.campaign_review import (
    CampaignReviewResult,
    ContainedOperationRequestRecord,
    TargetProposalRecord,
    TriageResultRecord,
)


ResultValue = TypeVar("ResultValue")


@dataclass(frozen=True)
class ActionResult(Generic[ResultValue]):
    """The typed output associated with one application-owned action ID."""

    action_id: str
    output: ResultValue


class DecisionExecutor:
    """Resolve manager-selected IDs without exposing a shell or Docker client."""

    def __init__(self, target_preparation, bounded_operations=None):
        self._target_preparation = target_preparation
        self._bounded_operations = bounded_operations

    async def execute(self, project, decision: CampaignReviewResult) -> list[ActionResult]:
        if not isinstance(decision, CampaignReviewResult):
            raise TypeError("decision executor requires a validated campaign review")
        selected = tuple(decision.selected_action_ids)
        known = tuple(decision.known_action_ids)
        if (
            selected != tuple(decision.decision.bounded_actions)
            or len(selected) != len(set(selected))
            or len(known) != len(set(known))
            or not set(selected).issubset(known)
        ):
            raise ValueError("decision contains an action outside the manager-validated known IDs")

        records = self._records(decision)
        if set(records) != set(known) or any(action_id not in records for action_id in selected):
            raise ValueError("decision records do not match the manager-validated known IDs")
        selected_records = self._selected_records(decision)
        if (
            set(selected_records) != set(selected)
            or any(selected_records[action_id] != records[action_id] for action_id in selected)
        ):
            raise ValueError("decision selected records do not match the manager-validated action IDs")

        results = await asyncio.gather(*(
            self._execute_one(project, action_id, selected_records[action_id])
            for action_id in selected
        ))
        return list(results)

    async def _execute_one(self, project, action_id: str, record) -> ActionResult:
        if isinstance(record, TargetProposalRecord):
            output = await self._target_preparation.prepare(project, record)
            return ActionResult(action_id, output)
        if isinstance(record, ContainedOperationRequestRecord):
            if (
                not record.actionable
                or record.executed
                or record.provenance != "agent_request"
                or record.trusted_instructions
            ):
                raise ValueError("contained operation is not manager-validated for execution")
            if self._bounded_operations is None:
                raise ValueError("no bounded operation service is configured")
            output = await self._bounded_operations.execute(project, record)
            return ActionResult(action_id, output)
        if isinstance(record, TriageResultRecord):
            return ActionResult(action_id, record.triage)
        raise TypeError("manager-selected action record type is unsupported")

    @staticmethod
    def _records(decision: CampaignReviewResult) -> dict[str, object]:
        records: dict[str, object] = {}
        values = (
            *((record.result_id, record) for record in decision.known_target_proposals),
            *((record.result_id, record) for record in decision.known_triage_results),
            *((record.request_id, record) for record in decision.known_operation_requests),
        )
        for action_id, record in values:
            if action_id in records:
                raise ValueError("manager-validated action IDs are not unique")
            records[action_id] = record
        return records

    @staticmethod
    def _selected_records(decision: CampaignReviewResult) -> dict[str, object]:
        records: dict[str, object] = {}
        values = (
            *((record.result_id, record) for record in decision.selected_target_proposals),
            *((record.result_id, record) for record in decision.selected_triage_results),
            *((record.request_id, record) for record in decision.selected_operation_requests),
        )
        for action_id, record in values:
            if action_id in records:
                raise ValueError("manager-selected action IDs are not unique")
            records[action_id] = record
        return records
