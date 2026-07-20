"""Execute only typed action IDs selected by one validated manager review."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Generic, TypeVar

from backend.agents.outputs.campaign_review import (
    CampaignReviewResult,
    PipelineOperationRecord,
    ProgressionActionRecord,
    RetirementActionRecord,
    TargetProposalRecord,
    TriageResultRecord,
)
from backend.services.campaigns.target_lifecycle import TargetLifecycleAction


ResultValue = TypeVar("ResultValue")


@dataclass(frozen=True)
class ActionError:
    """A bounded action failure retained without cancelling sibling actions."""

    error_type: str
    message: str


@dataclass(frozen=True)
class ActionResult(Generic[ResultValue]):
    """The typed output associated with one application-owned action ID."""

    action_id: str
    output: ResultValue | None
    error: ActionError | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


class DecisionExecutor:
    """Resolve manager-selected IDs without exposing a shell or Docker client."""

    def __init__(
        self, target_preparation, campaign_control=None, pipeline_operations=None,
        target_lifecycle=None,
    ):
        self._target_preparation = target_preparation
        self._campaign_control = campaign_control
        self._pipeline_operations = pipeline_operations
        self._target_lifecycle = target_lifecycle

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
        try:
            if isinstance(record, TargetProposalRecord):
                output = await self._target_preparation.prepare(project, record)
                return ActionResult(action_id, output)
            if isinstance(record, TriageResultRecord):
                return ActionResult(action_id, record.triage)
            if isinstance(record, PipelineOperationRecord):
                if self._pipeline_operations is None:
                    raise ValueError("no pipeline operation service is configured")
                output = await self._pipeline_operations.execute(project, record)
                return ActionResult(action_id, output)
            if isinstance(record, RetirementActionRecord):
                if self._campaign_control is None:
                    raise ValueError("no campaign control service is configured")
                output = await self._campaign_control.retire(project, record)
                return ActionResult(action_id, output)
            if isinstance(record, ProgressionActionRecord):
                if self._campaign_control is None:
                    raise ValueError("no campaign control service is configured")
                output = await self._campaign_control.progress(project, record)
                return ActionResult(action_id, output)
            if isinstance(record, TargetLifecycleAction):
                if self._target_lifecycle is None:
                    raise ValueError("no target lifecycle service is configured")
                output = await self._target_lifecycle.execute(project, record)
                return ActionResult(action_id, output)
            raise TypeError("manager-selected action record type is unsupported")
        except Exception as error:
            return ActionResult(
                action_id,
                None,
                ActionError(type(error).__name__, str(error)),
            )

    @staticmethod
    def _records(decision: CampaignReviewResult) -> dict[str, object]:
        records: dict[str, object] = {}
        values = (
            *((record.result_id, record) for record in decision.known_target_proposals),
            *((record.result_id, record) for record in decision.known_triage_results),
            *((record.action_id, record) for record in decision.known_retirement_actions),
            *((record.action_id, record) for record in decision.known_progression_actions),
            *((record.action_id, record) for record in decision.known_pipeline_operations
              if record.action_id in decision.known_action_ids),
            *((record.action_id, record) for record in decision.known_lifecycle_actions),
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
            *((record.action_id, record) for record in decision.selected_retirement_actions),
            *((record.action_id, record) for record in decision.selected_progression_actions),
            *((record.action_id, record) for record in decision.selected_pipeline_operations),
            *((record.action_id, record) for record in decision.selected_lifecycle_actions),
        )
        for action_id, record in values:
            if action_id in records:
                raise ValueError("manager-selected action IDs are not unique")
            records[action_id] = record
        return records
