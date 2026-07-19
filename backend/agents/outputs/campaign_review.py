"""Typed records retained from one manager review for deterministic consumers."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import threading

from pydantic import BaseModel, ConfigDict, Field

from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.outputs.triage_result import TriageResult


@dataclass(frozen=True)
class SpecialistInvocation:
    """Exact outer agent-tool invocation and model attempt that produced a record."""

    specialist: str
    tool_call_id: str
    attempt: int
    model: str

    def __post_init__(self) -> None:
        if not isinstance(self.specialist, str) or not self.specialist or len(self.specialist) > 100:
            raise ValueError("specialist invocation name is invalid")
        if not isinstance(self.tool_call_id, str) or not self.tool_call_id or len(self.tool_call_id) > 500:
            raise ValueError("specialist tool call ID is invalid")
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or self.attempt < 1:
            raise ValueError("specialist attempt is invalid")
        if not isinstance(self.model, str) or not self.model or len(self.model) > 100:
            raise ValueError("specialist model is invalid")

    @property
    def key(self) -> tuple[str, str, int, str]:
        return self.specialist, self.tool_call_id, self.attempt, self.model


class TargetProposalRecord(BaseModel):
    """A validated target proposal and its stable application-owned identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result_id: str = Field(min_length=1, max_length=100)
    specialist: str = Field(min_length=1, max_length=100)
    tool_call_id: str = Field(min_length=1, max_length=500)
    attempt: int = Field(ge=1)
    model: str = Field(min_length=1, max_length=100)
    proposal: TargetProposal


class TriageResultRecord(BaseModel):
    """A validated triage result and its stable application-owned identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result_id: str = Field(min_length=1, max_length=100)
    specialist: str = Field(min_length=1, max_length=100)
    tool_call_id: str = Field(min_length=1, max_length=500)
    attempt: int = Field(ge=1)
    model: str = Field(min_length=1, max_length=100)
    triage: TriageResult


class ContainedOperationRequestRecord(BaseModel):
    """A validated request awaiting execution by a deterministic service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=100)
    specialist: str = Field(min_length=1, max_length=100)
    tool_call_id: str = Field(min_length=1, max_length=500)
    attempt: int = Field(ge=1)
    model: str = Field(min_length=1, max_length=100)
    operation: str = Field(min_length=1, max_length=100)
    asset_paths: tuple[str, ...] = Field(max_length=16)
    assertions: tuple[str, ...] = Field(min_length=1, max_length=16)
    executed: bool
    provenance: str = Field(min_length=1, max_length=100)
    trusted_instructions: bool
    actionable: bool


class CampaignReviewResult(BaseModel):
    """The decision plus every validated typed result produced while reaching it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: CampaignDecision
    known_action_ids: tuple[str, ...]
    selected_action_ids: tuple[str, ...]
    known_target_proposals: tuple[TargetProposalRecord, ...]
    selected_target_proposals: tuple[TargetProposalRecord, ...]
    known_triage_results: tuple[TriageResultRecord, ...]
    selected_triage_results: tuple[TriageResultRecord, ...]
    known_operation_requests: tuple[ContainedOperationRequestRecord, ...]
    selected_operation_requests: tuple[ContainedOperationRequestRecord, ...]
    quarantined_operation_requests: tuple[ContainedOperationRequestRecord, ...]

    @property
    def target_proposals(self) -> tuple[TargetProposalRecord, ...]:
        """Compatibility alias for known actionable target proposals."""
        return self.known_target_proposals

    @property
    def triage_results(self) -> tuple[TriageResultRecord, ...]:
        """Compatibility alias for known actionable triage results."""
        return self.known_triage_results

    @property
    def operation_requests(self) -> tuple[ContainedOperationRequestRecord, ...]:
        """Compatibility alias for known actionable operation requests."""
        return self.known_operation_requests


def _record_id(prefix: str, value: dict) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return prefix + "_" + sha256(encoded).hexdigest()[:24]


class CampaignReviewCollection:
    """Collect one review's validated outputs without parsing model traces.

    Function tools may run in parallel, so mutations are protected while snapshots remain immutable.
    Equal validated content receives the same stable identifier and is retained once.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._targets: dict[str, TargetProposalRecord] = {}
        self._triage: dict[str, TriageResultRecord] = {}
        self._operations: dict[str, ContainedOperationRequestRecord] = {}
        self._pending_operations: dict[
            tuple[str, str, int, str], dict[str, ContainedOperationRequestRecord]
        ] = {}
        self._quarantined_operations: dict[str, ContainedOperationRequestRecord] = {}

    def record_specialist(
        self, invocation: SpecialistInvocation, result: TargetProposal | TriageResult,
    ) -> TargetProposalRecord | TriageResultRecord:
        if isinstance(result, TargetProposal):
            payload = {**invocation.__dict__, "proposal": result.model_dump(mode="json")}
            record = TargetProposalRecord(
                result_id=_record_id("target", payload), **invocation.__dict__, proposal=result,
            )
            with self._lock:
                self._targets.setdefault(record.result_id, record)
                return self._targets[record.result_id]
        if isinstance(result, TriageResult):
            payload = {**invocation.__dict__, "triage": result.model_dump(mode="json")}
            record = TriageResultRecord(
                result_id=_record_id("triage", payload), **invocation.__dict__, triage=result,
            )
            with self._lock:
                self._triage.setdefault(record.result_id, record)
                return self._triage[record.result_id]
        raise TypeError("campaign review result type is unsupported")

    def record_operation(
        self, invocation: SpecialistInvocation, request: dict,
    ) -> ContainedOperationRequestRecord:
        payload = {**invocation.__dict__, **request}
        record = ContainedOperationRequestRecord(
            request_id=_record_id("operation", payload), **invocation.__dict__, **request,
            actionable=False,
        )
        with self._lock:
            pending = self._pending_operations.setdefault(invocation.key, {})
            pending.setdefault(record.request_id, record)
            return pending[record.request_id]

    def complete_attempt(self, invocation: SpecialistInvocation, *, actionable: bool) -> None:
        """Publish or quarantine only operation requests made by this exact attempt."""
        with self._lock:
            pending = self._pending_operations.pop(invocation.key, {})
            for request_id, record in pending.items():
                completed = record.model_copy(update={"actionable": actionable})
                if actionable:
                    self._operations.setdefault(request_id, completed)
                else:
                    self._quarantined_operations.setdefault(request_id, completed)

    def operation_ids(self, invocation: SpecialistInvocation) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(
                request_id for request_id, record in self._operations.items()
                if (
                    record.specialist, record.tool_call_id, record.attempt, record.model
                ) == invocation.key
            ))

    def actionable_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset((*self._targets, *self._triage, *self._operations))

    def result(self, decision: CampaignDecision) -> CampaignReviewResult:
        with self._lock:
            known_ids = frozenset((*self._targets, *self._triage, *self._operations))
            selected_ids = tuple(decision.bounded_actions)
            if len(selected_ids) != len(set(selected_ids)):
                raise ValueError("campaign decision contains duplicate action IDs")
            if set(selected_ids) - known_ids:
                raise ValueError("campaign decision selected an action outside this review")
            target_values = tuple(self._targets[key] for key in sorted(self._targets))
            triage_values = tuple(self._triage[key] for key in sorted(self._triage))
            operation_values = tuple(self._operations[key] for key in sorted(self._operations))
            return CampaignReviewResult(
                decision=decision,
                known_action_ids=tuple(sorted(known_ids)), selected_action_ids=selected_ids,
                known_target_proposals=target_values,
                selected_target_proposals=tuple(
                    record for record in target_values if record.result_id in selected_ids
                ),
                known_triage_results=triage_values,
                selected_triage_results=tuple(
                    record for record in triage_values if record.result_id in selected_ids
                ),
                known_operation_requests=operation_values,
                selected_operation_requests=tuple(
                    record for record in operation_values if record.request_id in selected_ids
                ),
                quarantined_operation_requests=tuple(
                    self._quarantined_operations[key] for key in sorted(self._quarantined_operations)
                ),
            )
