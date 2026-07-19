"""Typed records retained from one manager review for deterministic consumers."""

from __future__ import annotations

from hashlib import sha256
import json
import threading

from pydantic import BaseModel, ConfigDict, Field

from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.outputs.triage_result import TriageResult


class TargetProposalRecord(BaseModel):
    """A validated target proposal and its stable application-owned identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result_id: str = Field(min_length=1, max_length=100)
    specialist: str = Field(min_length=1, max_length=100)
    proposal: TargetProposal


class TriageResultRecord(BaseModel):
    """A validated triage result and its stable application-owned identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result_id: str = Field(min_length=1, max_length=100)
    specialist: str = Field(min_length=1, max_length=100)
    triage: TriageResult


class ContainedOperationRequestRecord(BaseModel):
    """A validated request awaiting execution by a deterministic service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=100)
    specialist: str = Field(min_length=1, max_length=100)
    operation: str = Field(min_length=1, max_length=100)
    asset_paths: tuple[str, ...] = Field(max_length=16)
    assertions: tuple[str, ...] = Field(min_length=1, max_length=16)
    executed: bool
    provenance: str = Field(min_length=1, max_length=100)
    trusted_instructions: bool


class CampaignReviewResult(BaseModel):
    """The decision plus every validated typed result produced while reaching it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: CampaignDecision
    target_proposals: tuple[TargetProposalRecord, ...]
    triage_results: tuple[TriageResultRecord, ...]
    operation_requests: tuple[ContainedOperationRequestRecord, ...]


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

    def record_specialist(
        self, specialist: str, result: TargetProposal | TriageResult,
    ) -> TargetProposalRecord | TriageResultRecord:
        if isinstance(result, TargetProposal):
            payload = {"specialist": specialist, "proposal": result.model_dump(mode="json")}
            record = TargetProposalRecord(
                result_id=_record_id("target", payload), specialist=specialist, proposal=result,
            )
            with self._lock:
                self._targets.setdefault(record.result_id, record)
                return self._targets[record.result_id]
        if isinstance(result, TriageResult):
            payload = {"specialist": specialist, "triage": result.model_dump(mode="json")}
            record = TriageResultRecord(
                result_id=_record_id("triage", payload), specialist=specialist, triage=result,
            )
            with self._lock:
                self._triage.setdefault(record.result_id, record)
                return self._triage[record.result_id]
        raise TypeError("campaign review result type is unsupported")

    def record_operation(self, specialist: str, request: dict) -> ContainedOperationRequestRecord:
        payload = {"specialist": specialist, **request}
        record = ContainedOperationRequestRecord(
            request_id=_record_id("operation", payload), specialist=specialist, **request,
        )
        with self._lock:
            self._operations.setdefault(record.request_id, record)
            return self._operations[record.request_id]

    def result(self, decision: CampaignDecision) -> CampaignReviewResult:
        with self._lock:
            return CampaignReviewResult(
                decision=decision,
                target_proposals=tuple(self._targets[key] for key in sorted(self._targets)),
                triage_results=tuple(self._triage[key] for key in sorted(self._triage)),
                operation_requests=tuple(self._operations[key] for key in sorted(self._operations)),
            )
