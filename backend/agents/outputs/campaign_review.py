"""Typed records retained from one manager review for deterministic consumers."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import threading

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.outputs.triage_result import TriageResult
from backend.fuzzing.campaigns.coverage_contract import valid_replay_environment


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


class RetirementActionRecord(BaseModel):
    """Application-validated reversible release of one redundant worker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(min_length=1, max_length=200)
    project_id: int = Field(ge=1)
    campaign_id: int = Field(ge=1)
    strategy_asset_id: int = Field(ge=1)
    retained_campaign_id: int = Field(ge=1)
    retained_strategy_asset_id: int = Field(ge=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=1_000)
    reversible: bool

    @model_validator(mode="after")
    def validate_identity_and_evidence(self):
        expected = (
            f"retirement:{self.project_id}:{self.campaign_id}:{self.strategy_asset_id}:"
            f"{self.retained_campaign_id}:{self.retained_strategy_asset_id}"
        )
        if self.action_id != expected:
            raise ValueError("retirement action identity does not match its exact records")
        if (
            self.campaign_id == self.retained_campaign_id
            or self.strategy_asset_id == self.retained_strategy_asset_id
        ):
            raise ValueError("retirement action must preserve a different retained strategy")
        if (
            len(self.evidence_ids) != len(set(self.evidence_ids))
            or any(not value.strip() or len(value) > 2_000 for value in self.evidence_ids)
        ):
            raise ValueError("retirement action evidence identifiers are invalid")
        if self.reversible is not True:
            raise ValueError("retirement action must be reversible")
        return self


class ProgressionActionRecord(BaseModel):
    """Application-owned incremental variant of one exact healthy campaign."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(min_length=1, max_length=200)
    project_id: int = Field(ge=1)
    base_campaign_id: int = Field(ge=1)
    target_asset_id: int = Field(ge=1)
    action_name: str = Field(min_length=1, max_length=100)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    arguments: tuple[str, ...] = Field(default=(), max_length=32)
    environment: tuple[tuple[str, str], ...] = Field(default=(), max_length=32)
    detail: str | None = Field(default=None, max_length=500)
    dictionary_content: str | None = Field(default=None, max_length=64_000)

    @property
    def key(self) -> str:
        return f"{self.action_name}:{self.detail}" if self.detail else self.action_name

    @model_validator(mode="after")
    def validate_identity_and_mechanics(self):
        prefix = f"campaign-progression:{self.project_id}:{self.base_campaign_id}:"
        if not self.action_id.startswith(prefix):
            raise ValueError("progression action identity does not match its base campaign")
        if (
            len(self.evidence_ids) != len(set(self.evidence_ids))
            or any(not value.strip() or len(value) > 2_000 for value in self.evidence_ids)
        ):
            raise ValueError("progression action evidence identifiers are invalid")
        if not valid_replay_environment(self.environment):
            raise ValueError("progression action replay environment is invalid")
        if any(not value or "\x00" in value or "\n" in value for value in self.arguments):
            raise ValueError("progression action arguments are invalid")
        if self.action_name == "enable dictionary":
            if (
                not self.dictionary_content
                or "\x00" in self.dictionary_content
                or self.arguments or self.environment or self.detail is not None
            ):
                raise ValueError("dictionary progression mechanics are invalid")
        elif self.action_name == "try configuration":
            if not self.arguments or self.dictionary_content is not None or not self.detail:
                raise ValueError("configuration progression mechanics are invalid")
        elif self.action_name == "enable grammar mutator":
            if (
                self.arguments or self.dictionary_content is not None or self.detail is not None
                or self.environment != ((
                    "AFL_CUSTOM_MUTATOR_LIBRARY",
                    "/usr/local/lib/afl/libgrammarmutator-json.so",
                ),)
            ):
                raise ValueError("grammar progression mechanics are invalid")
        else:
            raise ValueError("progression action does not have application-owned mechanics")
        return self


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
    known_retirement_actions: tuple[RetirementActionRecord, ...] = ()
    selected_retirement_actions: tuple[RetirementActionRecord, ...] = ()
    known_progression_actions: tuple[ProgressionActionRecord, ...] = ()
    selected_progression_actions: tuple[ProgressionActionRecord, ...] = ()

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
        self._retirements: dict[str, RetirementActionRecord] = {}
        self._progressions: dict[str, ProgressionActionRecord] = {}
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
            return frozenset((
                *self._targets, *self._triage, *self._operations,
                *self._retirements, *self._progressions,
            ))

    def record_retirement(self, record: RetirementActionRecord) -> RetirementActionRecord:
        if not isinstance(record, RetirementActionRecord) or record.reversible is not True:
            raise TypeError("retirement action must be validated and reversible")
        if len(record.evidence_ids) != len(set(record.evidence_ids)) or any(
            not value.strip() for value in record.evidence_ids
        ):
            raise ValueError("retirement action evidence must be unique non-blank identifiers")
        with self._lock:
            self._retirements.setdefault(record.action_id, record)
            if self._retirements[record.action_id] != record:
                raise ValueError("retirement action identifier is not unique")
            return self._retirements[record.action_id]

    def record_progression(self, record: ProgressionActionRecord) -> ProgressionActionRecord:
        if not isinstance(record, ProgressionActionRecord):
            raise TypeError("progression action must be application-validated")
        with self._lock:
            self._progressions.setdefault(record.action_id, record)
            if self._progressions[record.action_id] != record:
                raise ValueError("progression action identifier is not unique")
            return self._progressions[record.action_id]

    def result(self, decision: CampaignDecision) -> CampaignReviewResult:
        with self._lock:
            known_ids = frozenset((
                *self._targets, *self._triage, *self._operations,
                *self._retirements, *self._progressions,
            ))
            selected_ids = tuple(decision.bounded_actions)
            if len(selected_ids) != len(set(selected_ids)):
                raise ValueError("campaign decision contains duplicate action IDs")
            if set(selected_ids) - known_ids:
                raise ValueError("campaign decision selected an action outside this review")
            target_values = tuple(self._targets[key] for key in sorted(self._targets))
            triage_values = tuple(self._triage[key] for key in sorted(self._triage))
            operation_values = tuple(self._operations[key] for key in sorted(self._operations))
            retirement_values = tuple(self._retirements[key] for key in sorted(self._retirements))
            progression_values = tuple(self._progressions[key] for key in sorted(self._progressions))
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
                known_retirement_actions=retirement_values,
                selected_retirement_actions=tuple(
                    record for record in retirement_values if record.action_id in selected_ids
                ),
                known_progression_actions=progression_values,
                selected_progression_actions=tuple(
                    record for record in progression_values if record.action_id in selected_ids
                ),
            )
