"""Typed records retained from one manager review for deterministic consumers."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import threading
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.outputs.triage_result import TriageResult
from backend.fuzzing.campaigns.coverage_contract import valid_replay_environment
from backend.services.campaigns.target_lifecycle import TargetLifecycleAction


@dataclass(frozen=True)
class WorkerInvocation:
    """Exact dynamic assignment, agent-tool call, and model attempt for one worker run."""

    worker_assignment: str
    tool_call_id: str
    attempt: int
    model: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.worker_assignment, str)
            or not self.worker_assignment
            or len(self.worker_assignment) > 4_000
        ):
            raise ValueError("worker assignment is invalid")
        if not isinstance(self.tool_call_id, str) or not self.tool_call_id or len(self.tool_call_id) > 500:
            raise ValueError("worker tool call ID is invalid")
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or self.attempt < 1:
            raise ValueError("worker attempt is invalid")
        if not isinstance(self.model, str) or not self.model or len(self.model) > 100:
            raise ValueError("worker model is invalid")

    @property
    def key(self) -> tuple[str, str, int, str]:
        return self.worker_assignment, self.tool_call_id, self.attempt, self.model


class TargetProposalRecord(BaseModel):
    """A validated target proposal and its stable application-owned identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result_id: str = Field(min_length=1, max_length=100)
    worker_assignment: str = Field(min_length=1, max_length=4_000)
    tool_call_id: str = Field(min_length=1, max_length=500)
    attempt: int = Field(ge=1)
    model: str = Field(min_length=1, max_length=100)
    proposal: TargetProposal


class TriageResultRecord(BaseModel):
    """A validated triage result and its stable application-owned identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result_id: str = Field(min_length=1, max_length=100)
    worker_assignment: str = Field(min_length=1, max_length=4_000)
    tool_call_id: str = Field(min_length=1, max_length=500)
    attempt: int = Field(ge=1)
    model: str = Field(min_length=1, max_length=100)
    triage: TriageResult


class ContainedOperationRequestRecord(BaseModel):
    """A typed worker planning record retained for audit, not execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=100)
    worker_assignment: str = Field(min_length=1, max_length=4_000)
    tool_call_id: str = Field(min_length=1, max_length=500)
    attempt: int = Field(ge=1)
    model: str = Field(min_length=1, max_length=100)
    operation: str = Field(min_length=1, max_length=100)
    asset_paths: tuple[str, ...] = Field(max_length=16)
    assertions: tuple[str, ...] = Field(min_length=1, max_length=16)
    executed: Literal[False]
    provenance: str = Field(min_length=1, max_length=100)
    trusted_instructions: bool
    actionable: Literal[False]


class PipelineOperationRecord(BaseModel):
    """Application-owned deterministic action derived from one inert worker request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(min_length=1, max_length=100)
    project_id: int = Field(ge=1)
    project_commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    operation: str = Field(min_length=1, max_length=100)
    asset_paths: tuple[str, ...] = Field(max_length=16)
    draft_sha256s: tuple[tuple[str, str], ...] = Field(max_length=16)
    assertions: tuple[str, ...] = Field(min_length=1, max_length=16)
    worker_tool_call_id: str = Field(min_length=1, max_length=500)
    evidence_ids: tuple[str, ...] = Field(max_length=64)
    target_proposal: TargetProposalRecord | None = None
    campaign_snapshot: "PipelineCampaignSnapshot | None" = None

    @model_validator(mode="after")
    def validate_bounded_action(self):
        if self.operation not in {"build", "probe", "replay", "coverage"}:
            raise ValueError("pipeline operation is not allowed")
        if len(self.asset_paths) != len(set(self.asset_paths)):
            raise ValueError("pipeline operation asset paths must be unique")
        for value in self.asset_paths:
            if not isinstance(value, str) or not value or len(value) > 500 or "\\" in value or "\x00" in value:
                raise ValueError("pipeline operation asset path is invalid")
            path = PurePosixPath(value)
            if path.is_absolute() or any(
                part in {"", ".", ".."} or part.casefold() == ".git" for part in path.parts
            ):
                raise ValueError("pipeline operation asset path is invalid")
        if tuple(path for path, _digest in self.draft_sha256s) != self.asset_paths or any(
            not isinstance(digest, str) or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for _path, digest in self.draft_sha256s
        ):
            raise ValueError("pipeline operation draft snapshots are invalid")
        if len(self.assertions) != len(set(self.assertions)) or any(
            not isinstance(value, str) or not value.strip() or len(value) > 500
            for value in self.assertions
        ):
            raise ValueError("pipeline operation assertions are invalid")
        if len(self.evidence_ids) != len(set(self.evidence_ids)) or any(
            not isinstance(value, str) or not value.strip() or len(value) > 2_000
            for value in self.evidence_ids
        ):
            raise ValueError("pipeline operation evidence identifiers are invalid")
        if self.operation in {"build", "probe"}:
            if self.target_proposal is None or self.campaign_snapshot is not None:
                raise ValueError("build and probe actions require one exact target proposal")
            if self.target_proposal.tool_call_id != self.worker_tool_call_id:
                raise ValueError("pipeline target proposal crossed its worker call boundary")
        elif self.target_proposal is not None or self.campaign_snapshot is None:
            raise ValueError("replay and coverage actions require one exact campaign snapshot")
        if self.campaign_snapshot is not None and self.campaign_snapshot.operation != self.operation:
            raise ValueError("pipeline campaign snapshot operation changed")
        expected = _record_id("pipeline", {
            "project_id": self.project_id,
            "project_commit_sha": self.project_commit_sha,
            "operation": self.operation,
            "asset_paths": self.asset_paths,
            "draft_sha256s": self.draft_sha256s,
            "assertions": self.assertions,
            "worker_tool_call_id": self.worker_tool_call_id,
            "evidence_ids": self.evidence_ids,
            "target_proposal": (
                self.target_proposal.model_dump(mode="json")
                if self.target_proposal is not None else None
            ),
            "campaign_snapshot": (
                self.campaign_snapshot.model_dump(mode="json")
                if self.campaign_snapshot is not None else None
            ),
        })
        if self.action_id != expected:
            raise ValueError("pipeline operation action identity is invalid")
        return self


class PipelineArtifactSnapshot(BaseModel):
    """One exact monitored input selected for replay or clean coverage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    relative_path: str = Field(min_length=1, max_length=1_000)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0, le=16 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_artifact(self):
        if self.kind not in {"crash", "corpus"}:
            raise ValueError("pipeline artifact kind is invalid")
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("pipeline artifact path is invalid")
        return self


class PipelineCampaignSnapshot(BaseModel):
    """Persisted campaign and monitor identity required by replay/coverage adapters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: str
    campaign_id: int = Field(ge=1)
    target_asset_id: int = Field(ge=1)
    configuration_asset_id: int | None = Field(default=None, ge=1)
    progress_evidence_id: str = Field(min_length=1, max_length=256)
    artifacts: tuple[PipelineArtifactSnapshot, ...] = Field(min_length=1, max_length=1_024)

    @model_validator(mode="after")
    def validate_campaign_snapshot(self):
        expected_kind = {"replay": "crash", "coverage": "corpus"}.get(self.operation)
        if expected_kind is None or any(value.kind != expected_kind for value in self.artifacts):
            raise ValueError("pipeline campaign snapshot does not match its operation")
        identities = tuple((item.relative_path, item.content_sha256) for item in self.artifacts)
        if len(identities) != len(set(identities)):
            raise ValueError("pipeline campaign snapshot artifacts are not unique")
        return self


PipelineOperationRecord.model_rebuild()


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
    known_pipeline_operations: tuple[PipelineOperationRecord, ...] = ()
    selected_pipeline_operations: tuple[PipelineOperationRecord, ...] = ()
    known_lifecycle_actions: tuple[TargetLifecycleAction, ...] = ()
    selected_lifecycle_actions: tuple[TargetLifecycleAction, ...] = ()

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
        """Compatibility alias for retained audit-only operation requests."""
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
        self._pipeline_operations: dict[str, PipelineOperationRecord] = {}
        self._pipeline_by_request: dict[str, str] = {}
        self._retirements: dict[str, RetirementActionRecord] = {}
        self._progressions: dict[str, ProgressionActionRecord] = {}
        self._lifecycles: dict[str, TargetLifecycleAction] = {}
        self._pending_operations: dict[
            tuple[str, str, int, str], dict[str, ContainedOperationRequestRecord]
        ] = {}
        self._pending_pipeline_operations: dict[
            tuple[str, str, int, str], dict[str, dict]
        ] = {}
        self._quarantined_operations: dict[str, ContainedOperationRequestRecord] = {}

    def record_worker_outcome(
        self, invocation: WorkerInvocation, result: TargetProposal | TriageResult,
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

    def record_worker(
        self, invocation: WorkerInvocation, targets: list[TargetProposal], triage: list[TriageResult],
    ) -> tuple[tuple[TargetProposalRecord, ...], tuple[TriageResultRecord, ...]]:
        """Retain every validated concrete outcome from one accepted worker result."""
        return (
            tuple(self.record_worker_outcome(invocation, result) for result in targets),
            tuple(self.record_worker_outcome(invocation, result) for result in triage),
        )

    def record_operation(
        self,
        invocation: WorkerInvocation,
        request: dict,
        *,
        project_id: int | None = None,
        project_commit_sha: str | None = None,
        draft_sha256s: tuple[tuple[str, str], ...] = (),
        campaign_snapshot: PipelineCampaignSnapshot | None = None,
        evidence_ids: tuple[str, ...] = (),
    ) -> ContainedOperationRequestRecord:
        request = dict(request)
        supplied_project_id = request.pop("project_id", None)
        if project_id is None:
            project_id = supplied_project_id
        elif supplied_project_id is not None and supplied_project_id != project_id:
            raise ValueError("operation request project identity changed")
        payload = {**invocation.__dict__, **request}
        record = ContainedOperationRequestRecord(
            request_id=_record_id("operation", payload), **invocation.__dict__, **request,
            actionable=False,
        )
        pipeline_values = None
        if project_id is not None:
            if project_commit_sha is None:
                # Compatibility path for audit-only unit callers. Production promotion
                # always supplies an exact commit and immutable draft identities.
                pipeline_values = None
            else:
                pipeline_values = {
                "project_id": project_id,
                "project_commit_sha": project_commit_sha,
                "operation": record.operation,
                "asset_paths": record.asset_paths,
                "draft_sha256s": draft_sha256s,
                "assertions": record.assertions,
                "worker_tool_call_id": invocation.tool_call_id,
                "evidence_ids": evidence_ids,
                "campaign_snapshot": campaign_snapshot,
            }
        with self._lock:
            pending = self._pending_operations.setdefault(invocation.key, {})
            pending.setdefault(record.request_id, record)
            if pipeline_values is not None:
                pipeline_pending = self._pending_pipeline_operations.setdefault(invocation.key, {})
                pipeline_pending.setdefault(record.request_id, pipeline_values)
            return pending[record.request_id]

    def pending_operation_ids(self, invocation: WorkerInvocation) -> frozenset[str]:
        """Return only operation requests created by this exact in-flight worker attempt."""
        with self._lock:
            return frozenset(self._pending_operations.get(invocation.key, ()))

    def complete_attempt(self, invocation: WorkerInvocation, *, accepted: bool) -> None:
        """Retain audit records only from the exact accepted worker attempt."""
        with self._lock:
            pending = self._pending_operations.pop(invocation.key, {})
            pending_pipeline = self._pending_pipeline_operations.pop(invocation.key, {})
            if not accepted:
                for request_id, record in pending.items():
                    self._quarantined_operations.setdefault(request_id, record)
                return

            promoted = {}
            try:
                bound_targets = {
                    value.target_proposal.result_id: value.action_id
                    for value in self._pipeline_operations.values()
                    if value.target_proposal is not None
                }
                for request_id, values in pending_pipeline.items():
                    pipeline = self._promote_pipeline(
                        invocation, pending[request_id], dict(values),
                    )
                    if pipeline.target_proposal is not None:
                        target_id = pipeline.target_proposal.result_id
                        existing = bound_targets.get(target_id)
                        if existing is not None and existing != pipeline.action_id:
                            raise ValueError(
                                "target proposal requested multiple build/probe pipeline actions"
                            )
                        bound_targets[target_id] = pipeline.action_id
                    promoted[request_id] = pipeline
            except Exception:
                for request_id, record in pending.items():
                    self._quarantined_operations.setdefault(request_id, record)
                self._targets = {
                    key: value for key, value in self._targets.items()
                    if (
                        value.worker_assignment, value.tool_call_id, value.attempt, value.model
                    ) != invocation.key
                }
                self._triage = {
                    key: value for key, value in self._triage.items()
                    if (
                        value.worker_assignment, value.tool_call_id, value.attempt, value.model
                    ) != invocation.key
                }
                raise

            for request_id, record in pending.items():
                self._operations.setdefault(request_id, record)
            for request_id, pipeline in promoted.items():
                existing_action = self._pipeline_operations.setdefault(
                    pipeline.action_id, pipeline,
                )
                if existing_action != pipeline:
                    raise ValueError("pipeline action identifier is not unique")
                self._pipeline_by_request.setdefault(request_id, pipeline.action_id)

    def _promote_pipeline(self, invocation, request, values) -> PipelineOperationRecord:
        target = None
        campaign = values.pop("campaign_snapshot")
        if request.operation in {"build", "probe"}:
            candidates = tuple(
                record for record in self._targets.values()
                if (
                    record.worker_assignment, record.tool_call_id, record.attempt, record.model
                ) == invocation.key
                and set(request.asset_paths) == {
                    intent.relative_path for intent in record.proposal.generated_asset_intents
                }
                and set(request.assertions).issubset(set(record.proposal.probe_assertions))
            )
            if len(candidates) != 1:
                raise ValueError("pipeline operation must bind one exact target proposal")
            target = candidates[0]
        elif campaign is None:
            raise ValueError("pipeline operation must bind one exact campaign snapshot")
        canonical = {
            **values,
            "target_proposal": target.model_dump(mode="json") if target is not None else None,
            "campaign_snapshot": campaign.model_dump(mode="json") if campaign is not None else None,
        }
        return PipelineOperationRecord(
            action_id=_record_id("pipeline", canonical),
            **values,
            target_proposal=target,
            campaign_snapshot=campaign,
        )

    def pipeline_action_id(self, request_id: str) -> str:
        """Resolve an accepted worker request to its separate selectable action identity."""
        with self._lock:
            try:
                return self._pipeline_by_request[request_id]
            except KeyError as error:
                raise ValueError("operation request has no accepted pipeline action") from error

    def pipeline_operation(self, request_id: str) -> PipelineOperationRecord:
        """Resolve an accepted audit request to its immutable application action."""
        action_id = self.pipeline_action_id(request_id)
        with self._lock:
            return self._pipeline_operations[action_id]

    def actionable_ids(self) -> frozenset[str]:
        with self._lock:
            pipeline_target_ids = {
                value.target_proposal.result_id
                for value in self._pipeline_operations.values()
                if value.target_proposal is not None
            }
            return frozenset((
                *(key for key in self._targets if key not in pipeline_target_ids),
                *self._triage, *self._retirements, *self._progressions,
                *self._pipeline_operations,
                *self._lifecycles,
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

    def record_lifecycle(self, record: TargetLifecycleAction) -> TargetLifecycleAction:
        if not isinstance(record, TargetLifecycleAction):
            raise TypeError("lifecycle action must be application-validated")
        with self._lock:
            self._lifecycles.setdefault(record.action_id, record)
            if self._lifecycles[record.action_id] != record:
                raise ValueError("lifecycle action identifier is not unique")
            return self._lifecycles[record.action_id]

    def result(self, decision: CampaignDecision) -> CampaignReviewResult:
        with self._lock:
            selected_ids = tuple(decision.bounded_actions)
            pipeline_target_ids = {
                value.target_proposal.result_id
                for value in self._pipeline_operations.values()
                if value.target_proposal is not None
            }
            selectable_ids = frozenset((
                *(key for key in self._targets if key not in pipeline_target_ids),
                *self._triage, *self._retirements, *self._progressions,
                *self._pipeline_operations,
                *self._lifecycles,
            ))
            if len(selected_ids) != len(set(selected_ids)):
                raise ValueError("campaign decision contains duplicate action IDs")
            audit_request_ids = frozenset((*self._operations, *self._quarantined_operations))
            if set(selected_ids) & audit_request_ids:
                raise ValueError("contained operation requests are audit records and not selectable")
            if set(selected_ids) - selectable_ids:
                raise ValueError("campaign decision selected an action outside this review")
            # Unselected operation requests remain inert audit data. A selected pipeline
            # operation enters the executable known-action set only in that exact review.
            known_ids = frozenset((
                *(key for key in self._targets if key not in pipeline_target_ids),
                *self._triage,
                *self._retirements,
                *self._progressions,
                *self._lifecycles,
                *self._pipeline_operations,
            ))
            target_values = tuple(
                self._targets[key] for key in sorted(self._targets)
                if key not in pipeline_target_ids
            )
            triage_values = tuple(self._triage[key] for key in sorted(self._triage))
            operation_values = tuple(self._operations[key] for key in sorted(self._operations))
            retirement_values = tuple(self._retirements[key] for key in sorted(self._retirements))
            progression_values = tuple(self._progressions[key] for key in sorted(self._progressions))
            pipeline_values = tuple(
                self._pipeline_operations[key] for key in sorted(self._pipeline_operations)
            )
            lifecycle_values = tuple(self._lifecycles[key] for key in sorted(self._lifecycles))
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
                selected_operation_requests=(),
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
                known_pipeline_operations=pipeline_values,
                selected_pipeline_operations=tuple(
                    record for record in pipeline_values if record.action_id in selected_ids
                ),
                known_lifecycle_actions=lifecycle_values,
                selected_lifecycle_actions=tuple(
                    record for record in lifecycle_values if record.action_id in selected_ids
                ),
            )
