"""Structured outcomes returned by one dynamically assigned fuzzing worker."""

from pydantic import BaseModel, ConfigDict, Field

from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.outputs.triage_result import TriageResult


class FuzzingWorkerResult(BaseModel):
    """One or more bounded outcomes from a manager-assigned fuzzing task."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2_000)
    evidence_ids: list[str] = Field(max_length=64)
    target_proposals: list[TargetProposal] = Field(max_length=4)
    triage_results: list[TriageResult] = Field(max_length=16)
    operation_request_ids: list[str] = Field(max_length=16)
    recommendations: list[str] = Field(max_length=16)
    uncertainty: str = Field(min_length=1, max_length=2_000)
