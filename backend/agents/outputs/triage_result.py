"""Structured interpretation of deterministically replayed crash evidence."""

from pydantic import BaseModel, ConfigDict, Field


class TriageResult(BaseModel):
    """One crash-group classification with uncertainty kept explicit."""

    model_config = ConfigDict(extra="forbid")

    classification: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)
    evidence_ids: list[str] = Field(min_length=1, max_length=64)
    uncertainty: str = Field(min_length=1, max_length=2_000)
    priority_rationale: str = Field(min_length=1, max_length=2_000)
    repair_intent: str = Field(min_length=1, max_length=2_000)
