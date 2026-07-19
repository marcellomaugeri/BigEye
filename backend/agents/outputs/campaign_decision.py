"""Structured project-level decision returned by the campaign manager."""

from pydantic import BaseModel, ConfigDict, Field


class CampaignDecision(BaseModel):
    """An observable decision and its next deterministic wake condition."""

    model_config = ConfigDict(extra="forbid")

    decision: str = Field(min_length=1, max_length=500)
    motivation: str = Field(min_length=1, max_length=2_000)
    evidence_ids: list[str] = Field(max_length=64)
    bounded_actions: list[str] = Field(max_length=16)
    next_review_condition: str = Field(min_length=1, max_length=1_000)
    uncertainty: str = Field(min_length=1, max_length=2_000)
