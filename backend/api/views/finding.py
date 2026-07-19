"""Bounded HTTP response models for replayed crash groups."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    classification: str
    priority_rank: int | None
    priority_reason: str | None
    description: str
    reproducible: bool
    occurrence_count: int
    created_at: datetime
    triaged_at: datetime | None

    @classmethod
    def from_model(cls, finding):
        return cls(
            id=str(finding.id), project_id=str(finding.project_id),
            classification=finding.classification, priority_rank=finding.priority_rank,
            priority_reason=finding.priority_reason, description=finding.description,
            reproducible=finding.reproducible, occurrence_count=finding.occurrence_count,
            created_at=finding.created_at, triaged_at=finding.triaged_at,
        )


class ReproducerMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0, le=16 * 1024 * 1024)


class ReplayVariantResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    variant: str = Field(min_length=1, max_length=200)
    crashed: bool
    signal: str | None = Field(default=None, max_length=100)
    sanitizer: str | None = Field(default=None, max_length=100)
    source_location: str | None = Field(default=None, max_length=2_000)
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    error: str | None = Field(default=None, max_length=2_000)


class ReplaySummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempts: int = Field(ge=2, le=10)
    matching: int = Field(ge=0, le=10)
    compatible_variants: list[ReplayVariantResponse] = Field(default_factory=list, max_length=64)
    clean_variant: ReplayVariantResponse | None = None


class MinimisationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: bool
    original_size: int = Field(ge=0, le=16 * 1024 * 1024)
    minimal_size: int = Field(ge=0, le=16 * 1024 * 1024)


class CorrectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: int | None = Field(default=None, gt=0)
    parent_asset_id: int | None = Field(default=None, gt=0)
    image_id: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    commit_sha: str | None = Field(default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    crashed: bool | None = None
    evidence_id: str | None = Field(default=None, max_length=2_000)
    error: str | None = Field(default=None, max_length=2_000)


class FindingDetailResponse(FindingResponse):
    uncertainty: str = Field(min_length=1, max_length=2_000)
    evidence_ids: list[str] = Field(min_length=1, max_length=128)
    reproducer: ReproducerMetadata
    replay: ReplaySummaryResponse
    minimisation: MinimisationResponse | None = None
    correction: CorrectionResponse | None = None
    repair_intent: str | None = Field(default=None, max_length=2_000)

    @classmethod
    def from_model_and_evidence(cls, finding, evidence: dict[str, object]):
        base = FindingResponse.from_model(finding).model_dump()
        return cls(**base, **evidence)
