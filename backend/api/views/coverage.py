"""HTTP views for clean source coverage and first-hit evidence."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.services.observability.redaction import redact_environment


class PaginationResponse(BaseModel):
    limit: int
    offset: int
    total: int


class CoverageMeasurementResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    covered: int = Field(ge=0)
    total: int = Field(ge=0)
    percent: float = Field(ge=0, le=100)


class CoverageSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lines: CoverageMeasurementResponse | None
    functions: CoverageMeasurementResponse | None
    branches: CoverageMeasurementResponse | None


class CoverageHistoryPointResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: datetime
    covered: int = Field(ge=0)
    total: int = Field(ge=0)
    percent: float = Field(ge=0, le=100)


class CoverageFileResponse(BaseModel):
    path: str
    covered_lines: int
    total_lines: int | None = None
    covered_functions: int | None = None
    total_functions: int | None = None
    covered_branches: int | None = None
    total_branches: int | None = None
    lines: CoverageMeasurementResponse | None = None
    functions: CoverageMeasurementResponse | None = None
    branches: CoverageMeasurementResponse | None = None
    cpu_exposure_seconds: float


class CoverageTreeResponse(BaseModel):
    project_id: int
    commit_sha: str
    files: list[CoverageFileResponse]
    summary: CoverageSummaryResponse
    history: list[CoverageHistoryPointResponse] = Field(default_factory=list)
    pagination: PaginationResponse


class SourceLineResponse(BaseModel):
    number: int
    text: str
    covered: bool
    branches: list[bool] | None = None
    strategy_count: int
    cpu_exposure_seconds: float


class SourceFileResponse(BaseModel):
    project_id: int
    commit_sha: str
    path: str
    start_line: int
    end_line: int
    total_lines: int
    lines: list[SourceLineResponse]


class FunctionCoverageResponse(BaseModel):
    name: str
    path: str
    start_line: int | None = None
    start_column: int | None = None
    covered: bool | None = None
    covered_lines: int
    cpu_exposure_seconds: float


class FunctionCoveragePageResponse(BaseModel):
    functions: list[FunctionCoverageResponse]
    pagination: PaginationResponse


class LineEvidenceResponse(BaseModel):
    campaign_id: int
    strategy_asset_id: int
    testcase_sha256: str
    replay_command: list[str]
    replay_environment: dict[str, str]
    target_asset_id: int
    configuration_asset_id: int | None
    clean_image_id: str
    cpu_exposure_seconds: float

    @field_validator("replay_environment", mode="before")
    @classmethod
    def redact_replay_environment(cls, value):
        return redact_environment(value)


class LineEvidencePageResponse(BaseModel):
    evidence: list[LineEvidenceResponse]
    pagination: PaginationResponse
