"""HTTP views for clean source coverage and first-hit evidence."""

from pydantic import BaseModel


class PaginationResponse(BaseModel):
    limit: int
    offset: int
    total: int


class CoverageFileResponse(BaseModel):
    path: str
    covered_lines: int
    cpu_exposure_seconds: float


class CoverageTreeResponse(BaseModel):
    project_id: int
    commit_sha: str
    files: list[CoverageFileResponse]
    pagination: PaginationResponse


class SourceLineResponse(BaseModel):
    number: int
    text: str
    covered: bool
    strategy_count: int
    cpu_exposure_seconds: float


class SourceFileResponse(BaseModel):
    project_id: int
    commit_sha: str
    path: str
    start_line: int
    end_line: int
    lines: list[SourceLineResponse]


class FunctionCoverageResponse(BaseModel):
    name: str
    path: str
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
    target_asset_id: int
    configuration_asset_id: int | None
    clean_image_id: str
    cpu_exposure_seconds: float


class LineEvidencePageResponse(BaseModel):
    evidence: list[LineEvidenceResponse]
    pagination: PaginationResponse
