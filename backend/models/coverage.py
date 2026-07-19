"""Persisted source coverage evidence."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CoverageEvidence:
    id: int
    project_id: int
    commit_sha: str
    source_path: str
    line_number: int
    function_name: str | None
    campaign_id: int
    asset_id: int
    first_testcase_sha256: str
    cpu_exposure_seconds: float
