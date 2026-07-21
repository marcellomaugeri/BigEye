"""Structured target proposal returned by a dynamically assigned fuzzing worker."""

from pydantic import BaseModel, ConfigDict, Field


class SeedReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=500)
    provenance: str = Field(min_length=1, max_length=100)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class GeneratedAssetIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relative_path: str = Field(min_length=1, max_length=500)
    purpose: str = Field(min_length=1, max_length=500)


class TargetProposal(BaseModel):
    """One target whose build and probe can be checked before fuzzing."""

    model_config = ConfigDict(extra="forbid")

    target_name: str = Field(min_length=1, max_length=200)
    instance_type: str = Field(
        min_length=1, max_length=100,
        description="Begin with the assigned instance type: system-level or component-level.",
    )
    byte_path: str = Field(min_length=1, max_length=2_000)
    expected_project_reach: str = Field(min_length=1, max_length=2_000)
    build_command: str = Field(min_length=1, max_length=4_000)
    run_command: str = Field(min_length=1, max_length=4_000)
    seeds: list[SeedReference] = Field(max_length=32)
    configuration: str = Field(min_length=1, max_length=2_000)
    sanitizer_plan: str = Field(min_length=1, max_length=1_000)
    generated_asset_intents: list[GeneratedAssetIntent] = Field(max_length=16)
    probe_assertions: list[str] = Field(min_length=1, max_length=16)
    evidence_ids: list[str] = Field(min_length=1, max_length=64)
    uncertainty: str = Field(min_length=1, max_length=2_000)
