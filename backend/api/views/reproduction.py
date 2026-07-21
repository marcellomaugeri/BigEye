"""Public views for read-only finding reproduction."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.services.findings.reproduction_registry import ReproductionRun


class ReproductionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    phase: Literal["starting", "completed", "failed", "timed_out", "interrupted"]
    started_at: datetime
    completed_at: datetime | None
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    command: list[str]
    exit_code: int | None
    terminal_reason: str | None
    sanitizer_crash_observed: bool

    @classmethod
    def from_run(cls, run: ReproductionRun) -> "ReproductionResponse":
        return cls(
            run_id=run.run_id, phase=run.phase, started_at=run.started_at,
            completed_at=run.completed_at, image_id=run.image_id,
            command=list(run.command), exit_code=run.exit_code,
            terminal_reason=run.terminal_reason,
            sanitizer_crash_observed=run.sanitizer_crash_observed,
        )
