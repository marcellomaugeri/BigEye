"""Project request and response bodies."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CreateProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_url: str = Field(min_length=1, max_length=2048)
    worker_count: int = Field(gt=0, le=2_147_483_647)


class ProjectResponse(BaseModel):
    id: str
    repository_url: str
    requested_revision: str
    worker_count: int
    commit_sha: str | None
    token_present: bool
    created_at: datetime
    paused_at: datetime | None
    error: str | None

    @classmethod
    def from_model(cls, project):
        return cls(
            id=str(project.id),
            repository_url=project.repository_url,
            requested_revision=project.requested_revision,
            worker_count=project.worker_count,
            commit_sha=project.commit_sha,
            token_present=project.token_present,
            created_at=project.created_at,
            paused_at=project.paused_at,
            error=project.error,
        )
