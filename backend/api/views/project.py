"""Project request and response bodies."""

from datetime import datetime

from pydantic import BaseModel, Field


class CreateProjectRequest(BaseModel):
    repository_url: str = Field(min_length=1, max_length=2048)
    worker_count: int = Field(gt=0)


class ProjectResponse(BaseModel):
    id: str
    repository_url: str
    worker_count: int
    commit_sha: str | None
    created_at: datetime
    finished_at: datetime | None
    error: str | None

    @classmethod
    def from_model(cls, project):
        return cls(id=str(project.id), repository_url=project.repository_url, worker_count=project.worker_count, commit_sha=project.commit_sha, created_at=project.created_at, finished_at=project.finished_at, error=project.error)
