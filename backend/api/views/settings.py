"""Host and project settings request and response bodies."""

from pydantic import BaseModel, ConfigDict, Field


class SettingsResponse(BaseModel):
    database: bool
    docker: bool
    openai_api_key_present: bool
    toolchain: bool


class UpdateProjectSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker_count: int | None = Field(default=None, gt=0, le=2_147_483_647)
    repository_token: str | None = Field(default=None, max_length=4096)


class ProjectSettingsResponse(BaseModel):
    requested_revision: str
    commit_sha: str | None
    worker_count: int
    token_present: bool

    @classmethod
    def from_model(cls, project):
        return cls(
            requested_revision=project.requested_revision,
            commit_sha=project.commit_sha,
            worker_count=project.worker_count,
            token_present=project.token_present,
        )
