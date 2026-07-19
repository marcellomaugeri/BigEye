"""Validate and persist a project before its backbone is scheduled."""

from urllib.parse import urlparse

from backend.services.initial_tasks import InitialTaskService


class InvalidRepositoryUrl(ValueError):
    """Raised when a repository URL cannot safely be passed to Git."""


def validate_repository_url(repository_url: str) -> str:
    parsed = urlparse(repository_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or repository_url.startswith("-")
        or any(character.isspace() for character in repository_url)
        or "@" in parsed.netloc
    ):
        raise InvalidRepositoryUrl("repository_url must be an http or https Git URL without credentials")
    return repository_url


class CreateProjectService:
    def __init__(self, projects, backbone, initial_tasks: InitialTaskService | None = None):
        self._projects = projects
        self._backbone = backbone
        self._initial_tasks = initial_tasks or InitialTaskService()

    async def create(self, repository_url: str, worker_count: int):
        validated_url = validate_repository_url(repository_url)
        created = await self._projects.create_with_tasks(validated_url, worker_count, self._initial_tasks.names())
        self._backbone.schedule(created.id)
        return created
