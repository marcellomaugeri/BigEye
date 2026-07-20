"""Apply mutable project controls without exposing repository credentials."""

from typing import Protocol


class CoordinatorRegistry(Protocol):
    async def settings_changed(self, project_id: int) -> None: ...


class ProjectSettingsService:
    def __init__(
        self, projects, coordinator_registry: CoordinatorRegistry | None = None, execution_slots=None,
    ):
        self._projects = projects
        self._coordinator_registry = coordinator_registry
        self._execution_slots = execution_slots

    async def get(self, project_id: int):
        project = await self._projects.get(project_id)
        if project is None:
            raise KeyError(project_id)
        return project

    async def update(self, project_id: int, worker_count: int | None, repository_token: str | None):
        current = await self.get(project_id)
        project = await self._projects.update_settings(
            project_id, current.worker_count if worker_count is None else worker_count, repository_token
        )
        if self._execution_slots is not None:
            await self._execution_slots.configure(project)
        if self._coordinator_registry is not None:
            await self._coordinator_registry.settings_changed(project_id)
        return project
