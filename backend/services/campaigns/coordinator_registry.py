"""Own and observe exactly one local coordinator task per project."""

from __future__ import annotations

import asyncio


class CoordinatorRegistry:
    def __init__(self, projects, coordinator_factory):
        self._projects = projects
        self._coordinator_factory = coordinator_factory
        self._tasks: dict[int, asyncio.Task] = {}
        self._coordinators: dict[int, object] = {}
        self._closed = False
        self._restart_attempts: dict[int, int] = {}
        self._failure_tasks: set[asyncio.Task] = set()

    @property
    def tasks(self) -> dict[int, asyncio.Task]:
        return dict(self._tasks)

    def start(self, project_id: int) -> bool:
        if self._closed:
            raise RuntimeError("coordinator registry is closed")
        existing = self._tasks.get(project_id)
        if existing is not None and not existing.done():
            return False
        coordinator = self._coordinators.get(project_id)
        if coordinator is None:
            coordinator = self._coordinator_factory(project_id)
        task = asyncio.create_task(coordinator.run(project_id), name=f"bigeye-project-{project_id}")
        self._coordinators[project_id] = coordinator
        self._tasks[project_id] = task
        task.add_done_callback(lambda completed, identifier=project_id: self._observe(identifier, completed))
        return True

    async def recover(self) -> None:
        for project in await self._projects.list_unfinished():
            self.start(project.id)

    async def settings_changed(self, project_id: int) -> None:
        coordinator = self._coordinators.get(project_id)
        task = self._tasks.get(project_id)
        if coordinator is None or task is None or task.done():
            self.start(project_id)
            coordinator = self._coordinators[project_id]
        coordinator.notify(project_id)

    async def pause(self, project_id: int) -> None:
        coordinator = self._coordinators.get(project_id)
        if coordinator is not None:
            await coordinator.pause(project_id)

    async def resume(self, project_id: int) -> None:
        coordinator = self._coordinators.get(project_id)
        if coordinator is None:
            coordinator = self._coordinator_factory(project_id)
            self._coordinators[project_id] = coordinator
        await coordinator.resume(project_id)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        tasks = tuple(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        failures = tuple(self._failure_tasks)
        if failures:
            await asyncio.gather(*failures, return_exceptions=True)
        self._tasks.clear()
        self._coordinators.clear()

    def _observe(self, project_id: int, task: asyncio.Task) -> None:
        if self._tasks.get(project_id) is task:
            self._tasks.pop(project_id, None)
            self._coordinators.pop(project_id, None)
        if task.cancelled():
            return
        error = task.exception()
        if error is None:
            self._restart_attempts.pop(project_id, None)
            return
        failure = asyncio.create_task(self._recover_failure(project_id, error))
        self._failure_tasks.add(failure)
        failure.add_done_callback(self._failure_tasks.discard)

    async def _recover_failure(self, project_id: int, error: Exception) -> None:
        if self._closed:
            return
        project = await self._projects.get(project_id)
        attempts = self._restart_attempts.get(project_id, 0)
        if (
            project is not None and project.error is None and project.paused_at is None
            and attempts < 1
        ):
            self._restart_attempts[project_id] = attempts + 1
            self.start(project_id)
            return
        finish = getattr(self._projects, "finish", None)
        if finish is not None:
            await finish(project_id, f"coordinator failed ({type(error).__name__})")
