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

    @property
    def tasks(self) -> dict[int, asyncio.Task]:
        return dict(self._tasks)

    def start(self, project_id: int) -> bool:
        if self._closed:
            raise RuntimeError("coordinator registry is closed")
        existing = self._tasks.get(project_id)
        if existing is not None and not existing.done():
            return False
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
        if coordinator is None:
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
            self.start(project_id)
            coordinator = self._coordinators[project_id]
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
        self._tasks.clear()
        self._coordinators.clear()

    def _observe(self, project_id: int, task: asyncio.Task) -> None:
        if self._tasks.get(project_id) is task:
            self._tasks.pop(project_id, None)
            self._coordinators.pop(project_id, None)
        if not task.cancelled():
            task.exception()
