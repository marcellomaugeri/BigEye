"""Coordinate recovery and genuine project update observation."""

import asyncio


class AnalysisNotReady(RuntimeError):
    """Raised while repository analysis has not produced its artifact."""


class ProjectBackboneService:
    def __init__(self, projects, scheduler):
        self._projects = projects
        self._scheduler = scheduler

    async def schedule(self, project_id: int) -> None:
        await self._scheduler.schedule(project_id)

    async def recover(self) -> None:
        for project in await self._projects.list_unfinished():
            await self.schedule(project.id)


class ProjectEventWatcher:
    def __init__(self, tasks, logs):
        self._tasks = tasks
        self._logs = logs
        self._snapshots: dict[int, tuple] = {}

    async def changed(self, project_id: int) -> bool:
        tasks = await self._tasks.list_for_project(project_id)
        state = []
        for task in tasks:
            state.append((task.id, task.finished_at, task.error, await self._logs.signature_for(task)))
        snapshot = tuple(state)
        prior = self._snapshots.get(project_id)
        self._snapshots[project_id] = snapshot
        return snapshot != prior

    async def stream(self, project_id: int):
        while True:
            if await self.changed(project_id):
                yield self.frame()
            await asyncio.sleep(1)

    @staticmethod
    def frame() -> str:
        return "data: updated\n\n"
