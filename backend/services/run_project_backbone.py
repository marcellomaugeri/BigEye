"""Coordinate recovery and genuine project update observation."""

import asyncio


class AnalysisNotReady(RuntimeError):
    """Raised while repository analysis has not produced its artifact."""


class ProjectBackboneService:
    def __init__(self, projects, scheduler):
        self._projects = projects
        self._scheduler = scheduler
        self._background_tasks: set[asyncio.Task] = set()

    def schedule(self, project_id: int) -> None:
        task = asyncio.create_task(self._scheduler.schedule(project_id))
        self._background_tasks.add(task)
        task.add_done_callback(self._observe)

    def _observe(self, task: asyncio.Task) -> None:
        self._background_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def recover(self) -> None:
        for project in await self._projects.list_unfinished():
            self.schedule(project.id)

    async def close(self) -> None:
        tasks = tuple(self._background_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


class ProjectEventWatcher:
    def __init__(self, tasks, logs):
        self._tasks = tasks
        self._logs = logs
    async def snapshot(self, project_id: int) -> tuple:
        tasks = await self._tasks.list_for_project(project_id)
        state = []
        for task in tasks:
            state.append((task.id, task.finished_at, task.error, await self._logs.signature_for(task)))
        return tuple(state)

    async def stream(self, project_id: int, poll_interval: float = 1):
        previous = object()
        while True:
            snapshot = await self.snapshot(project_id)
            if snapshot != previous:
                previous = snapshot
                yield self.frame()
            await asyncio.sleep(poll_interval)

    @staticmethod
    def frame() -> str:
        return "data: updated\n\n"
