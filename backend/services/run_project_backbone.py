"""Coordinate recovery and genuine project update observation."""

import asyncio

from backend.fuzzing.docker.client import DOCKER_REQUEST_TIMEOUT_SECONDS


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
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=DOCKER_REQUEST_TIMEOUT_SECONDS + 5)
            except TimeoutError:
                return
