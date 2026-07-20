"""Compatibility entry point for the project coordinator registry."""

from __future__ import annotations

import inspect

from backend.services.campaigns.coordinator_registry import CoordinatorRegistry


class AnalysisNotReady(RuntimeError):
    """Raised while the initial campaign decision has not been published."""


class _BootstrapCoordinator:
    """Adapt the release backbone bootstrap to the continuous registry lifecycle."""

    def __init__(self, scheduler, advisory_lock=None):
        self._scheduler = scheduler
        self._advisory_lock = advisory_lock

    async def run(self, project_id: int) -> None:
        if self._advisory_lock is None:
            await self._scheduler.schedule(project_id)
            return
        async with self._advisory_lock.acquire(project_id) as acquired:
            if acquired:
                await self._scheduler.schedule(project_id)

    def notify(self, project_id: int) -> None:
        notify = getattr(self._scheduler, "notify", None)
        if notify is not None:
            notify(project_id)

    async def pause(self, project_id: int) -> None:
        await _optional_call(self._scheduler, "pause", project_id)

    async def resume(self, project_id: int) -> None:
        await _optional_call(self._scheduler, "resume", project_id)


class ProjectBackboneService(CoordinatorRegistry):
    """Retain the public backbone name while enforcing one task per project."""

    def __init__(self, projects, scheduler, advisory_lock=None):
        self._scheduler = scheduler
        self._advisory_lock = advisory_lock
        super().__init__(
            projects,
            lambda _project_id: _BootstrapCoordinator(scheduler, advisory_lock),
        )

    @property
    def _background_tasks(self):
        return set(self.tasks.values())

    def schedule(self, project_id: int) -> bool:
        return self.start(project_id)


async def _optional_call(target, method_name: str, *arguments) -> None:
    method = getattr(target, method_name, None)
    if method is None:
        return
    result = method(*arguments)
    if inspect.isawaitable(result):
        await result
