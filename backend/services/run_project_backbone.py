"""Compatibility entry point for the project coordinator registry."""

from __future__ import annotations

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


class ProjectBackboneService(CoordinatorRegistry):
    """Retain the public backbone name while enforcing one task per project."""

    def __init__(self, projects, scheduler, advisory_lock=None, coordinator_factory=None):
        self._scheduler = scheduler
        self._advisory_lock = advisory_lock
        super().__init__(
            projects,
            coordinator_factory or (
                lambda _project_id: _BootstrapCoordinator(scheduler, advisory_lock)
            ),
        )

    @property
    def _background_tasks(self):
        return set(self.tasks.values())

    def schedule(self, project_id: int) -> bool:
        return self.start(project_id)
