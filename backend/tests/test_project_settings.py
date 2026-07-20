from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock


def test_settings_configures_updated_project_before_notifying_coordinator() -> None:
    from backend.services.projects.project_settings import ProjectSettingsService

    async def exercise():
        current = SimpleNamespace(id=7, worker_count=1)
        updated = SimpleNamespace(id=7, worker_count=2)
        projects = AsyncMock()
        projects.get.return_value = current
        projects.update_settings.return_value = updated
        order = []

        async def configure(project):
            order.append(("configure", project))

        async def settings_changed(project_id):
            order.append(("notify", project_id))

        slots = SimpleNamespace(configure=AsyncMock(side_effect=configure))
        coordinator = SimpleNamespace(settings_changed=AsyncMock(side_effect=settings_changed))
        service = ProjectSettingsService(projects, coordinator, slots)

        assert await service.update(7, 2, None) is updated
        assert order == [("configure", updated), ("notify", 7)]
        slots.configure.assert_awaited_once_with(updated)
        coordinator.settings_changed.assert_awaited_once_with(7)

    asyncio.run(exercise())
