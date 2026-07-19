"""Injectable application service container."""

from dataclasses import dataclass
from pathlib import Path

from backend.repositories.project_repository import ProjectRepository
from backend.repositories.task_repository import TaskRepository
from backend.services.check_settings import SettingsService
from backend.services.create_project import CreateProjectService
from backend.services.read_analysis import AnalysisReader
from backend.services.run_project_backbone import ProjectBackboneService, ProjectEventWatcher
from backend.services.stream_task_output import TaskLogReader


class UnconfiguredScheduler:
    async def schedule(self, project_id: int) -> None:
        return None


@dataclass
class Services:
    project_creator: object
    projects: object
    tasks: object
    logs: object
    events: object
    settings: object
    recovery: object
    analysis: object | None = None


def build_services(pool, workspace: Path) -> Services:
    projects = ProjectRepository(pool)
    tasks = TaskRepository(pool)
    backbone = ProjectBackboneService(projects, UnconfiguredScheduler())
    return Services(
        project_creator=CreateProjectService(projects, backbone), projects=projects, tasks=tasks,
        logs=TaskLogReader(workspace), events=ProjectEventWatcher(tasks, TaskLogReader(workspace)),
        settings=SettingsService(pool), recovery=backbone, analysis=AnalysisReader(workspace),
    )
