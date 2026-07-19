"""Behavioural tests for the minimal project backend."""

from __future__ import annotations

import asyncio
import warnings
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")

from starlette.testclient import TestClient


NOW = datetime(2026, 7, 19, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


def project(identifier: int = 7):
    from backend.models.project import Project

    return Project(identifier, "https://github.com/acme/demo.git", 2, None, NOW, None, None)


def task(identifier: int = 11, project_id: int = 7, name: str = "repository clone"):
    from backend.models.task import Task

    return Task(identifier, project_id, name, NOW, None, None)


class TestProjectRepository:
    def test_create_with_tasks_uses_one_transaction_and_explicit_columns(self) -> None:
        from backend.repositories.project_repository import ProjectRepository

        connection = AsyncMock()
        connection.transaction = MagicMock(return_value=_Transaction())
        connection.fetchrow.side_effect = [
            {"id": 7, "repository_url": "https://github.com/acme/demo.git", "worker_count": 2, "commit_sha": None, "created_at": NOW, "finished_at": None, "error": None},
        ]
        pool = SimpleNamespace(acquire=lambda: _Acquire(connection))

        created = run(ProjectRepository(pool).create_with_tasks("https://github.com/acme/demo.git", 2, ["repository clone"]))

        assert created.id == 7
        connection.transaction.assert_called_once_with()
        queries = "\n".join(call.args[0] for call in connection.fetchrow.call_args_list + connection.execute.call_args_list)
        assert "INSERT INTO projects (repository_url, worker_count)" in queries
        assert "INSERT INTO tasks (project_id, name)" in queries
        assert "$1" in queries and "$2" in queries

    def test_project_and_task_lookups_use_parameterized_queries(self) -> None:
        from backend.repositories.project_repository import ProjectRepository
        from backend.repositories.task_repository import TaskRepository

        pool = AsyncMock()
        pool.fetchrow.return_value = {"id": 7, "repository_url": "https://github.com/acme/demo.git", "worker_count": 2, "commit_sha": None, "created_at": NOW, "finished_at": None, "error": None}
        ProjectRepository(pool).get
        assert run(ProjectRepository(pool).get(7)).id == 7
        assert "$1" in pool.fetchrow.call_args.args[0]
        pool.fetchrow.return_value = {"id": 11, "project_id": 7, "name": "repository clone", "created_at": NOW, "finished_at": None, "error": None}
        assert run(TaskRepository(pool).get(11)).id == 11
        assert "$1" in pool.fetchrow.call_args.args[0]


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *args):
        return False


class TestProjectCreation:
    def test_creation_validates_url_creates_expected_tasks_and_schedules_backbone(self) -> None:
        from backend.services.create_project import CreateProjectService

        repository = AsyncMock()
        repository.create_with_tasks.return_value = project()
        backbone = AsyncMock()
        service = CreateProjectService(repository, backbone)

        created = run(service.create("https://github.com/acme/demo.git", 2))

        assert created.id == 7
        repository.create_with_tasks.assert_awaited_once_with(
            "https://github.com/acme/demo.git", 2,
            ["repository clone", "LLVM toolchain preparation", "repository analysis"],
        )
        backbone.schedule.assert_awaited_once_with(7)

    @pytest.mark.parametrize("url", [
        "file:///tmp/repository", "https://user:password@example.com/repository.git",
        "https://github.com/acme/repository.git --upload-pack=x",
        "ssh://git@example.com/acme/repository.git", "/tmp/repository",
    ])
    def test_creation_rejects_unsafe_repository_urls(self, url: str) -> None:
        from backend.services.create_project import CreateProjectService, InvalidRepositoryUrl

        with pytest.raises(InvalidRepositoryUrl):
            run(CreateProjectService(AsyncMock(), AsyncMock()).create(url, 1))


class TestCloneRepository:
    def test_clone_uses_argv_and_records_resolved_commit(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService

        calls: list[list[str]] = []

        def command(argv, cwd=None):
            calls.append(argv)
            if argv[1] == "rev-parse":
                return "a" * 40
            return ""

        project_repository = AsyncMock()
        service = CloneRepositoryService(tmp_path, command, project_repository)

        run(service.clone(project()))

        assert calls[0] == ["git", "clone", "--", "https://github.com/acme/demo.git", str(tmp_path / "projects/7/repository")]
        project_repository.set_commit_sha.assert_awaited_once_with(7, "a" * 40)

    def test_clone_rejects_workspace_symlink_escape(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService, UnsafeWorkspacePath

        (tmp_path / "projects").symlink_to(tmp_path.parent)
        with pytest.raises(UnsafeWorkspacePath):
            run(CloneRepositoryService(tmp_path, lambda *_: "", AsyncMock()).clone(project()))


class TestLogAndSse:
    def test_log_reader_uses_non_negative_offset_and_derived_path(self, tmp_path: Path) -> None:
        from backend.services.stream_task_output import TaskLogReader

        path = tmp_path / "projects/7/logs"
        path.mkdir(parents=True)
        (path / "11.log").write_bytes(b"first\nsecond\n")
        reader = TaskLogReader(tmp_path)

        assert run(reader.read(task(), 6)).content == "second\n"
        assert run(reader.read(task(), 6)).next_offset == 13
        with pytest.raises(ValueError):
            run(reader.read(task(), -1))

    def test_log_reader_rejects_a_symlink_escape(self, tmp_path: Path) -> None:
        from backend.services.stream_task_output import TaskLogReader, UnsafeWorkspacePath

        logs = tmp_path / "projects/7/logs"
        logs.mkdir(parents=True)
        (logs / "11.log").symlink_to(tmp_path.parent / "outside.log")
        with pytest.raises(UnsafeWorkspacePath):
            run(TaskLogReader(tmp_path).read(task(), 0))

    def test_sse_emits_only_when_task_or_log_state_changes(self, tmp_path: Path) -> None:
        from backend.services.run_project_backbone import ProjectEventWatcher
        from backend.services.stream_task_output import TaskLogReader

        task_repository = AsyncMock()
        task_repository.list_for_project.return_value = [task()]
        logs = tmp_path / "projects/7/logs"
        logs.mkdir(parents=True)
        (logs / "11.log").write_text("one")
        watcher = ProjectEventWatcher(task_repository, TaskLogReader(tmp_path))

        first = run(watcher.changed(7))
        second = run(watcher.changed(7))
        (logs / "11.log").write_text("two")
        third = run(watcher.changed(7))

        assert first is True
        assert second is False
        assert third is True
        assert ProjectEventWatcher.frame() == "data: updated\n\n"


class TestApi:
    def test_post_projects_returns_202_and_string_identifier(self) -> None:
        from backend.api.app import create_app

        creator = AsyncMock()
        creator.create.return_value = project()
        app = create_app(services=SimpleNamespace(project_creator=creator, projects=AsyncMock(), tasks=AsyncMock(), logs=AsyncMock(), events=AsyncMock(), settings=AsyncMock(), recovery=AsyncMock()))

        with TestClient(app) as client:
            response = client.post("/api/projects", json={"repository_url": "https://github.com/acme/demo.git", "worker_count": 2})

        assert response.status_code == 202
        assert response.json()["id"] == "7"
        creator.create.assert_awaited_once_with("https://github.com/acme/demo.git", 2)

    def test_api_returns_truthful_not_ready_and_missing_resource_responses(self) -> None:
        from backend.api.app import create_app
        from backend.services.run_project_backbone import AnalysisNotReady

        projects = AsyncMock()
        projects.get.side_effect = [None, project()]
        analysis = AsyncMock()
        analysis.get.side_effect = AnalysisNotReady()
        app = create_app(services=SimpleNamespace(project_creator=AsyncMock(), projects=projects, tasks=AsyncMock(), logs=AsyncMock(), events=AsyncMock(), settings=AsyncMock(), recovery=AsyncMock(), analysis=analysis))

        with TestClient(app) as client:
            assert client.get("/api/projects/999").status_code == 404
            assert client.get("/api/projects/7/analysis").status_code == 409

    def test_settings_are_injected_and_never_expose_values(self) -> None:
        from backend.api.app import create_app

        settings = AsyncMock()
        settings.check.return_value = {"database": True, "docker": False, "openai_api_key_present": True, "toolchain": False}
        app = create_app(services=SimpleNamespace(project_creator=AsyncMock(), projects=AsyncMock(), tasks=AsyncMock(), logs=AsyncMock(), events=AsyncMock(), settings=settings, recovery=AsyncMock()))

        with TestClient(app) as client:
            response = client.get("/api/settings")

        assert response.json() == {"database": True, "docker": False, "openai_api_key_present": True, "toolchain": False}


class TestRecovery:
    def test_recovery_schedules_each_unfinished_project_without_claiming_success(self) -> None:
        from backend.services.run_project_backbone import ProjectBackboneService

        projects = AsyncMock()
        projects.list_unfinished.return_value = [project(1), project(2)]
        scheduler = AsyncMock()
        service = ProjectBackboneService(projects, scheduler)

        run(service.recover())

        assert scheduler.schedule.await_args_list == [((1,),), ((2,),)]
