"""Behavioural tests for the minimal project backend."""

from __future__ import annotations

import asyncio
import importlib
import threading
from dataclasses import replace
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


def _record(identifier, project_id, name, finished_at=None, error=None):
    return SimpleNamespace(id=identifier, project_id=project_id, name=name, finished_at=finished_at, error=error)


def _execution_repositories(value, records):
    class Projects:
        def __init__(self): self.finished = {}
        async def get(self, identifier): return value if identifier == value.id else None
        async def finish(self, identifier, error): self.finished[identifier] = error
    class Tasks:
        def __init__(self): self.finished = []
        async def list_for_project(self, identifier): return [item for item in records if item.project_id == identifier]
        async def finish(self, identifier, error=None):
            self.finished.append((identifier, error))
            item = next(item for item in records if item.id == identifier)
            item.finished_at, item.error = NOW, error
    class Logs:
        def __init__(self): self.entries = []
        async def append(self, item, content): self.entries.append((item.id, content))
    return Projects(), Tasks(), Logs()


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
        backbone = MagicMock()
        service = CreateProjectService(repository, backbone)

        created = run(service.create("https://github.com/acme/demo.git", 2))

        assert created.id == 7
        repository.create_with_tasks.assert_awaited_once_with(
            "https://github.com/acme/demo.git", 2,
            ["repository clone", "LLVM toolchain preparation", "repository analysis"],
        )
        backbone.schedule.assert_called_once_with(7)

    def test_creation_returns_after_scheduler_failure_is_isolated(self) -> None:
        from backend.services.create_project import CreateProjectService
        from backend.services.run_project_backbone import ProjectBackboneService

        async def scenario():
            repository = AsyncMock()
            repository.create_with_tasks.return_value = project()
            scheduler = AsyncMock()
            scheduler.schedule.side_effect = RuntimeError("worker unavailable")
            backbone = ProjectBackboneService(AsyncMock(), scheduler)

            created = await CreateProjectService(repository, backbone).create("https://github.com/acme/demo.git", 2)
            await asyncio.sleep(0)

            assert created.id == 7
            scheduler.schedule.assert_awaited_once_with(7)

        run(scenario())

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
    @pytest.mark.parametrize("commit_sha", ["a" * 40, "B" * 64])
    def test_clone_uses_argv_and_records_resolved_commit(self, tmp_path: Path, commit_sha: str) -> None:
        from backend.services.clone_repository import CloneRepositoryService

        calls: list[list[str]] = []

        async def command(argv, cwd=None):
            calls.append(argv)
            if argv[1] == "rev-parse":
                return commit_sha
            return ""

        project_repository = AsyncMock()
        service = CloneRepositoryService(tmp_path, command, project_repository)

        run(service.clone(project()))

        assert calls[0] == ["git", "clone", "--", "https://github.com/acme/demo.git", str(tmp_path / "projects/7/repository")]
        project_repository.set_commit_sha.assert_awaited_once_with(7, commit_sha)

    def test_clone_rejects_workspace_symlink_escape(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService, UnsafeWorkspacePath

        (tmp_path / "projects").symlink_to(tmp_path.parent)
        with pytest.raises(UnsafeWorkspacePath):
            run(CloneRepositoryService(tmp_path, _empty_command, AsyncMock()).clone(project()))

    def test_clone_rejects_an_invalid_object_id_length(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService, GitCommandFailed

        async def command(argv, cwd=None):
            return "a" * 39 if argv[1] == "rev-parse" else ""

        with pytest.raises(GitCommandFailed):
            run(CloneRepositoryService(tmp_path, command, AsyncMock()).clone(project()))

    def test_default_command_terminates_and_waits_when_cancelled(self, monkeypatch) -> None:
        from backend.services.clone_repository import run_command

        class Process:
            returncode = None

            def __init__(self):
                self.terminated = False
                self.waited = False

            async def communicate(self):
                await asyncio.Future()

            def terminate(self):
                self.terminated = True

            async def wait(self):
                self.waited = True
                self.returncode = -15

            def kill(self):
                raise AssertionError("kill is not needed after a successful terminate")

        process = Process()

        async def create_subprocess_exec(*argv, **kwargs):
            assert argv == ("git", "rev-parse", "HEAD")
            assert "shell" not in kwargs
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)

        async def scenario():
            command = asyncio.create_task(run_command(["git", "rev-parse", "HEAD"]))
            await asyncio.sleep(0)
            command.cancel()
            with pytest.raises(asyncio.CancelledError):
                await command

        run(scenario())
        assert process.terminated is True
        assert process.waited is True


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

    def test_log_writer_rejects_ancestor_and_leaf_symlink_redirection(self, tmp_path: Path) -> None:
        from backend.services.stream_task_output import TaskLogWriter
        from backend.services.clone_repository import UnsafeWorkspacePath

        outside = tmp_path.parent / "outside.log"
        (tmp_path / "projects").symlink_to(tmp_path.parent)
        with pytest.raises(UnsafeWorkspacePath):
            run(TaskLogWriter(tmp_path).append(task(), "blocked\n"))
        assert not outside.exists()
        (tmp_path / "projects").unlink()
        logs = tmp_path / "projects/7/logs"
        logs.mkdir(parents=True)
        (logs / "11.log").symlink_to(outside)
        with pytest.raises(UnsafeWorkspacePath):
            run(TaskLogWriter(tmp_path).append(task(), "blocked\n"))
        assert not outside.exists()

    def test_sse_streams_do_not_consume_each_others_changes(self, tmp_path: Path) -> None:
        from backend.services.run_project_backbone import ProjectEventWatcher
        from backend.services.stream_task_output import TaskLogReader

        task_repository = AsyncMock()
        task_repository.list_for_project.return_value = [task()]
        logs = tmp_path / "projects/7/logs"
        logs.mkdir(parents=True)
        (logs / "11.log").write_text("one")
        watcher = ProjectEventWatcher(task_repository, TaskLogReader(tmp_path))

        async def scenario():
            first_subscriber = watcher.stream(7, poll_interval=0)
            second_subscriber = watcher.stream(7, poll_interval=0)
            assert await anext(first_subscriber) == "data: updated\n\n"
            assert await anext(second_subscriber) == "data: updated\n\n"
            (logs / "11.log").write_text("two")
            assert await anext(first_subscriber) == "data: updated\n\n"
            assert await anext(second_subscriber) == "data: updated\n\n"
            await first_subscriber.aclose()
            await second_subscriber.aclose()

        run(scenario())


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

    def test_post_projects_rejects_unrecognised_fields(self) -> None:
        from backend.api.app import create_app

        app = create_app(services=SimpleNamespace(project_creator=AsyncMock(), projects=AsyncMock(), tasks=AsyncMock(), logs=AsyncMock(), events=AsyncMock(), settings=AsyncMock(), recovery=AsyncMock()))

        with TestClient(app) as client:
            response = client.post("/api/projects", json={"repository_url": "https://github.com/acme/demo.git", "worker_count": 2, "unexpected": True})

        assert response.status_code == 422

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

    def test_asgi_repository_journey_uses_real_scheduler_logs_analysis_and_events(self, tmp_path: Path) -> None:
        """HTTP SSE is infinite, so this journey reads its real watcher directly."""
        import httpx
        from backend.api.app import create_app
        from backend.api.dependencies import Services
        from backend.models.project import Project
        from backend.models.task import Task
        from backend.services.create_project import CreateProjectService
        from backend.services.execute_project_backbone import ExecuteProjectBackbone
        from backend.services.read_analysis import AnalysisReader
        from backend.services.run_project_backbone import ProjectBackboneService, ProjectEventWatcher
        from backend.services.stream_task_output import TaskLogWriter

        class Projects:
            def __init__(self): self.items, self.next_id = {}, 1
            async def create_with_tasks(self, url, workers, names):
                identifier = self.next_id; self.next_id += 1
                item = Project(identifier, url, workers, None, NOW, None, None); self.items[identifier] = item
                await tasks.add(identifier, names); return item
            async def get(self, identifier): return self.items.get(identifier)
            async def list(self): return list(self.items.values())
            async def list_unfinished(self): return [item for item in self.items.values() if item.finished_at is None]
            async def set_commit_sha(self, identifier, sha): self.items[identifier] = replace(self.items[identifier], commit_sha=sha)
            async def finish(self, identifier, error=None): self.items[identifier] = replace(self.items[identifier], finished_at=NOW, error=error)
        class Tasks:
            def __init__(self): self.items, self.next_id = {}, 1
            async def add(self, project_id, names):
                for name in names:
                    identifier = self.next_id; self.next_id += 1
                    self.items[identifier] = Task(identifier, project_id, name, NOW, None, None)
            async def get(self, identifier): return self.items.get(identifier)
            async def list_for_project(self, project_id): return [item for item in self.items.values() if item.project_id == project_id]
            async def finish(self, identifier, error=None): self.items[identifier] = replace(self.items[identifier], finished_at=NOW, error=error)
        tasks, projects, completed = Tasks(), Projects(), asyncio.Event()
        logs = TaskLogWriter(tmp_path)
        class Clone:
            async def clone(self, value, clone_task):
                root = tmp_path / "projects" / str(value.id) / "repository"; root.mkdir(parents=True)
                (root / "main.c").write_text("int main(void) { return 0; }\n")
                await projects.set_commit_sha(value.id, "a" * 40); await logs.append(clone_task, "clone complete\n")
        class Toolchain:
            async def prepare(self, toolchain_task): await logs.append(toolchain_task, "toolchain ready\n")
        class Analysis:
            async def analyse(self, identifier, root):
                path = tmp_path / "projects" / str(identifier) / "analysis"; path.mkdir(parents=True)
                (path / "repository.md").write_text("repository analysis\n"); completed.set()
        executor = ExecuteProjectBackbone(projects, tasks, Clone(), Toolchain(), Analysis(), logs, tmp_path)
        backbone = ProjectBackboneService(projects, executor)
        services = Services(CreateProjectService(projects, backbone), projects, tasks, logs,
                            ProjectEventWatcher(tasks, logs), SimpleNamespace(check=lambda: {}), backbone, AnalysisReader(tmp_path))
        app = create_app(services=services)
        async def scenario():
            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.post("/api/projects", json={"repository_url": "https://github.com/acme/demo.git", "worker_count": 1})
                    assert response.status_code == 202 and len(tasks.items) == 3
                    await asyncio.wait_for(completed.wait(), 1)
                    project_id = response.json()["id"]
                    listed = await client.get(f"/api/projects/{project_id}/tasks")
                    assert len(listed.json()) == 3 and all(item["finished_at"] for item in listed.json())
                    clone_id = next(item.id for item in tasks.items.values() if item.name == "repository clone")
                    log = await client.get(f"/api/tasks/{clone_id}/log")
                    assert log.json()["content"] == "clone complete\n" and log.json()["next_offset"] == 15
                    analysis = await client.get(f"/api/projects/{project_id}/analysis")
                    assert analysis.json() == {"content": "repository analysis\n"}
                    events = services.events.stream(int(project_id), poll_interval=0)
                    assert await anext(events) == "data: updated\n\n"
                    await logs.append(next(item for item in tasks.items.values() if item.name == "LLVM toolchain preparation"), "updated\n")
                    assert await asyncio.wait_for(anext(events), 1) == "data: updated\n\n"
                    await events.aclose()
        run(scenario())


class TestRecovery:
    def test_recovery_schedules_each_unfinished_project_without_claiming_success(self) -> None:
        from backend.services.run_project_backbone import ProjectBackboneService

        projects = AsyncMock()
        projects.list_unfinished.return_value = [project(1), project(2)]
        scheduler = AsyncMock()
        service = ProjectBackboneService(projects, scheduler)

        async def scenario():
            await service.recover()
            await asyncio.sleep(0)

        run(scenario())
        assert scheduler.schedule.await_args_list == [((1,),), ((2,),)]

    def test_lifespan_closes_pool_when_recovery_raises(self, monkeypatch) -> None:
        app_module = importlib.import_module("backend.api.app")
        pool = AsyncMock()
        services = SimpleNamespace(recovery=AsyncMock(), close=AsyncMock())
        services.recovery.recover.side_effect = RuntimeError("database recovery failed")

        async def create_pool():
            return pool

        monkeypatch.setattr(app_module, "create_pool", create_pool)
        monkeypatch.setattr(app_module, "build_services", lambda *_: services)
        app = app_module.create_app()

        async def scenario():
            with pytest.raises(RuntimeError, match="database recovery failed"):
                async with app.router.lifespan_context(app):
                    pass

        run(scenario())
        services.close.assert_awaited_once_with()
        pool.close.assert_awaited_once_with()


class TestRuntimeContracts:
    def test_production_graph_uses_real_executor_workflow_and_deferred_docker(self, tmp_path: Path) -> None:
        from backend.api.dependencies import build_services
        from backend.agents.workflow import RepositoryAnalysisWorkflow
        from backend.fuzzing.toolchain.deferred import DeferredToolchain
        from backend.services.execute_project_backbone import ExecuteProjectBackbone

        services = build_services(AsyncMock(), tmp_path)
        executor = services.recovery._scheduler
        assert isinstance(executor, ExecuteProjectBackbone)
        assert isinstance(executor._analysis, RepositoryAnalysisWorkflow)
        assert isinstance(executor._toolchain, DeferredToolchain)

    def test_deferred_docker_checks_close_the_connected_sdk_client(self, tmp_path: Path) -> None:
        from backend.fuzzing.toolchain.deferred import DeferredToolchain

        class Client:
            def __init__(self):
                self.closed = 0
                self.api = SimpleNamespace(inspect_image=lambda tag: {"Id": "sha256:ready", "Os": "linux", "Architecture": "amd64"})
            def close(self): self.closed += 1
        client = Client()
        docker = SimpleNamespace(connect=lambda: client)
        toolchain = DeferredToolchain(tmp_path / "Dockerfile", SimpleNamespace(), docker)
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:24.04\n")

        async def scenario():
            assert await toolchain.docker_available() is True
            assert await toolchain.toolchain_available() is True
        run(scenario())
        assert client.closed == 2

    def test_cancelled_connect_closes_client_only_after_connecting_thread_stops(self, tmp_path: Path) -> None:
        from backend.fuzzing.toolchain.deferred import DeferredToolchain

        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        client = SimpleNamespace(close=closed.set)
        class Docker:
            def connect(self):
                entered.set(); release.wait(1); return client
        toolchain = DeferredToolchain(tmp_path / "Dockerfile", SimpleNamespace(), Docker())

        async def scenario():
            running = asyncio.create_task(toolchain.prepare(task()))
            assert await asyncio.to_thread(entered.wait, 1)
            running.cancel()
            with pytest.raises(asyncio.CancelledError): await running
            assert not closed.is_set()
            release.set()
            assert await asyncio.to_thread(closed.wait, 1)
        run(scenario())


class TestProjectExecution:
    def test_clone_and_toolchain_overlap_and_analysis_waits_only_for_clone(self, tmp_path: Path) -> None:
        from backend.services.execute_project_backbone import ExecuteProjectBackbone

        clone_started, toolchain_started = asyncio.Event(), asyncio.Event()
        release_clone, release_toolchain = asyncio.Event(), asyncio.Event()
        analysed = asyncio.Event()
        clone_task = task(11, name="repository clone")
        toolchain_task = task(12, name="LLVM toolchain preparation")
        analysis_task = task(13, name="repository analysis")
        projects, tasks = AsyncMock(), AsyncMock()
        projects.get.return_value = project()
        tasks.list_for_project.return_value = [clone_task, toolchain_task, analysis_task]

        class Clone:
            async def clone(self, value, clone_task):
                clone_started.set()
                await release_clone.wait()
                return "a" * 40

        class Toolchain:
            async def prepare(self, value):
                toolchain_started.set()
                await release_toolchain.wait()

        class Analysis:
            async def analyse(self, project_id, root):
                assert root == tmp_path / "projects/7/repository"
                assert toolchain_started.is_set()
                analysed.set()

        executor = ExecuteProjectBackbone(projects, tasks, Clone(), Toolchain(), Analysis(), AsyncMock(), tmp_path)

        async def scenario():
            running = asyncio.create_task(executor.schedule(7))
            await asyncio.wait_for(asyncio.gather(clone_started.wait(), toolchain_started.wait()), 1)
            assert not analysed.is_set()
            release_clone.set()
            await asyncio.wait_for(analysed.wait(), 1)
            assert not release_toolchain.is_set()
            release_toolchain.set()
            await running

        run(scenario())
        assert tasks.finish.await_args_list == [((11,),), ((13,),), ((12,),)]

    def test_failure_is_logged_and_aggregated_after_all_tasks_are_terminal(self, tmp_path: Path) -> None:
        from backend.services.execute_project_backbone import ExecuteProjectBackbone

        records = [_record(11, 7, "repository clone"), _record(12, 7, "LLVM toolchain preparation"), _record(13, 7, "repository analysis")]
        projects, tasks, logs = _execution_repositories(project(), records)

        class Clone:
            async def clone(self, value, clone_task): raise RuntimeError("remote rejected clone")
        class Toolchain:
            async def prepare(self, value): raise RuntimeError("Docker is unavailable")
        class Analysis: pass

        run(ExecuteProjectBackbone(projects, tasks, Clone(), Toolchain(), Analysis(), logs, tmp_path).schedule(7))

        assert {entry[1] for entry in logs.entries} == {"remote rejected clone\n", "repository clone did not complete\n", "Docker is unavailable\n"}
        assert all(item.finished_at is not None for item in records)
        assert records[0].error == "remote rejected clone"
        assert records[1].error == "Docker is unavailable"
        assert records[2].error == "repository clone did not complete"
        assert "repository clone: remote rejected clone" in projects.finished[7]

    def test_cancellation_does_not_finish_tasks_or_project(self, tmp_path: Path) -> None:
        from backend.services.execute_project_backbone import ExecuteProjectBackbone

        records = [_record(11, 7, "repository clone"), _record(12, 7, "LLVM toolchain preparation"), _record(13, 7, "repository analysis")]
        projects, tasks, logs = _execution_repositories(project(), records)
        started = asyncio.Event()
        class Clone:
            async def clone(self, value, clone_task):
                started.set(); await asyncio.Future()
        class Toolchain:
            async def prepare(self, value): await asyncio.Future()

        async def scenario():
            running = asyncio.create_task(ExecuteProjectBackbone(projects, tasks, Clone(), Toolchain(), SimpleNamespace(), logs, tmp_path).schedule(7))
            await started.wait(); running.cancel()
            with pytest.raises(asyncio.CancelledError): await running
        run(scenario())
        assert not tasks.finished and not projects.finished

    def test_committed_clone_is_recovered_without_recloning(self, tmp_path: Path) -> None:
        from backend.services.execute_project_backbone import ExecuteProjectBackbone

        recovered = project()
        recovered = type(recovered)(recovered.id, recovered.repository_url, recovered.worker_count, "a" * 40, recovered.created_at, None, None)
        records = [_record(11, 7, "repository clone"), _record(12, 7, "LLVM toolchain preparation", finished_at=NOW), _record(13, 7, "repository analysis", finished_at=NOW)]
        projects, tasks, logs = _execution_repositories(recovered, records)
        clone = SimpleNamespace(verify_committed=AsyncMock(return_value=True), clone=AsyncMock())
        run(ExecuteProjectBackbone(projects, tasks, clone, SimpleNamespace(prepare=AsyncMock()), SimpleNamespace(), logs, tmp_path).schedule(7))
        clone.verify_committed.assert_awaited_once_with(recovered)
        clone.clone.assert_not_called()
        assert records[0].finished_at is not None and records[0].error is None

    def test_projects_execute_independently_when_one_clone_fails(self, tmp_path: Path) -> None:
        from backend.services.execute_project_backbone import ExecuteProjectBackbone

        first = type(project())(1, "https://github.com/acme/one.git", 1, None, NOW, None, None)
        second = type(project())(2, "https://github.com/acme/two.git", 1, None, NOW, None, None)
        first_records = [_record(11, 1, "repository clone"), _record(12, 1, "LLVM toolchain preparation"), _record(13, 1, "repository analysis")]
        second_records = [_record(21, 2, "repository clone"), _record(22, 2, "LLVM toolchain preparation"), _record(23, 2, "repository analysis")]
        first_projects, first_tasks, first_logs = _execution_repositories(first, first_records)
        second_projects, second_tasks, second_logs = _execution_repositories(second, second_records)
        second_started, release_second = asyncio.Event(), asyncio.Event()
        class FailingClone:
            async def clone(self, value, clone_task): raise RuntimeError("first clone failed")
        class WaitingClone:
            async def clone(self, value, clone_task): second_started.set(); await release_second.wait()
        class Toolchain:
            async def prepare(self, value): return None
        class Analysis:
            async def analyse(self, project_id, root): return None

        async def scenario():
            failed = asyncio.create_task(ExecuteProjectBackbone(first_projects, first_tasks, FailingClone(), Toolchain(), Analysis(), first_logs, tmp_path).schedule(1))
            healthy = asyncio.create_task(ExecuteProjectBackbone(second_projects, second_tasks, WaitingClone(), Toolchain(), Analysis(), second_logs, tmp_path).schedule(2))
            await second_started.wait()
            await failed
            assert not healthy.done()
            release_second.set()
            await healthy
        run(scenario())
        assert first_projects.finished[1] is not None
        assert second_projects.finished[2] is None


async def _empty_command(*args, **kwargs):
    return ""
