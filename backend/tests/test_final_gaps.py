"""Regression contracts for final lifecycle bounds and truthful state."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


def run(awaitable):
    return asyncio.run(awaitable)


def project(commit_sha=None):
    return SimpleNamespace(id=7, repository_url="https://github.com/acme/demo.git", commit_sha=commit_sha,
                           worker_count=1, created_at=datetime.now(timezone.utc), finished_at=None, error=None)


def task():
    return SimpleNamespace(id=11, project_id=7, finished_at=None, error=None)


class TestAtomicClone:
    def test_absent_published_destination_has_no_recovery_so_initial_clone_can_proceed(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService

        service = CloneRepositoryService(tmp_path, AsyncMock(), AsyncMock())
        assert run(service.recover_published(project())) is None

    def test_clone_publishes_only_after_staging_head_is_valid(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService

        calls = []
        async def command(argv, cwd=None, sink=None):
            calls.append((argv, cwd))
            if argv[1] == "clone":
                destination = Path(argv[-1]); destination.mkdir(parents=True); (destination / ".git").mkdir()
            return "a" * 40 if argv[1] == "rev-parse" else ""
        projects = AsyncMock()
        run(CloneRepositoryService(tmp_path, command, projects).clone(project()))
        final = tmp_path / "projects/7/repository"
        assert final.is_dir() and not (tmp_path / "projects/7/repository.clone").exists()
        assert calls[0][0][-1] == str(tmp_path / "projects/7/repository.clone")
        projects.set_commit_sha.assert_awaited_once_with(7, "a" * 40)

    def test_clone_failure_cleans_only_internal_staging_and_preserves_final(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService, GitCommandFailed

        final = tmp_path / "projects/7/repository"; final.mkdir(parents=True); (final / "keep").write_text("keep")
        with pytest.raises(GitCommandFailed):
            run(CloneRepositoryService(tmp_path, AsyncMock(side_effect=GitCommandFailed("bad")), AsyncMock()).clone(project()))
        assert (final / "keep").read_text() == "keep"
        assert not (tmp_path / "projects/7/repository.clone").exists()

    def test_recovery_adopts_published_git_when_commit_was_not_persisted(self, tmp_path: Path) -> None:
        from backend.services.clone_repository import CloneRepositoryService
        final = tmp_path / "projects/7/repository"; (final / ".git").mkdir(parents=True)
        projects = AsyncMock()
        async def command(argv, cwd=None, sink=None): return "b" * 40
        service = CloneRepositoryService(tmp_path, command, projects)
        assert run(service.recover_published(project())) == "b" * 40
        projects.set_commit_sha.assert_awaited_once_with(7, "b" * 40)


class TestBoundedGitAndLogs:
    def test_git_spawns_noninteractive_with_finite_timeout(self, monkeypatch) -> None:
        from backend.services.clone_repository import GIT_COMMAND_TIMEOUT_SECONDS, run_command
        seen = {}
        class Process:
            returncode = 0
            async def communicate(self): return (b"ok", b"")
        async def spawn(*argv, **kwargs): seen.update(kwargs); return Process()
        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        assert run(run_command(["git", "rev-parse", "HEAD"])) == "ok"
        assert seen["stdin"] is asyncio.subprocess.DEVNULL
        assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0" and seen["env"]["GIT_ASKPASS"]
        assert GIT_COMMAND_TIMEOUT_SECONDS > 0

    def test_log_reader_reads_a_bounded_chunk_from_offset(self, tmp_path: Path) -> None:
        from backend.services.stream_task_output import TASK_LOG_CHUNK_BYTES, TaskLogReader
        path = tmp_path / "projects/7/logs"; path.mkdir(parents=True); (path / "11.log").write_bytes(b"x" * (TASK_LOG_CHUNK_BYTES + 3))
        result = run(TaskLogReader(tmp_path).read(task(), 2))
        assert len(result.content) == TASK_LOG_CHUNK_BYTES and result.next_offset == 2 + TASK_LOG_CHUNK_BYTES

    def test_log_reader_completes_utf8_codepoint_split_at_byte_chunk_boundary(self, tmp_path: Path) -> None:
        from backend.services.stream_task_output import TASK_LOG_CHUNK_BYTES, TaskLogReader
        prefix = "a" * (TASK_LOG_CHUNK_BYTES - 1)
        expected = f"{prefix}€tail"
        path = tmp_path / "projects/7/logs"; path.mkdir(parents=True); (path / "11.log").write_text(expected)
        reader = TaskLogReader(tmp_path)
        first = run(reader.read(task(), 0))
        second = run(reader.read(task(), first.next_offset))
        assert first.next_offset > TASK_LOG_CHUNK_BYTES
        assert first.content + second.content == expected
        assert "\ufffd" not in first.content + second.content

    def test_log_writer_refuses_growth_past_cap(self, tmp_path: Path, monkeypatch) -> None:
        from backend.services.stream_task_output import TaskLogLimitExceeded, TaskLogWriter
        monkeypatch.setattr("backend.services.stream_task_output.TASK_LOG_MAX_BYTES", 4)
        writer = TaskLogWriter(tmp_path)
        writer.append_sync(task(), "four")
        with pytest.raises(TaskLogLimitExceeded): writer.append_sync(task(), "x")


class TestDockerBounds:
    def test_deferred_cancellation_cancels_owned_operation_before_closing_client(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.client import DOCKER_REQUEST_TIMEOUT_SECONDS
        from backend.fuzzing.toolchain.deferred import CANCELLATION_CLEANUP_TIMEOUT_SECONDS, DeferredToolchain

        entered, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        client = SimpleNamespace(close=lambda: None)
        toolchain = DeferredToolchain(tmp_path / "Dockerfile", SimpleNamespace(), SimpleNamespace(connect=lambda: client))
        async def operation(_client):
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise
        async def scenario():
            running = asyncio.create_task(toolchain._with_client(operation))
            await entered.wait()
            running.cancel()
            await asyncio.sleep(0)
            release.set()
            with pytest.raises(asyncio.CancelledError): await running
        run(scenario())
        assert cancelled.is_set()
        assert DOCKER_REQUEST_TIMEOUT_SECONDS < CANCELLATION_CLEANUP_TIMEOUT_SECONDS < DOCKER_REQUEST_TIMEOUT_SECONDS + 5

    def test_connect_closes_created_client_when_ping_fails_and_uses_timeout(self) -> None:
        from backend.fuzzing.docker.client import DOCKER_REQUEST_TIMEOUT_SECONDS, DockerClient, DockerUnavailable
        class DockerException(Exception): pass
        client = SimpleNamespace(close=Mock(), ping=lambda: (_ for _ in ()).throw(DockerException("no")))
        module = SimpleNamespace(from_env=lambda **kwargs: (setattr(module, "kwargs", kwargs) or client), errors=SimpleNamespace(DockerException=DockerException))
        with pytest.raises(DockerUnavailable): DockerClient(module).connect()
        client.close.assert_called_once_with()
        assert module.kwargs["timeout"] == DOCKER_REQUEST_TIMEOUT_SECONDS

    def test_connect_closes_client_for_unexpected_post_creation_error(self) -> None:
        from backend.fuzzing.docker.client import DockerClient
        class DockerException(Exception): pass
        closed = []
        client = SimpleNamespace(close=lambda: closed.append(True), ping=lambda: (_ for _ in ()).throw(ValueError("bug")))
        module = SimpleNamespace(from_env=lambda **kwargs: client, errors=SimpleNamespace(DockerException=DockerException))
        with pytest.raises(ValueError, match="bug"):
            DockerClient(module).connect()
        assert closed == [True]

    def test_settings_classifies_bounded_verifier_timeout_as_unavailable(self, tmp_path: Path) -> None:
        from backend.fuzzing.toolchain.deferred import DeferredToolchain
        class Container:
            id = "probe"
            def start(self): pass
            def wait(self, timeout): raise TimeoutError()
            def stop(self, timeout=0): pass
            def kill(self): pass
            def remove(self, force=True): pass
        client = SimpleNamespace(
            close=lambda: None,
            api=SimpleNamespace(inspect_image=lambda tag: {"Id": "sha256:ready", "Os": "linux", "Architecture": "amd64"}),
            containers=SimpleNamespace(create=lambda *args, **kwargs: Container()),
        )
        dockerfile = tmp_path / "Dockerfile"; dockerfile.write_text("FROM scratch")
        toolchain = DeferredToolchain(dockerfile, SimpleNamespace(), SimpleNamespace(connect=lambda: client))
        assert run(toolchain.toolchain_available()) is False

    def test_image_builder_stops_and_closes_stream_at_log_budget(self, tmp_path: Path, monkeypatch) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuildLogLimitExceeded, ImageBuilder
        monkeypatch.setattr("backend.fuzzing.docker.image_builder.IMAGE_BUILD_LOG_MAX_BYTES", 4)
        class Stream:
            closed = False
            def __iter__(self): return iter(({"stream": "large"},))
            def close(self): self.closed = True
        stream = Stream()
        api = SimpleNamespace(build=lambda **kwargs: stream)
        dockerfile = tmp_path / "Dockerfile"; dockerfile.write_text("FROM scratch")
        with pytest.raises(ImageBuildLogLimitExceeded): ImageBuilder(SimpleNamespace(api=api)).build(dockerfile, "x", lambda text: None)
        assert stream.closed


class TestProjectEventState:
    def test_snapshot_includes_project_fields_even_without_task_change(self, tmp_path: Path) -> None:
        from backend.services.run_project_backbone import ProjectEventWatcher
        projects = AsyncMock(); projects.get.return_value = project()
        tasks = AsyncMock(); tasks.list_for_project.return_value = []
        snapshot = run(ProjectEventWatcher(tasks, SimpleNamespace(), projects).snapshot(7))
        assert snapshot[0] == (None, None, None)


class TestTerminalPersistence:
    def test_task_log_limit_does_not_block_task_terminal_error_persistence(self, tmp_path: Path) -> None:
        from backend.services.execute_project_backbone import ExecuteProjectBackbone
        from backend.services.stream_task_output import TaskLogLimitExceeded
        tasks = SimpleNamespace(finish=AsyncMock())
        executor = ExecuteProjectBackbone(SimpleNamespace(), tasks, SimpleNamespace(), SimpleNamespace(), SimpleNamespace(),
                                          SimpleNamespace(append=AsyncMock(side_effect=TaskLogLimitExceeded("full"))), tmp_path)
        run(executor._fail(task(), RuntimeError("capability failed")))
        tasks.finish.assert_awaited_once_with(11, "capability failed")
