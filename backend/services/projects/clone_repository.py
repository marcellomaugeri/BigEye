"""Contained, argv-only repository cloning."""

import asyncio
import os
import re
import shutil
from pathlib import Path

from backend.services.projects.create_project import validate_repository_url


class UnsafeWorkspacePath(ValueError):
    """Raised when a derived workspace path leaves its project directory."""


def contained_path(workspace: Path, *parts: str) -> Path:
    root = workspace.resolve(strict=False)
    candidate = workspace.joinpath(*parts)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise UnsafeWorkspacePath("workspace path escapes the configured workspace") from error
    return candidate


class GitCommandFailed(RuntimeError):
    """Raised when Git fails without exposing command output to callers."""


MAX_GIT_OUTPUT_BYTES = 1_048_576
GIT_COMMAND_TIMEOUT_SECONDS = 60


class GitCommandTimedOut(RuntimeError):
    """Raised when a Git child exceeds its bounded command lifetime."""


async def _stop_process(process, drains=()) -> None:
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError:
        process.kill()
        await process.wait()
    for drain_task in drains:
        drain_task.cancel()
    if drains:
        await asyncio.gather(*drains, return_exceptions=True)


async def run_command(argv: list[str], cwd: Path | None = None, sink=None, env: dict[str, str] | None = None) -> str:
    """Run a Git argv list and clean up the child process on cancellation."""
    process = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd) if cwd is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", **(env or {})},
    )
    if not hasattr(process, "stdout"):
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=GIT_COMMAND_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            await _stop_process(process)
            raise
        except TimeoutError as error:
            await _stop_process(process)
            raise GitCommandTimedOut("Git command timed out") from error
        if process.returncode != 0:
            raise GitCommandFailed("Git command failed")
        return stdout.decode("utf-8", errors="replace").strip()
    stdout = bytearray()
    output_size = 0
    truncated = False

    async def drain(reader, keep_stdout: bool) -> None:
        nonlocal output_size, truncated
        while chunk := await reader.read(65536):
            remaining = MAX_GIT_OUTPUT_BYTES - output_size
            allowed = chunk[:max(remaining, 0)]
            output_size += len(allowed)
            if keep_stdout:
                stdout.extend(allowed)
            if sink is not None and allowed:
                sink(allowed.decode("utf-8", errors="replace"))
            if len(allowed) != len(chunk) and not truncated:
                truncated = True
                if sink is not None:
                    sink("Git output exceeded 1048576 bytes and was truncated\n")
    drains = (asyncio.create_task(drain(process.stdout, True)), asyncio.create_task(drain(process.stderr, False)))
    wait = asyncio.create_task(process.wait())
    try:
        await asyncio.wait_for(asyncio.gather(*drains, wait), timeout=GIT_COMMAND_TIMEOUT_SECONDS)
    except asyncio.CancelledError:
        await _stop_process(process, drains)
        raise
    except TimeoutError as error:
        await _stop_process(process, drains)
        raise GitCommandTimedOut("Git command timed out") from error
    except BaseException:
        await _stop_process(process, drains)
        raise
    if truncated:
        raise GitCommandFailed("Git output exceeded 1048576 bytes")
    if process.returncode != 0:
        raise GitCommandFailed("Git command failed")
    return bytes(stdout).decode("utf-8", errors="replace").strip()


class CloneRepositoryService:
    def __init__(self, workspace: Path, command=run_command, projects=None, logs=None):
        self._workspace = workspace
        self._command = command
        self._projects = projects
        self._logs = logs

    async def clone(self, project, task=None) -> str:
        repository_url = validate_repository_url(project.repository_url)
        destination = contained_path(self._workspace, "projects", str(project.id), "repository")
        staging = contained_path(self._workspace, "projects", str(project.id), "repository.clone")
        project_root = contained_path(self._workspace, "projects", str(project.id))
        project_root.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            if project.commit_sha is None:
                recovered = await self.recover_published(project, task)
                if recovered is not None:
                    return recovered
            raise UnsafeWorkspacePath("repository destination already exists")
        self._remove_staging(staging, project_root)
        kwargs = {}
        token = None
        if project.token_present:
            token = await self._projects.get_repository_token(project.id) or None
            if token:
                kwargs["env"] = {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "http.extraHeader",
                    "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {token}",
                }
        if self._logs is not None and task is not None:
            kwargs["sink"] = self._task_log_sink(task, token)
        try:
            await self._run_command(["git", "clone", "--", repository_url, str(staging)], kwargs)
            await self._run_command(["git", "checkout", "--detach", project.requested_revision], kwargs, staging)
            commit_sha = await self._head(staging, kwargs)
            os.replace(staging, destination)
            await self._projects.set_commit_sha(project.id, commit_sha)
            return commit_sha
        except BaseException:
            self._remove_staging(staging, project_root)
            raise

    @staticmethod
    def _remove_staging(staging: Path, project_root: Path) -> None:
        if not (staging.exists() or staging.is_symlink()):
            return
        if staging.is_symlink() or not staging.is_dir() or staging.parent.resolve(strict=True) != project_root.resolve(strict=True):
            raise UnsafeWorkspacePath("repository staging directory is unsafe")
        shutil.rmtree(staging)

    def _task_log_sink(self, task, token: str | None):
        if token is None:
            return lambda text: self._logs.append_sync(task, text)
        output = []

        def sink(text: str) -> None:
            output.append(text)

        def flush() -> None:
            if output:
                self._logs.append_sync(task, "".join(output).replace(token, "[REDACTED]"))
                output.clear()

        sink.flush = flush
        return sink

    async def _run_command(self, argv: list[str], kwargs, cwd: Path | None = None) -> str:
        try:
            return await self._command(argv, cwd=cwd, **kwargs)
        finally:
            sink = kwargs.get("sink")
            flush = getattr(sink, "flush", None)
            if flush is not None:
                flush()

    async def _head(self, destination: Path, kwargs) -> str:
        commit_sha = await self._run_command(["git", "rev-parse", "HEAD"], kwargs, destination)
        if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit_sha) is None:
            raise GitCommandFailed("Git did not return a full object ID")
        return commit_sha

    async def recover_published(self, project, task=None) -> str | None:
        destination = contained_path(self._workspace, "projects", str(project.id), "repository")
        if not destination.exists() and not destination.is_symlink():
            return None
        if destination.is_symlink() or not destination.is_dir() or not (destination / ".git").is_dir():
            raise GitCommandFailed("published repository is not a valid Git repository")
        kwargs = {"sink": lambda text: self._logs.append_sync(task, text)} if self._logs is not None and task is not None else {}
        commit_sha = await self._head(destination, kwargs)
        await self._projects.set_commit_sha(project.id, commit_sha)
        return commit_sha

    async def verify_committed(self, project) -> bool:
        destination = contained_path(self._workspace, "projects", str(project.id), "repository")
        if destination.is_symlink() or not destination.is_dir() or not (destination / ".git").exists():
            return False
        try:
            resolved = await self._command(["git", "rev-parse", "HEAD"], cwd=destination)
        except GitCommandFailed:
            return False
        return resolved == project.commit_sha
