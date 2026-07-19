"""Contained, argv-only repository cloning."""

import asyncio
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
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
GIT_OUTPUT_TRUNCATED_MESSAGE = "Git output exceeded 1048576 bytes and was truncated\n"


class GitCommandTimedOut(RuntimeError):
    """Raised when a Git child exceeds its bounded command lifetime."""


def clone_argv(repository_url: str, revision: str, destination: str) -> list[str]:
    """Return the non-checking-out clone command for a requested revision."""
    del revision
    return ["git", "clone", "--no-checkout", "--", repository_url, destination]


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
                    sink(GIT_OUTPUT_TRUNCATED_MESSAGE)
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
        token = None
        if project.token_present:
            token = await self._projects.get_repository_token(project.id) or None
        try:
            with self._git_auth(project_root, token) as env:
                await self._run_git(
                    "clone", clone_argv(repository_url, project.requested_revision, str(staging)), env
                )
                await self._run_git(
                    "fetch requested revision",
                    ["git", "fetch", "--no-tags", "origin", "--", project.requested_revision],
                    env,
                    staging,
                )
                commit_sha = await self._resolve_revision(staging, env)
                await self._run_git("checkout exact commit", ["git", "checkout", "--detach", commit_sha], env, staging)
                if await self._head(staging, env) != commit_sha:
                    raise GitCommandFailed("Git command failed during checkout verification")
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

    @contextmanager
    def _git_auth(self, project_root: Path, token: str | None):
        if not token:
            yield None
            return
        directory = Path(tempfile.mkdtemp(prefix=".git-auth-", dir=project_root))
        try:
            directory.chmod(0o700)
            askpass = directory / "askpass"
            askpass.write_text(
                "#!/bin/sh\ncase \"$1\" in *Username*) printf '%s\\n' 'x-access-token' ;; *) printf '%s\\n' \"$BIGEYE_GIT_TOKEN\" ;; esac\n"
            )
            askpass.chmod(0o700)
            yield {"GIT_ASKPASS": str(askpass), "BIGEYE_GIT_TOKEN": token}
        finally:
            if directory.exists() and directory.is_dir() and not directory.is_symlink():
                if directory.parent.resolve(strict=True) == project_root.resolve(strict=True):
                    shutil.rmtree(directory)

    async def _run_git(self, operation: str, argv: list[str], env: dict[str, str] | None, cwd: Path | None = None) -> str:
        try:
            kwargs = {"env": env} if env is not None else {}
            return await self._command(argv, cwd=cwd, **kwargs)
        except (GitCommandFailed, GitCommandTimedOut):
            raise GitCommandFailed(f"Git command failed during {operation}") from None

    async def _resolve_revision(self, destination: Path, env: dict[str, str] | None) -> str:
        commit_sha = await self._run_git(
            "resolve requested revision", ["git", "rev-parse", "--verify", "FETCH_HEAD^{commit}"], env, destination
        )
        return self._valid_commit(commit_sha, "resolve requested revision")

    async def _head(self, destination: Path, env: dict[str, str] | None) -> str:
        commit_sha = await self._run_git("read checkout HEAD", ["git", "rev-parse", "HEAD"], env, destination)
        return self._valid_commit(commit_sha, "read checkout HEAD")

    @staticmethod
    def _valid_commit(commit_sha: str, operation: str) -> str:
        if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit_sha) is None:
            raise GitCommandFailed(f"Git command failed during {operation}")
        return commit_sha

    async def recover_published(self, project, task=None) -> str | None:
        destination = contained_path(self._workspace, "projects", str(project.id), "repository")
        if not destination.exists() and not destination.is_symlink():
            return None
        if destination.is_symlink() or not destination.is_dir() or not (destination / ".git").is_dir():
            raise GitCommandFailed("published repository is not a valid Git repository")
        commit_sha = await self._head(destination, None)
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
