"""Contained, argv-only repository cloning."""

import asyncio
import re
from pathlib import Path

from backend.services.create_project import validate_repository_url


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


async def run_command(argv: list[str], cwd: Path | None = None, sink=None) -> str:
    """Run a Git argv list and clean up the child process on cancellation."""
    process = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd) if cwd is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    if not hasattr(process, "stdout"):
        try:
            stdout, _ = await process.communicate()
        except asyncio.CancelledError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()
            raise
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
    try:
        await asyncio.gather(drain(process.stdout, True), drain(process.stderr, False), process.wait())
    except asyncio.CancelledError:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()
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
        project_root = contained_path(self._workspace, "projects", str(project.id))
        project_root.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise UnsafeWorkspacePath("repository destination already exists")
        kwargs = {"sink": lambda text: self._logs.append_sync(task, text)} if self._logs is not None and task is not None else {}
        await self._command(["git", "clone", "--", repository_url, str(destination)], **kwargs)
        commit_sha = await self._command(["git", "rev-parse", "HEAD"], cwd=destination, **kwargs)
        if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit_sha) is None:
            raise GitCommandFailed("Git did not return a full object ID")
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
