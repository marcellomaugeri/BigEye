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


async def run_command(argv: list[str], cwd: Path | None = None) -> str:
    """Run a Git argv list and clean up the child process on cancellation."""
    process = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd) if cwd is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
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


class CloneRepositoryService:
    def __init__(self, workspace: Path, command=run_command, projects=None):
        self._workspace = workspace
        self._command = command
        self._projects = projects

    async def clone(self, project) -> str:
        repository_url = validate_repository_url(project.repository_url)
        destination = contained_path(self._workspace, "projects", str(project.id), "repository")
        project_root = contained_path(self._workspace, "projects", str(project.id))
        project_root.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise UnsafeWorkspacePath("repository destination already exists")
        await self._command(["git", "clone", "--", repository_url, str(destination)])
        commit_sha = await self._command(["git", "rev-parse", "HEAD"], cwd=destination)
        if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit_sha) is None:
            raise GitCommandFailed("Git did not return a full object ID")
        await self._projects.set_commit_sha(project.id, commit_sha)
        return commit_sha
