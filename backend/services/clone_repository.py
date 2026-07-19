"""Contained, argv-only repository cloning."""

import subprocess
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


def _run(argv: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


class CloneRepositoryService:
    def __init__(self, workspace: Path, command=_run, projects=None):
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
        self._command(["git", "clone", "--", repository_url, str(destination)])
        commit_sha = self._command(["git", "rev-parse", "HEAD"], cwd=destination)
        if len(commit_sha) != 40 or any(character not in "0123456789abcdef" for character in commit_sha.lower()):
            raise RuntimeError("Git did not return a commit SHA")
        await self._projects.set_commit_sha(project.id, commit_sha)
        return commit_sha
