"""Application boundary for cited repository analysis and publication."""

import os
from pathlib import Path
import re
import stat
from typing import Awaitable, Callable
from uuid import uuid4

from agents import Runner

from backend.agents.context import AgentContext
from backend.agents.manager import build_manager_agent
from backend.agents.repository_analysis import build_repository_analysis_agent
from backend.agents.tools.agent_dispatch import repository_analysis_tool
from backend.agents.tools.code_navigation import CodeNavigationError, read_source_lines


_CITATION = re.compile(r"\[([^\[\]]+):(\d+)-(\d+)\]")


class CitationValidationError(ValueError):
    """Raised when an analysis contains no valid bounded source citations."""


def validate_citations(content: str, repository_root: Path) -> list[tuple[str, int, int]]:
    """Validate every citation against a real contained source-file line range."""
    if not isinstance(content, str) or not content.strip():
        raise CitationValidationError("analysis is empty")
    matches = list(_CITATION.finditer(content))
    remainder = _CITATION.sub("", content)
    if "[" in remainder or "]" in remainder:
        raise CitationValidationError("analysis contains a malformed citation")
    citations: list[tuple[str, int, int]] = []
    for match in matches:
        relative_path, start, end = match.groups()
        start_line, end_line = int(start), int(end)
        try:
            read_source_lines(repository_root, relative_path, start_line, end_line)
        except CodeNavigationError as error:
            raise CitationValidationError("analysis contains an invalid citation") from error
        citations.append((relative_path, start_line, end_line))
    if not citations:
        raise CitationValidationError("analysis requires at least one source citation")
    return citations


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_workspace(workspace: Path) -> tuple[Path, int]:
    absolute_workspace = Path(os.path.abspath(os.fspath(workspace)))
    try:
        descriptor = os.open("/", _directory_flags())
    except OSError as error:
        raise CitationValidationError("workspace directory is unsafe") from error
    try:
        for part in absolute_workspace.parts[1:]:
            child_descriptor = _open_or_create_directory(descriptor, part)
            os.close(descriptor)
            descriptor = child_descriptor
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise CitationValidationError("workspace directory is unsafe")
    except BaseException:
        os.close(descriptor)
        raise
    return absolute_workspace, descriptor


def _open_or_create_directory(parent_descriptor: int, name: str) -> int:
    try:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except OSError as error:
        raise CitationValidationError("analysis directory is unsafe") from error
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise CitationValidationError("analysis directory is unsafe")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def publish_analysis(workspace: Path, project_id: int, content: str) -> Path:
    """Atomically publish already-validated analysis within its project directory."""
    if not isinstance(project_id, int) or isinstance(project_id, bool) or project_id < 1:
        raise CitationValidationError("project ID is unsafe")
    root, workspace_descriptor = _open_workspace(workspace)
    project_descriptors = [workspace_descriptor]
    temporary_name = f".repository-{uuid4().hex}.tmp"
    temporary_created = False
    try:
        for name in ("projects", str(project_id), "analysis"):
            project_descriptors.append(_open_or_create_directory(project_descriptors[-1], name))
        analysis_descriptor = project_descriptors[-1]
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=analysis_descriptor,
        )
        temporary_created = True
        try:
            encoded = content.encode("utf-8")
            written = 0
            while written < len(encoded):
                count = os.write(descriptor, encoded[written:])
                if count <= 0:
                    raise OSError("analysis temporary file could not be written")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(
            temporary_name,
            "repository.md",
            src_dir_fd=analysis_descriptor,
            dst_dir_fd=analysis_descriptor,
        )
        temporary_created = False
    except BaseException:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=project_descriptors[-1])
            except OSError:
                pass
        raise
    finally:
        for descriptor in reversed(project_descriptors):
            os.close(descriptor)
    return root / "projects" / str(project_id) / "analysis" / "repository.md"


def _observed_repository_dispatch(result: object) -> bool:
    for item in getattr(result, "new_items", ()) or ():
        name = getattr(item, "tool_name", None)
        if name == "analyse_repository":
            return True
        raw_item = getattr(item, "raw_item", item)
        if isinstance(raw_item, dict):
            name = raw_item.get("name")
        else:
            name = getattr(raw_item, "name", None)
        if name == "analyse_repository":
            return True
    return False


RunnerCallable = Callable[..., Awaitable[object]]


class RepositoryAnalysisWorkflow:
    """Run the temporary manager and publish only deterministically valid output."""

    def __init__(self, workspace: Path, runner: RunnerCallable = Runner.run):
        self._workspace = workspace
        self._runner = runner

    async def analyse(self, project_id: int, repository_root: Path) -> Path:
        context = AgentContext(project_id=project_id, repository_root=repository_root)
        for worker_model in ("gpt-5.6-luna", "gpt-5.6-terra"):
            worker = build_repository_analysis_agent(model=worker_model)
            manager = build_manager_agent(repository_analysis_tool(worker))
            result = await self._runner(
                manager,
                "Inspect this repository and prepare the cited repository analysis.",
                context=context,
            )
            content = getattr(result, "final_output", None)
            try:
                if not _observed_repository_dispatch(result):
                    raise CitationValidationError("analysis did not dispatch repository inspection")
                validate_citations(content, context.repository_root)
            except CitationValidationError:
                if worker_model == "gpt-5.6-luna":
                    continue
                raise
            return publish_analysis(self._workspace, project_id, content)
        raise CitationValidationError("analysis contains no valid citations")
