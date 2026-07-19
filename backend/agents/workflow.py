"""Application boundary for cited repository analysis and publication."""

import os
from pathlib import Path
import re
import tempfile
from typing import Awaitable, Callable

from agents import Runner

from backend.agents.context import AgentContext
from backend.agents.manager import build_manager_agent
from backend.agents.repository_analysis import build_repository_analysis_agent
from backend.agents.tools.agent_dispatch import repository_analysis_tool
from backend.agents.tools.code_navigation import CodeNavigationError, read_source_lines
from backend.services.clone_repository import contained_path


_CITATION = re.compile(r"\[([^\[\]]+):(\d+)-(\d+)\]")
_BRACKETED = re.compile(r"\[[^\[\]]*\]")


class CitationValidationError(ValueError):
    """Raised when an analysis contains no valid bounded source citations."""


def validate_citations(content: str, repository_root: Path) -> list[tuple[str, int, int]]:
    """Validate every citation against a real contained source-file line range."""
    if not isinstance(content, str) or not content.strip():
        raise CitationValidationError("analysis is empty")
    citations: list[tuple[str, int, int]] = []
    for token in _BRACKETED.findall(content):
        if ":" not in token:
            continue
        match = _CITATION.fullmatch(token)
        if match is None:
            raise CitationValidationError("analysis contains a malformed citation")
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


def publish_analysis(workspace: Path, project_id: int, content: str) -> Path:
    """Atomically publish already-validated analysis within its project directory."""
    destination = contained_path(workspace, "projects", str(project_id), "analysis", "repository.md")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise CitationValidationError("analysis directory is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".repository-", suffix=".tmp", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination


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
                validate_citations(content, context.repository_root)
            except CitationValidationError:
                if worker_model == "gpt-5.6-luna":
                    continue
                raise
            return publish_analysis(self._workspace, project_id, content)
        raise CitationValidationError("analysis contains no valid citations")
