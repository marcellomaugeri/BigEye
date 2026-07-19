"""Bounded, read-only navigation of a single contained repository."""

import os
from pathlib import Path, PurePosixPath
import re
import subprocess

from agents import RunContextWrapper, function_tool

from backend.agents.context import AgentContext


MAX_FILES = 500
MAX_FILE_BYTES = 1_000_000
MAX_LINE_RANGE = 200
MAX_QUERY_LENGTH = 200
MAX_SEARCH_RESULTS = 50
MAX_RESULT_LINE_LENGTH = 500
GIT_TIMEOUT_SECONDS = 5


class CodeNavigationError(ValueError):
    """Raised when a navigation request would exceed the repository boundary."""


def _repository_root(repository_root: Path) -> Path:
    try:
        root = repository_root.resolve(strict=True)
    except OSError as error:
        raise CodeNavigationError("repository root is unavailable") from error
    if not root.is_dir() or root.is_symlink():
        raise CodeNavigationError("repository root must be a directory")
    return root


def _contained_file(repository_root: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path or "\x00" in relative_path:
        raise CodeNavigationError("path must be a non-empty relative path")
    normalised = relative_path.replace("\\", "/")
    path = PurePosixPath(normalised)
    if path.is_absolute() or any(part in {"", ".", "..", ".git"} for part in path.parts):
        raise CodeNavigationError("path is outside the allowed repository files")
    root = _repository_root(repository_root)
    candidate = root.joinpath(*path.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise CodeNavigationError("path escapes the repository") from error
    if not resolved.is_file():
        raise CodeNavigationError("path must identify a file")
    return resolved


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CodeNavigationError("source file cannot be read") from error
    if len(data) > MAX_FILE_BYTES:
        raise CodeNavigationError("source file exceeds the read limit")
    if b"\x00" in data:
        raise CodeNavigationError("binary files cannot be read")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CodeNavigationError("source file is not UTF-8 text") from error


def list_project_files(repository_root: Path, limit: int = MAX_FILES) -> list[str]:
    """List at most ``limit`` contained, non-Git, text-like repository files."""
    if not isinstance(limit, int) or limit < 1 or limit > MAX_FILES:
        raise CodeNavigationError("file listing limit is outside the allowed range")
    root = _repository_root(repository_root)
    files: list[str] = []
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if name != ".git")
        for filename in sorted(filenames):
            candidate = Path(directory, filename)
            relative = candidate.relative_to(root)
            if candidate.is_symlink():
                continue
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            files.append(relative.as_posix())
            if len(files) == limit:
                return sorted(files)
    return sorted(files)


def read_source_lines(repository_root: Path, relative_path: str, start_line: int, end_line: int) -> str:
    """Read a bounded inclusive line range from one contained UTF-8 source file."""
    if (
        not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or start_line < 1
        or end_line < start_line
        or end_line - start_line + 1 > MAX_LINE_RANGE
    ):
        raise CodeNavigationError("line range is outside the allowed bounds")
    lines = _read_text(_contained_file(repository_root, relative_path)).splitlines()
    if end_line > len(lines):
        raise CodeNavigationError("line range is outside the source file")
    return "\n".join(lines[start_line - 1 : end_line])


def search_source_text(repository_root: Path, query: str, limit: int = MAX_SEARCH_RESULTS) -> list[dict[str, int | str]]:
    """Find bounded literal text matches in contained UTF-8 repository files."""
    if not isinstance(query, str) or not query or "\x00" in query or len(query) > MAX_QUERY_LENGTH:
        raise CodeNavigationError("search query is outside the allowed bounds")
    if not isinstance(limit, int) or limit < 1 or limit > MAX_SEARCH_RESULTS:
        raise CodeNavigationError("search result limit is outside the allowed bounds")
    root = _repository_root(repository_root)
    matches: list[dict[str, int | str]] = []
    for relative_path in list_project_files(root):
        try:
            content = _read_text(_contained_file(root, relative_path))
        except CodeNavigationError:
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            if query in line:
                matches.append({"path": relative_path, "line": line_number, "text": line[:MAX_RESULT_LINE_LENGTH]})
                if len(matches) == limit:
                    return matches
    return matches


def inspect_git_metadata(repository_root: Path, run=subprocess.run) -> dict[str, str]:
    """Return only the resolved commit and branch through fixed Git argv calls."""
    root = _repository_root(repository_root)
    outputs: list[str] = []
    for argv in (["git", "rev-parse", "HEAD"], ["git", "rev-parse", "--abbrev-ref", "HEAD"]):
        try:
            completed = run(argv, cwd=root, capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CodeNavigationError("Git metadata is unavailable") from error
        if completed.returncode != 0:
            raise CodeNavigationError("Git metadata is unavailable")
        output = completed.stdout.strip()
        if not output or len(output) > 200:
            raise CodeNavigationError("Git returned invalid metadata")
        outputs.append(output)
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", outputs[0]) is None:
        raise CodeNavigationError("Git returned invalid commit metadata")
    return {"commit": outputs[0], "branch": outputs[1]}


@function_tool(name_override="list_project_files")
async def list_contained_project_files(context: RunContextWrapper[AgentContext], limit: int = MAX_FILES) -> list[str]:
    """List contained project files, excluding Git internals."""
    return list_project_files(context.context.repository_root, limit)


@function_tool(name_override="read_source_lines")
async def read_contained_source_lines(
    context: RunContextWrapper[AgentContext], relative_path: str, start_line: int, end_line: int
) -> str:
    """Read a bounded inclusive line range from a contained source file."""
    return read_source_lines(context.context.repository_root, relative_path, start_line, end_line)


@function_tool(name_override="search_source_text")
async def search_contained_source_text(
    context: RunContextWrapper[AgentContext], query: str, limit: int = MAX_SEARCH_RESULTS
) -> list[dict[str, int | str]]:
    """Search bounded literal text in contained source files."""
    return search_source_text(context.context.repository_root, query, limit)


@function_tool(name_override="inspect_git_metadata")
async def inspect_contained_git_metadata(context: RunContextWrapper[AgentContext]) -> dict[str, str]:
    """Inspect only the repository commit and branch through fixed Git metadata calls."""
    return inspect_git_metadata(context.context.repository_root)


def code_navigation_tools() -> list:
    return [
        list_contained_project_files,
        read_contained_source_lines,
        search_contained_source_text,
        inspect_contained_git_metadata,
    ]
