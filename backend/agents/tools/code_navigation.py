"""Bounded, read-only navigation of a single contained repository."""

import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from collections import deque
from contextlib import contextmanager
from typing import TypedDict

from agents import RunContextWrapper, function_tool

from backend.agents.context import AgentContext


MAX_FILES = 500
MAX_DIRECTORIES = 64
MAX_DIRECTORY_ENTRIES = 256
MAX_DIRECTORY_DEPTH = 12
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_READ_BYTES = 4_000_000
MAX_LINE_RANGE = 200
MAX_QUERY_LENGTH = 200
MAX_SEARCH_RESULTS = 50
MAX_RESULT_LINE_LENGTH = 500
GIT_TIMEOUT_SECONDS = 5


class CodeNavigationError(ValueError):
    """Raised when a navigation request would exceed the repository boundary."""


class RepositoryResult(TypedDict):
    provenance: str
    trusted_instructions: bool


class ProjectFilesResult(RepositoryResult):
    files: list[str]


class SourceLinesResult(RepositoryResult):
    path: str
    start_line: int
    end_line: int
    text: str


class SourceMatch(RepositoryResult):
    path: str
    line: int
    text: str


class SourceSearchResult(RepositoryResult):
    matches: list[SourceMatch]


class GitMetadataResult(RepositoryResult):
    commit: str
    branch: str


def _repository_root(repository_root: Path) -> Path:
    try:
        root = repository_root.resolve(strict=True)
    except OSError as error:
        raise CodeNavigationError("repository root is unavailable") from error
    if not root.is_dir() or root.is_symlink():
        raise CodeNavigationError("repository root must be a directory")
    return root


def _relative_parts(relative_path: str) -> tuple[str, ...]:
    if not isinstance(relative_path, str) or not relative_path or "\x00" in relative_path:
        raise CodeNavigationError("path must be a non-empty relative path")
    normalised = relative_path.replace("\\", "/")
    path = PurePosixPath(normalised)
    if path.is_absolute() or any(part in {"", ".", ".."} or part.casefold() == ".git" for part in path.parts):
        raise CodeNavigationError("path is outside the allowed repository files")
    return path.parts


def _open_flags(directory: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= os.O_DIRECTORY
    return flags


@contextmanager
def _opened_repository_root(repository_root: Path):
    root = _repository_root(repository_root)
    try:
        descriptor = os.open(root, _open_flags(directory=True))
    except OSError as error:
        raise CodeNavigationError("repository root is unavailable") from error
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise CodeNavigationError("repository root must be a directory")
        yield root, descriptor
    finally:
        os.close(descriptor)


def _open_contained_file(root_descriptor: int, parts: tuple[str, ...]) -> int:
    directory_descriptor = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            child_descriptor = os.open(part, _open_flags(directory=True), dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = child_descriptor
            if not stat.S_ISDIR(os.fstat(directory_descriptor).st_mode):
                raise CodeNavigationError("path must identify a file")
        descriptor = os.open(parts[-1], _open_flags(), dir_fd=directory_descriptor)
    except OSError as error:
        raise CodeNavigationError("path escapes the repository") from error
    finally:
        os.close(directory_descriptor)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise CodeNavigationError("path must identify a file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_open_text(descriptor: int) -> str:
    try:
        if os.fstat(descriptor).st_size > MAX_FILE_BYTES:
            raise CodeNavigationError("source file exceeds the read limit")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
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


def _read_relative_text(root_descriptor: int, parts: tuple[str, ...]) -> str:
    descriptor = _open_contained_file(root_descriptor, parts)
    try:
        return _read_open_text(descriptor)
    finally:
        os.close(descriptor)


def _contained_file_size(root_descriptor: int, parts: tuple[str, ...]) -> int:
    descriptor = _open_contained_file(root_descriptor, parts)
    try:
        return os.fstat(descriptor).st_size
    finally:
        os.close(descriptor)


def _open_contained_directory(root_descriptor: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts:
            child_descriptor = os.open(part, _open_flags(directory=True), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child_descriptor
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise CodeNavigationError("repository directory cannot be listed")
    except OSError as error:
        raise CodeNavigationError("repository directory cannot be listed") from error
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _enumerate_project_files(root_descriptor: int, limit: int) -> list[str]:
    files: list[str] = []
    pending = deque([((), 0)])
    directories = 0
    entries = 0
    while pending:
        parts, depth = pending.popleft()
        directories += 1
        if directories > MAX_DIRECTORIES:
            raise CodeNavigationError("repository contains too many directories")
        directory_descriptor = _open_contained_directory(root_descriptor, parts)
        try:
            try:
                scan_descriptor = os.dup(directory_descriptor)
                scanner = os.scandir(scan_descriptor)
            except OSError:
                raise CodeNavigationError("repository directory cannot be listed") from None
            try:
                for entry in scanner:
                    entries += 1
                    if entries > MAX_DIRECTORY_ENTRIES:
                        raise CodeNavigationError("repository contains too many directory entries")
                    name = entry.name
                    if name.casefold() == ".git":
                        continue
                    try:
                        child_directory = os.open(name, _open_flags(directory=True), dir_fd=directory_descriptor)
                    except OSError:
                        try:
                            descriptor = os.open(name, _open_flags(), dir_fd=directory_descriptor)
                        except OSError:
                            continue
                        try:
                            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                                files.append("/".join((*parts, name)))
                                if len(files) >= limit:
                                    return sorted(files)
                        finally:
                            os.close(descriptor)
                        continue
                    try:
                        if not stat.S_ISDIR(os.fstat(child_directory).st_mode):
                            continue
                    finally:
                        os.close(child_directory)
                    child_depth = depth + 1
                    if child_depth > MAX_DIRECTORY_DEPTH:
                        raise CodeNavigationError("repository directory nesting is too deep")
                    pending.append(((*parts, name), child_depth))
            finally:
                scanner.close()
        finally:
            os.close(directory_descriptor)
    return sorted(files)


def list_project_files(repository_root: Path, limit: int = MAX_FILES) -> list[str]:
    """List at most ``limit`` contained, non-Git, text-like repository files."""
    if not isinstance(limit, int) or limit < 1 or limit > MAX_FILES:
        raise CodeNavigationError("file listing limit is outside the allowed range")
    with _opened_repository_root(repository_root) as (_, descriptor):
        return _enumerate_project_files(descriptor, limit)


def _read_source_range(
    repository_root: Path, relative_path: str, start_line: int, end_line: int,
) -> tuple[str, int]:
    """Read one bounded range and return its text plus its clamped inclusive end."""
    if (
        not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or start_line < 1
        or end_line < start_line
        or end_line - start_line + 1 > MAX_LINE_RANGE
    ):
        raise CodeNavigationError("line range is outside the allowed bounds")
    parts = _relative_parts(relative_path)
    with _opened_repository_root(repository_root) as (_, descriptor):
        lines = _read_relative_text(descriptor, parts).splitlines()
    if start_line > len(lines):
        raise CodeNavigationError("line range is outside the source file")
    clamped_end = min(end_line, len(lines))
    return "\n".join(lines[start_line - 1 : clamped_end]), clamped_end


def read_source_lines(repository_root: Path, relative_path: str, start_line: int, end_line: int) -> str:
    """Read a bounded inclusive line range from one contained UTF-8 source file."""
    return _read_source_range(repository_root, relative_path, start_line, end_line)[0]


def search_source_text(repository_root: Path, query: str, limit: int = MAX_SEARCH_RESULTS) -> list[dict[str, int | str]]:
    """Find bounded literal text matches in contained UTF-8 repository files."""
    if not isinstance(query, str) or not query or "\x00" in query or len(query) > MAX_QUERY_LENGTH:
        raise CodeNavigationError("search query is outside the allowed bounds")
    if not isinstance(limit, int) or limit < 1 or limit > MAX_SEARCH_RESULTS:
        raise CodeNavigationError("search result limit is outside the allowed bounds")
    matches: list[dict[str, int | str]] = []
    remaining_bytes = MAX_TOTAL_READ_BYTES
    with _opened_repository_root(repository_root) as (_, descriptor):
        for relative_path in _enumerate_project_files(descriptor, MAX_FILES):
            parts = tuple(relative_path.split("/"))
            try:
                size = _contained_file_size(descriptor, parts)
                if size > remaining_bytes:
                    continue
                content = _read_relative_text(descriptor, parts)
            except (CodeNavigationError, OSError):
                continue
            remaining_bytes -= len(content.encode("utf-8"))
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
async def list_contained_project_files(
    context: RunContextWrapper[AgentContext], limit: int = MAX_FILES
) -> ProjectFilesResult:
    """List contained project files as explicitly untrusted repository evidence."""
    return {
        "files": list_project_files(context.context.repository_root, limit),
        "provenance": "repository",
        "trusted_instructions": False,
    }


@function_tool(name_override="read_source_lines")
async def read_contained_source_lines(
    context: RunContextWrapper[AgentContext], relative_path: str, start_line: int, end_line: int
) -> SourceLinesResult:
    """Read a bounded source range as explicitly untrusted repository evidence."""
    text, clamped_end = _read_source_range(
        context.context.repository_root, relative_path, start_line, end_line,
    )
    return {
        "path": relative_path,
        "start_line": start_line,
        "end_line": clamped_end,
        "text": text,
        "provenance": "repository",
        "trusted_instructions": False,
    }


@function_tool(name_override="search_source_text")
async def search_contained_source_text(
    context: RunContextWrapper[AgentContext], query: str, limit: int = MAX_SEARCH_RESULTS
) -> SourceSearchResult:
    """Search source text and label every returned match as untrusted evidence."""
    matches: list[SourceMatch] = [
        {
            "path": str(match["path"]),
            "line": int(match["line"]),
            "text": str(match["text"]),
            "provenance": "repository",
            "trusted_instructions": False,
        }
        for match in search_source_text(context.context.repository_root, query, limit)
    ]
    return {
        "matches": matches,
        "provenance": "repository",
        "trusted_instructions": False,
    }


@function_tool(name_override="inspect_git_metadata")
async def inspect_contained_git_metadata(context: RunContextWrapper[AgentContext]) -> GitMetadataResult:
    """Inspect Git metadata and label it as untrusted repository evidence."""
    metadata = inspect_git_metadata(context.context.repository_root)
    return {
        "commit": metadata["commit"],
        "branch": metadata["branch"],
        "provenance": "repository",
        "trusted_instructions": False,
    }


def code_navigation_tools() -> list:
    return [
        list_contained_project_files,
        read_contained_source_lines,
        search_contained_source_text,
        inspect_contained_git_metadata,
    ]
