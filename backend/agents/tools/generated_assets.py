"""Descriptor-contained creation and compare-and-swap edits for generated drafts."""

from __future__ import annotations

import difflib
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import stat
import threading
from uuid import uuid4

from agents import RunContextWrapper, function_tool

from backend.agents.context import AgentContext


MAX_GENERATED_ASSET_BYTES = 128_000
MAX_GENERATED_PATH_DEPTH = 16
MAX_GENERATED_PATH_CHARS = 500
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_EDIT_LOCKS = tuple(threading.Lock() for _ in range(32))
_ALLOWED_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".rs", ".sh", ".patch",
    ".diff", ".dict", ".json", ".yaml", ".yml", ".toml", ".txt", ".proto", ".grammar",
    ".options", ".cmake", ".mk",
})


class GeneratedAssetError(ValueError):
    """Raised when an agent attempts an unsafe or stale generated draft edit."""


def _relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or len(value) > MAX_GENERATED_PATH_CHARS or "\x00" in value or "\\" in value:
        raise GeneratedAssetError("generated asset path is invalid")
    path = PurePosixPath(value)
    if (
        not value or path.is_absolute() or len(path.parts) > MAX_GENERATED_PATH_DEPTH
        or any(part in {"", ".", ".."} or part.casefold() == ".git" for part in path.parts)
        or path.parts[0].isdigit()
    ):
        raise GeneratedAssetError("generated asset path is invalid")
    if path.name != "Dockerfile" and path.suffix.casefold() not in _ALLOWED_SUFFIXES:
        raise GeneratedAssetError("generated asset type is not allowed")
    return path


def _content_bytes(content: str) -> bytes:
    if not isinstance(content, str) or "\x00" in content:
        raise GeneratedAssetError("generated asset content must be text")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_GENERATED_ASSET_BYTES:
        raise GeneratedAssetError("generated asset content exceeds its byte limit")
    return encoded


def _open_or_create(parent: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    except OSError as error:
        raise GeneratedAssetError("generated asset directory is unsafe") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise GeneratedAssetError("generated asset directory is unsafe")
    return descriptor


def _open_root(context: AgentContext) -> tuple[int, int]:
    project_root = context.repository_root.parent
    try:
        relative = context.generated_assets_root.relative_to(project_root)
    except ValueError as error:
        raise GeneratedAssetError("generated asset root escaped the project") from error
    try:
        project_descriptor = os.open(project_root, _DIRECTORY_FLAGS)
        descriptor = os.dup(project_descriptor)
        for part in relative.parts:
            child = _open_or_create(descriptor, part)
            os.close(descriptor)
            descriptor = child
        return project_descriptor, descriptor
    except OSError as error:
        if "project_descriptor" in locals():
            os.close(project_descriptor)
        if "descriptor" in locals():
            os.close(descriptor)
        raise GeneratedAssetError("generated asset root is unsafe") from error


def _root_is_canonical(project_descriptor: int, relative: Path, held_descriptor: int) -> bool:
    descriptor = os.dup(project_descriptor)
    try:
        for part in relative.parts:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        expected, actual = os.fstat(held_descriptor), os.fstat(descriptor)
        return (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _read_existing(parent: int, name: str) -> tuple[bytes | None, tuple[int, int] | None]:
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent)
    except FileNotFoundError:
        return None, None
    except OSError as error:
        raise GeneratedAssetError("generated asset destination is unsafe") from error
    try:
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_size > MAX_GENERATED_ASSET_BYTES:
            raise GeneratedAssetError("generated asset destination is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_GENERATED_ASSET_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(65_536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > MAX_GENERATED_ASSET_BYTES:
            raise GeneratedAssetError("generated asset destination is unsafe")
        return data, (source_stat.st_dev, source_stat.st_ino)
    finally:
        os.close(descriptor)


def _diff(path: str, previous: bytes | None, current: bytes) -> str:
    before = [] if previous is None else previous.decode("utf-8", errors="replace").splitlines()
    after = current.decode("utf-8").splitlines()
    return "\n".join(difflib.unified_diff(before, after, fromfile=f"a/{path}", tofile=f"b/{path}", lineterm=""))


def write_asset_file(
    context: AgentContext, relative_path: str, content: str, expected_sha256: str | None
) -> dict[str, object]:
    """Create a generated draft or replace its exact known version atomically."""
    path = _relative_path(relative_path)
    encoded = _content_bytes(content)
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise GeneratedAssetError("expected generated asset hash is invalid")
    lock = _EDIT_LOCKS[int.from_bytes(sha256(relative_path.encode()).digest()[:2], "big") % len(_EDIT_LOCKS)]
    with lock:
        project_descriptor, root_descriptor = _open_root(context)
        parent_descriptor = os.dup(root_descriptor)
        temporary_name = f".{path.name}.{uuid4().hex}.tmp"
        backup_name = f".{path.name}.{uuid4().hex}.backup"
        created_temporary = False
        backup_created = False
        published = False
        try:
            for part in path.parts[:-1]:
                child = _open_or_create(parent_descriptor, part)
                os.close(parent_descriptor)
                parent_descriptor = child
            previous, identity = _read_existing(parent_descriptor, path.name)
            if previous is None:
                if expected_sha256 is not None:
                    raise GeneratedAssetError("generated asset no longer exists")
            else:
                if expected_sha256 is None or sha256(previous).hexdigest() != expected_sha256:
                    raise GeneratedAssetError("generated asset changed since it was read")
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            created_temporary = True
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("generated asset temporary file could not be written")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            current, current_identity = _read_existing(parent_descriptor, path.name)
            if current != previous or current_identity != identity:
                raise GeneratedAssetError("generated asset changed during the edit")
            relative_root = context.generated_assets_root.relative_to(context.repository_root.parent)
            if not _root_is_canonical(project_descriptor, relative_root, root_descriptor):
                raise GeneratedAssetError("generated asset root changed during the edit")
            if previous is not None:
                os.replace(path.name, backup_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
                backup_created = True
                backup_value, backup_identity = _read_existing(parent_descriptor, backup_name)
                if backup_value != previous or backup_identity != identity:
                    raise GeneratedAssetError("generated asset changed during publication")
            os.replace(temporary_name, path.name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            created_temporary = False
            published = True
            os.fsync(parent_descriptor)
            if not _root_is_canonical(project_descriptor, relative_root, root_descriptor):
                os.unlink(path.name, dir_fd=parent_descriptor)
                published = False
                if backup_created:
                    os.replace(backup_name, path.name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
                    backup_created = False
                os.fsync(parent_descriptor)
                raise GeneratedAssetError("generated asset root changed during publication")
            if backup_created:
                os.unlink(backup_name, dir_fd=parent_descriptor)
                backup_created = False
                os.fsync(parent_descriptor)
            return {
                "relative_path": path.as_posix(), "sha256": sha256(encoded).hexdigest(),
                "created": previous is None, "diff": _diff(path.as_posix(), previous, encoded),
                "provenance": "generated_asset", "trusted_instructions": False,
            }
        except OSError as error:
            raise GeneratedAssetError("generated asset edit failed safely") from error
        finally:
            if created_temporary:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            if backup_created:
                if published:
                    try:
                        os.unlink(path.name, dir_fd=parent_descriptor)
                    except OSError:
                        pass
                try:
                    os.replace(backup_name, path.name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                except OSError:
                    pass
            os.close(parent_descriptor)
            os.close(root_descriptor)
            os.close(project_descriptor)


@function_tool(name_override="write_generated_asset", failure_error_function=None)
async def write_generated_asset(
    context: RunContextWrapper[AgentContext], relative_path: str, content: str,
    expected_sha256: str | None = None,
) -> dict[str, object]:
    """Atomically create a draft, or edit exactly the draft hash previously read."""
    return write_asset_file(context.context, relative_path, content, expected_sha256)


def generated_asset_tools() -> list:
    return [write_generated_asset]
