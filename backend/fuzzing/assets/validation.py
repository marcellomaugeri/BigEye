"""Validate the limited file shapes accepted for generated campaign assets."""

from __future__ import annotations

import stat
from hashlib import sha256
from pathlib import Path, PurePosixPath


def safe_relative_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("asset file names must be safe relative paths")
    return path


def validate_source(name: str, source: Path, kind: str) -> None:
    relative = safe_relative_name(name)
    if source.is_symlink() or not source.is_file():
        raise ValueError("asset source must be a regular file")
    if source.stat().st_mode & stat.S_IXUSR:
        if kind != "script" or relative.suffix != ".sh":
            raise ValueError("asset host files must be non-executable")


def file_hash(source: Path) -> str:
    digest = sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collection_hash(files: dict[str, tuple[Path, str | None]], kind: str) -> str:
    digest = sha256()
    for name in sorted(files):
        source, declared = files[name]
        validate_source(name, source, kind)
        actual = file_hash(source)
        if declared is not None and declared != actual:
            raise ValueError(f"declared hash does not match content for {name}")
        for field in (name.encode("utf-8"), actual.encode("ascii")):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()
