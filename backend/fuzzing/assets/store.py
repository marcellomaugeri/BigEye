"""Publish generated assets atomically under their persisted project and asset IDs."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from backend.fuzzing.assets.validation import collection_hash, safe_relative_name, validate_source


class AssetStore:
    """Keep generated files outside checkouts and make each version immutable after validation."""

    def __init__(self, workspace: Path, repository):
        self._workspace = Path(workspace).resolve()
        self._repository = repository

    async def create(self, project_id: int, kind: str, name: str, files, parent_id: int | None):
        safe_relative_name(name)
        normalised = self._normalise(project_id, kind, files)
        content_hash = collection_hash(normalised, kind)
        if parent_id is not None:
            parent = await self._repository.get(parent_id)
            if parent is None or parent.project_id != project_id:
                raise ValueError("parent asset does not belong to this project")
        asset = await self._repository.create(project_id, kind, name, content_hash, parent_id)
        staging: Path | None = None
        try:
            content_hash = collection_hash(normalised, kind)
            if content_hash != asset.content_hash:
                raise ValueError("asset content hash changed before publication")
            root = self._asset_root(project_id)
            root.mkdir(parents=True, exist_ok=True)
            self._fsync_directory(root)
            staging = root / f"{asset.id}.staging"
            destination = root / str(asset.id)
            if staging.exists() or staging.is_symlink() or destination.exists() or destination.is_symlink():
                raise RuntimeError("asset version path already exists")
            staging.mkdir()
            for file_name, (source, declared) in normalised.items():
                validate_source(file_name, source, kind)
                target = staging / safe_relative_name(file_name)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                target.chmod(0o700 if kind == "script" and target.suffix == ".sh" else 0o600)
                self._fsync_file(target)
            staged_files = {
                name: (staging / safe_relative_name(name), None) for name in normalised
            }
            if collection_hash(staged_files, kind) != asset.content_hash:
                raise ValueError("copied asset content does not match its persisted hash")
            self._fsync_tree(staging)
            os.replace(staging, destination)
            self._fsync_directory(root)
            return await self._repository.mark_validated(asset.id)
        except BaseException as error:
            if staging is not None and (staging.exists() or staging.is_symlink()):
                self._remove_staging(staging, self._asset_root(project_id))
            try:
                await self._repository.record_error(asset.id, str(error))
            except Exception:
                pass
            raise

    def _asset_root(self, project_id: int) -> Path:
        if not isinstance(project_id, int) or project_id <= 0:
            raise ValueError("project ID must be positive")
        return self._workspace / "projects" / str(project_id) / "assets"

    def _normalise(self, project_id: int, kind: str, files) -> dict[str, tuple[Path, str | None]]:
        if not isinstance(files, dict) or not files:
            raise ValueError("asset files must be a non-empty mapping")
        normalised = {}
        for name, value in files.items():
            safe_relative_name(name)
            if isinstance(value, tuple):
                source, declared = value
            else:
                source, declared = value, None
            if not isinstance(source, Path) or declared is not None and not isinstance(declared, str):
                raise ValueError("asset file source and declared hash are invalid")
            validate_source(name, source, kind)
            try:
                source.resolve(strict=True).relative_to(self._workspace / "projects" / str(project_id))
            except ValueError as error:
                raise ValueError("asset sources must be in the contained project workspace") from error
            normalised[name] = (source, declared)
        return normalised

    @staticmethod
    def _fsync_file(path: Path) -> None:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())

    @classmethod
    def _fsync_tree(cls, root: Path) -> None:
        for directory, _, files in os.walk(root, topdown=False):
            folder = Path(directory)
            for name in files:
                cls._fsync_file(folder / name)
            cls._fsync_directory(folder)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _remove_staging(staging: Path, root: Path) -> None:
        if staging.parent.resolve(strict=True) != root.resolve(strict=True):
            raise RuntimeError("asset staging path escaped its project")
        if staging.is_symlink():
            staging.unlink()
        else:
            shutil.rmtree(staging)
