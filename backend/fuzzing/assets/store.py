"""Publish generated assets atomically under persisted project and asset IDs."""

from __future__ import annotations

import os
import shutil
import stat
from hashlib import sha256
from pathlib import Path

from backend.fuzzing.assets.validation import collection_hash, safe_relative_name


class AssetStore:
    """Persist only descriptor-verified, project-contained generated files."""

    def __init__(self, workspace: Path, repository):
        self._workspace = Path(os.path.abspath(workspace))
        self._repository = repository

    async def create(self, project_id: int, kind: str, name: str, files, parent_id: int | None):
        safe_relative_name(name)
        normalised = self._normalise(project_id, kind, files)
        expected = self._hash_sources(project_id, kind, normalised)
        content_hash = self._collection_hash(expected)
        if parent_id is not None:
            parent = await self._repository.get(parent_id)
            if parent is None or parent.project_id != project_id:
                raise ValueError("parent asset does not belong to this project")
        asset = await self._repository.create(project_id, kind, name, content_hash, parent_id)
        staging: Path | None = None
        try:
            root = self._asset_root(project_id)
            assets_descriptor = self._open_assets_directory(project_id, create=True)
            os.close(assets_descriptor)
            self._fsync_directory(root)
            staging = root / f"{asset.id}.staging"
            destination = root / str(asset.id)
            if staging.exists() or staging.is_symlink() or destination.exists() or destination.is_symlink():
                raise RuntimeError("asset version path already exists")
            staging.mkdir(mode=0o700)
            for file_name, source in normalised.items():
                target = staging / safe_relative_name(file_name)
                target.parent.mkdir(parents=True, exist_ok=True)
                copied_hash = self._copy_source(project_id, kind, file_name, source, target)
                if copied_hash != expected[file_name]:
                    raise ValueError("asset source changed after content validation")
            staged = {
                name: (staging / safe_relative_name(name), None) for name in normalised
            }
            if collection_hash(staged, kind) != asset.content_hash:
                raise ValueError("copied asset content does not match its persisted hash")
            self._lock_down(staging, kind)
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

    def _normalise(self, project_id: int, kind: str, files) -> dict[str, Path]:
        if not isinstance(files, dict) or not files:
            raise ValueError("asset files must be a non-empty mapping")
        normalised: dict[str, Path] = {}
        for name, value in files.items():
            safe_relative_name(name)
            source, declared = value if isinstance(value, tuple) else (value, None)
            if not isinstance(source, Path) or declared is not None and not isinstance(declared, str):
                raise ValueError("asset file source and declared hash are invalid")
            self._validate_source_path(project_id, source)
            with self._open_source(project_id, source) as descriptor:
                self._validate_source_stat(name, kind, os.fstat(descriptor.fileno()))
                actual = self._hash_descriptor(descriptor)
            if declared is not None and declared != actual:
                raise ValueError(f"declared hash does not match content for {name}")
            normalised[name] = source
        return normalised

    def _hash_sources(self, project_id: int, kind: str, files: dict[str, Path]) -> dict[str, str]:
        hashes = {}
        for name, source in files.items():
            with self._open_source(project_id, source) as descriptor:
                self._validate_source_stat(name, kind, os.fstat(descriptor.fileno()))
                hashes[name] = self._hash_descriptor(descriptor)
        return hashes

    def _copy_source(self, project_id: int, kind: str, name: str, source: Path, target: Path) -> str:
        with self._open_source(project_id, source) as input_descriptor:
            self._validate_source_stat(name, kind, os.fstat(input_descriptor.fileno()))
            output_descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            digest = sha256()
            try:
                while block := input_descriptor.read(1024 * 1024):
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(output_descriptor, view)
                        view = view[written:]
                os.fsync(output_descriptor)
            finally:
                os.close(output_descriptor)
        return digest.hexdigest()

    def _validate_source_path(self, project_id: int, source: Path) -> None:
        root = self._project_root(project_id)
        absolute = Path(os.path.abspath(source))
        try:
            relative = absolute.relative_to(root)
        except ValueError as error:
            raise ValueError("asset sources must be in the contained project workspace") from error
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("asset sources must be in the contained project workspace")

    def _open_source(self, project_id: int, source: Path):
        root = self._project_root(project_id)
        relative = Path(os.path.abspath(source)).relative_to(root)
        directory_descriptor = self._open_project_directory(project_id, create=False)
        try:
            for component in relative.parts[:-1]:
                next_descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_descriptor)
                os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            descriptor = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return os.fdopen(descriptor, "rb", closefd=True)

    @staticmethod
    def _validate_source_stat(name: str, kind: str, source_stat) -> None:
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("asset source must be a regular file")
        if source_stat.st_mode & stat.S_IXUSR and (kind != "script" or not name.endswith(".sh")):
            raise ValueError("asset host files must be non-executable")

    @staticmethod
    def _hash_descriptor(descriptor) -> str:
        digest = sha256()
        descriptor.seek(0)
        for block in iter(lambda: descriptor.read(1024 * 1024), b""):
            digest.update(block)
        descriptor.seek(0)
        return digest.hexdigest()

    @staticmethod
    def _collection_hash(hashes: dict[str, str]) -> str:
        digest = sha256()
        for name in sorted(hashes):
            for field in (name.encode("utf-8"), hashes[name].encode("ascii")):
                digest.update(len(field).to_bytes(8, "big")); digest.update(field)
        return digest.hexdigest()

    def _project_root(self, project_id: int) -> Path:
        if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
            raise ValueError("project ID must be positive")
        return self._workspace / "projects" / str(project_id)

    def _asset_root(self, project_id: int) -> Path:
        return self._project_root(project_id) / "assets"

    def _open_project_directory(self, project_id: int, create: bool) -> int:
        self._project_root(project_id)
        descriptor = os.open(self._workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in ("projects", str(project_id)):
                next_descriptor = self._open_directory_component(descriptor, component, create)
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_assets_directory(self, project_id: int, create: bool) -> int:
        descriptor = self._open_project_directory(project_id, create)
        try:
            assets_descriptor = self._open_directory_component(descriptor, "assets", create)
        finally:
            os.close(descriptor)
        return assets_descriptor

    @staticmethod
    def _open_directory_component(parent_descriptor: int, component: str, create: bool) -> int:
        if create:
            try:
                os.mkdir(component, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                pass
        return os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_descriptor)

    @classmethod
    def _lock_down(cls, root: Path, kind: str) -> None:
        for directory, _, files in os.walk(root, topdown=False):
            folder = Path(directory)
            for name in files:
                path = folder / name
                path.chmod(0o500 if kind == "script" and path.suffix == ".sh" else 0o400)
            folder.chmod(0o500)

    @staticmethod
    def _fsync_tree(root: Path) -> None:
        for directory, _, files in os.walk(root, topdown=False):
            folder = Path(directory)
            for name in files:
                with (folder / name).open("rb") as handle:
                    os.fsync(handle.fileno())
            AssetStore._fsync_directory(folder)

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
