"""Publish generated assets atomically under persisted project and asset IDs."""

from __future__ import annotations

import os
import stat
from hashlib import sha256
from pathlib import Path

from backend.fuzzing.assets.validation import safe_relative_name


_MAX_ASSET_PATH_DEPTH = 32


class AssetStore:
    """Persist only descriptor-verified, project-contained generated files."""

    def __init__(self, workspace: Path, repository):
        self._workspace = Path(os.path.abspath(workspace))
        self._repository = repository

    async def create(self, project_id: int, kind: str, name: str, files, parent_id: int | None):
        safe_relative_name(name)
        if parent_id is not None and (isinstance(parent_id, bool) or not isinstance(parent_id, int) or parent_id <= 0):
            raise ValueError("parent ID must be a positive integer")
        normalised = self._normalise(project_id, kind, files)
        expected = self._hash_sources(project_id, kind, normalised)
        content_hash = self._collection_hash(expected)
        if parent_id is not None:
            parent = await self._repository.get(parent_id)
            if parent is None or parent.project_id != project_id:
                raise ValueError("parent asset does not belong to this project")
        asset = await self._repository.create(project_id, kind, name, content_hash, parent_id)
        assets_descriptor: int | None = None
        staging_name: str | None = None
        published = False
        try:
            assets_descriptor = self._open_assets_directory(project_id, create=True)
            self._after_assets_opened(assets_descriptor)
            self._fsync_descriptor(assets_descriptor)
            if isinstance(asset.id, bool) or not isinstance(asset.id, int) or asset.id <= 0:
                raise ValueError("asset ID must be a positive integer")
            staging_name = f"{asset.id}.staging"
            destination_name = str(asset.id)
            for candidate in (staging_name, destination_name):
                try:
                    os.stat(candidate, dir_fd=assets_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise RuntimeError("asset version path already exists")
            os.mkdir(staging_name, mode=0o700, dir_fd=assets_descriptor)
            staging_descriptor = os.open(staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=assets_descriptor)
            for file_name, source in normalised.items():
                relative = safe_relative_name(file_name)
                parent_descriptor = self._open_relative_directory(staging_descriptor, relative.parts[:-1], create=True)
                try:
                    copied_hash = self._copy_source(project_id, kind, file_name, source, parent_descriptor, relative.name)
                finally:
                    os.close(parent_descriptor)
                if copied_hash != expected[file_name]:
                    raise ValueError("asset source changed after content validation")
            self._lock_down_staging(staging_descriptor, tuple(normalised), kind)
            self._fsync_descriptor(staging_descriptor)
            os.close(staging_descriptor)
            staging_descriptor = None
            os.replace(staging_name, destination_name, src_dir_fd=assets_descriptor, dst_dir_fd=assets_descriptor)
            published = True
            self._fsync_descriptor(assets_descriptor)
            if not self._is_canonical_assets_directory(project_id, assets_descriptor):
                self._remove_staging_at(assets_descriptor, destination_name)
                self._fsync_descriptor(assets_descriptor)
                raise ValueError("canonical assets directory changed during publication")
            return await self._repository.mark_validated(asset.id)
        except BaseException as error:
            if staging_name is not None and assets_descriptor is not None and not published:
                try:
                    self._remove_staging_at(assets_descriptor, staging_name)
                except BaseException:
                    pass
            try:
                await self._repository.record_error(asset.id, str(error))
            except Exception:
                pass
            raise
        finally:
            if "staging_descriptor" in locals() and staging_descriptor is not None:
                os.close(staging_descriptor)
            if assets_descriptor is not None:
                os.close(assets_descriptor)

    async def create_reusable(
        self, project_id: int, kind: str, name: str, files, parent_id: int | None,
    ):
        """Reuse one validated content-identical asset when the repository supports lookup."""
        safe_relative_name(name)
        normalised = self._normalise(project_id, kind, files)
        content_hash = self._collection_hash(self._hash_sources(project_id, kind, normalised))
        finder = getattr(self._repository, "find_validated", None)
        if finder is not None:
            existing = await finder(project_id, kind, name, content_hash, parent_id)
            if existing is not None and self._existing_matches(project_id, existing):
                return existing
        return await self.create(project_id, kind, name, normalised, parent_id)

    def _existing_matches(self, project_id: int, asset) -> bool:
        if (
            getattr(asset, "project_id", None) != project_id
            or getattr(asset, "validated_at", None) is None
            or getattr(asset, "error", None) is not None
        ):
            return False
        root = self._asset_root(project_id) / str(asset.id)
        if root.is_symlink() or not root.is_dir():
            return False
        entries = tuple(root.rglob("*"))
        if any(
            entry.is_symlink() or not (entry.is_file() or entry.is_dir())
            for entry in entries
        ):
            return False
        files = {
            entry.relative_to(root).as_posix(): (entry, None)
            for entry in entries if entry.is_file()
        }
        if not files:
            return False
        from backend.fuzzing.assets.validation import collection_hash
        return collection_hash(files, asset.kind) == asset.content_hash

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

    def _copy_source(self, project_id: int, kind: str, name: str, source: Path, parent_descriptor: int, target_name: str) -> str:
        with self._open_source(project_id, source) as input_descriptor:
            self._validate_source_stat(name, kind, os.fstat(input_descriptor.fileno()))
            output_descriptor = os.open(target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_descriptor)
            digest = sha256()
            try:
                while block := input_descriptor.read(1024 * 1024):
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(output_descriptor, view)
                        view = view[written:]
                os.fchmod(output_descriptor, 0o500 if kind == "script" and name.endswith(".sh") else 0o400)
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

    def _is_canonical_assets_directory(self, project_id: int, publication_descriptor: int) -> bool:
        try:
            canonical_descriptor = self._open_assets_directory(project_id, create=False)
        except OSError:
            return False
        try:
            canonical = os.fstat(canonical_descriptor)
            published = os.fstat(publication_descriptor)
            return (canonical.st_dev, canonical.st_ino) == (published.st_dev, published.st_ino)
        finally:
            os.close(canonical_descriptor)

    @staticmethod
    def _after_assets_opened(_descriptor: int) -> None:
        """Test seam: publication remains anchored to this descriptor after path replacement."""

    def _open_relative_directory(self, root_descriptor: int, parts, create: bool) -> int:
        if len(parts) > _MAX_ASSET_PATH_DEPTH:
            raise ValueError("asset path is too deeply nested")
        descriptor = os.dup(root_descriptor)
        try:
            for component in parts:
                next_descriptor = self._open_directory_component(descriptor, component, create)
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _open_directory_component(parent_descriptor: int, component: str, create: bool) -> int:
        if create:
            try:
                os.mkdir(component, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                pass
        return os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_descriptor)

    def _lock_down_staging(self, root_descriptor: int, names: tuple[str, ...], kind: str) -> None:
        directories = {tuple(safe_relative_name(name).parts[:-1]) for name in names}
        for parts in sorted(directories, key=len, reverse=True):
            descriptor = self._open_relative_directory(root_descriptor, parts, create=False)
            try:
                os.fchmod(descriptor, 0o500)
                self._fsync_descriptor(descriptor)
            finally:
                os.close(descriptor)
        os.fchmod(root_descriptor, 0o500)

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
    def _fsync_descriptor(descriptor: int) -> None:
        os.fsync(descriptor)

    @staticmethod
    def _remove_staging_at(parent_descriptor: int, name: str, depth: int = 0) -> None:
        if depth > _MAX_ASSET_PATH_DEPTH:
            raise RuntimeError("asset staging cleanup exceeded its nesting limit")
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        except FileNotFoundError:
            return
        try:
            os.fchmod(descriptor, 0o700)
            for child in os.listdir(descriptor):
                source_stat = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(source_stat.st_mode):
                    AssetStore._remove_staging_at(descriptor, child, depth + 1)
                else:
                    os.unlink(child, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        os.rmdir(name, dir_fd=parent_descriptor)
