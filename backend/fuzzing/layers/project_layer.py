"""Reusable dependency layer built from a clean repository layer and build asset."""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import re
from hashlib import sha256
from pathlib import Path

from backend.fuzzing.layers.manifest import LayerManifest
from backend.fuzzing.layers.policy import validate_generated_dockerfile
from backend.fuzzing.assets.validation import collection_hash
from backend.fuzzing.docker.image_builder import ImageBuildCancelled


_CONTENT_HASH_SENTINEL = "__BIGEYE_CONTENT_HASH_SENTINEL__"


class _GeneratedLayerService:
    """Shared implementation for content-addressed generated build contexts."""

    _tag_locks: dict[str, threading.Lock] = {}
    _tag_locks_guard = threading.Lock()

    def __init__(self, workspace: Path, image_builder, inspector):
        self._workspace = Path(workspace).resolve()
        self._image_builder = image_builder
        self._inspector = inspector

    @classmethod
    def _lock_for(cls, tag: str) -> threading.Lock:
        with cls._tag_locks_guard:
            return cls._tag_locks.setdefault(tag, threading.Lock())

    def _prepare(
        self, project, parent_manifest: LayerManifest, assets, dockerfile_template: str,
        sink, network_mode: str | None, cancellation_signal=None, extra_labels=None,
    ):
        if cancellation_signal is not None and cancellation_signal.is_set():
            raise ImageBuildCancelled(f"{self._kind} layer build cancelled")
        if parent_manifest.kind != self._parent_kind:
            raise ValueError(f"{self._kind} layers require a {self._parent_kind} parent")
        project_id = self._project_id(project)
        commit_sha = self._commit(project)
        parent = self._verify_parent(parent_manifest, project_id, commit_sha)
        assets = tuple(assets)
        extra_labels = self._validate_extra_labels(extra_labels)
        asset_digest = self._assets_digest(project_id, assets)
        starter = dockerfile_template.format(
            parent=parent_manifest.tag,
            parent_image=parent.image_id,
            content_hash=_CONTENT_HASH_SENTINEL,
        )
        template = self._asset_dockerfile(project_id, assets, starter, parent.image_id, project_id, commit_sha)
        if extra_labels:
            template = template.rstrip() + "\nLABEL " + " ".join(
                f'{key}="{value}"' for key, value in sorted(extra_labels.items())
            ) + "\n"
        if template.count(_CONTENT_HASH_SENTINEL) != 1:
            raise ValueError("generated Dockerfile content hash sentinel is invalid")
        content_hash = self._digest(parent.image_id, commit_sha, template, asset_digest)
        kind = self._kind
        dockerfile_text = template.replace(_CONTENT_HASH_SENTINEL, content_hash)
        validate_generated_dockerfile(dockerfile_text, parent_manifest.tag, allow_network=self._network_allowed)
        tag_hash = self._digest(parent.image_id, commit_sha, dockerfile_text, asset_digest)
        tag = f"bigeye-{kind}:{tag_hash[:20]}"
        labels = {
            "bigeye.project": str(project_id),
            "bigeye.commit": commit_sha,
            "bigeye.layer": kind,
            "bigeye.content-hash": content_hash,
            "bigeye.parent-image": parent.image_id,
        }
        labels.update(extra_labels)
        root = self._workspace / "projects" / str(project_id) / "build-contexts" / f"{kind}-{tag_hash}"
        context_dir = root / "context"
        dockerfile = context_dir / "Dockerfile"
        with self._lock_for(tag):
            if cancellation_signal is not None and cancellation_signal.is_set():
                raise ImageBuildCancelled(f"{self._kind} layer build cancelled")
            root.parent.mkdir(parents=True, exist_ok=True)
            if root.exists() or root.is_symlink():
                if not self._valid_context(context_dir, dockerfile_text, project_id, assets):
                    self._remove_context(root, root.parent)
            if not root.exists():
                self._publish_context(root.parent, root, dockerfile_text, project_id, assets)
            manifest = LayerManifest(kind, tag, content_hash, parent_manifest.tag, dockerfile, context_dir, labels)
            if self._image_builder.inspect_matching(tag, labels) is None:
                if cancellation_signal is not None and cancellation_signal.is_set():
                    raise ImageBuildCancelled(f"{self._kind} layer build cancelled")
                build_arguments = {"sink": sink, "network_mode": network_mode}
                if cancellation_signal is not None:
                    build_arguments["cancellation_signal"] = cancellation_signal
                self._image_builder.build(dockerfile, tag, **build_arguments)
            return manifest

    @staticmethod
    def _validate_extra_labels(labels):
        if labels is None:
            return {}
        reserved = {
            "bigeye.project", "bigeye.commit", "bigeye.layer",
            "bigeye.content-hash", "bigeye.parent-image",
        }
        if (
            not isinstance(labels, dict)
            or any(
                not isinstance(key, str)
                or re.fullmatch(r"bigeye\.[a-z0-9-]+", key) is None
                or key in reserved
                or not isinstance(value, str)
                or not value
                or len(value) > 256
                or any(character in value for character in "\"\\\r\n")
                for key, value in labels.items()
            )
        ):
            raise ValueError("generated layer labels are invalid")
        return dict(labels)

    def _assets_digest(self, project_id: int, assets) -> str:
        digest = sha256()
        for context_name, asset in assets:
            self._validated_asset(project_id, asset)
            path = self._asset_path(project_id, asset)
            if not path.is_dir() or path.is_symlink():
                raise ValueError("validated asset directory is missing")
            for entry in path.rglob("*"):
                if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
                    raise ValueError("asset path contains an unsafe entry")
            files = {
                entry.relative_to(path).as_posix(): (entry, None)
                for entry in path.rglob("*") if entry.is_file() and not entry.is_symlink()
            }
            if collection_hash(files, asset.kind) != asset.content_hash:
                raise ValueError("validated asset content hash does not match its files")
            field = f"{context_name}\0{asset.id}\0{asset.content_hash}".encode("utf-8")
            digest.update(len(field).to_bytes(8, "big")); digest.update(field)
            for entry in sorted(path.rglob("*"), key=lambda item: item.as_posix()):
                if entry.is_dir():
                    continue
                relative = entry.relative_to(path).as_posix().encode("utf-8")
                data = entry.read_bytes()
                for value in (relative, data):
                    digest.update(len(value).to_bytes(8, "big")); digest.update(value)
        return digest.hexdigest()

    def _verify_parent(self, parent_manifest: LayerManifest, project_id: int, commit_sha: str):
        labels = parent_manifest.labels
        expected = {
            "bigeye.project": str(project_id),
            "bigeye.commit": commit_sha,
            "bigeye.layer": parent_manifest.kind,
            "bigeye.content-hash": parent_manifest.content_hash,
        }
        if any(labels.get(key) != value for key, value in expected.items()):
            raise ValueError("parent manifest does not belong to this project and commit")
        if not isinstance(labels.get("bigeye.parent-image"), str) or not labels["bigeye.parent-image"]:
            raise ValueError("parent manifest is missing its parent image label")
        parent = self._inspector.inspect(parent_manifest.tag)
        verifier = getattr(self._image_builder, "verify_parent", None)
        if verifier is None or not verifier(parent_manifest.tag, labels, parent.image_id):
            raise ValueError("parent tag no longer matches its inspected manifest labels")
        return parent

    def _asset_dockerfile(self, project_id: int, assets, starter: str, parent_image: str, project: int, commit: str) -> str:
        _, asset = assets[self._dockerfile_asset_index]
        candidate = self._asset_path(project_id, asset) / "Dockerfile"
        if not candidate.exists():
            return starter
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("asset Dockerfile must be a regular file")
        text = candidate.read_text(encoding="utf-8")
        if _CONTENT_HASH_SENTINEL in text:
            raise ValueError("asset Dockerfile uses a reserved BigEye sentinel")
        return (
            text.rstrip() + "\n"
            f"LABEL bigeye.project=\"{project}\" bigeye.commit=\"{commit}\" "
            f"bigeye.layer=\"{self._kind}\" bigeye.content-hash=\"{_CONTENT_HASH_SENTINEL}\" "
            f"bigeye.parent-image=\"{parent_image}\"\n"
        )

    def _asset_path(self, project_id: int, asset) -> Path:
        if isinstance(asset.id, bool) or not isinstance(asset.id, int) or asset.id <= 0:
            raise ValueError("asset ID must be positive")
        return self._workspace / "projects" / str(project_id) / "assets" / str(asset.id)

    @staticmethod
    def _validated_asset(project_id: int, asset) -> None:
        if getattr(asset, "project_id", None) != project_id:
            raise ValueError("asset does not belong to this project")
        if getattr(asset, "validated_at", None) is None or getattr(asset, "error", None) is not None:
            raise ValueError("asset must be validated without an error")

    @staticmethod
    def _asset_entrypoint(asset) -> str:
        name = getattr(asset, "name", "")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", name):
            raise ValueError("asset script name is unsafe for a Dockerfile")
        return name

    @staticmethod
    def _digest(*values: str) -> str:
        return sha256(b"\0".join(value.encode("utf-8") for value in values)).hexdigest()

    @staticmethod
    def _project_id(project) -> int:
        if isinstance(project.id, bool) or not isinstance(project.id, int) or project.id <= 0:
            raise ValueError("project ID must be positive")
        return project.id

    @staticmethod
    def _commit(project) -> str:
        if not isinstance(project.commit_sha, str) or not project.commit_sha:
            raise ValueError("project must have a resolved commit")
        return project.commit_sha

    def _valid_context(self, context: Path, dockerfile_text: str, project_id: int, assets) -> bool:
        dockerfile = context / "Dockerfile"
        if context.is_symlink() or dockerfile.is_symlink() or not dockerfile.is_file():
            return False
        try:
            if dockerfile.read_text() != dockerfile_text:
                return False
            expected = {"Dockerfile", *(name for name, _ in assets)}
            if {entry.name for entry in context.iterdir()} != expected:
                return False
            for name, asset in assets:
                generated = context / name
                source = self._asset_path(project_id, asset)
                if generated.is_symlink() or not generated.is_dir() or self._tree_digest(generated) != self._tree_digest(source):
                    return False
            return True
        except (OSError, ValueError):
            return False

    @staticmethod
    def _tree_digest(root: Path) -> str:
        digest = sha256()
        for entry in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if entry.is_dir():
                continue
            if entry.is_symlink() or not entry.is_file():
                raise ValueError("generated context contains an unsafe entry")
            relative = entry.relative_to(root).as_posix().encode("utf-8")
            data = entry.read_bytes()
            for value in (relative, data):
                digest.update(len(value).to_bytes(8, "big")); digest.update(value)
        return digest.hexdigest()

    def _publish_context(self, parent: Path, destination: Path, dockerfile_text: str, project_id: int, assets) -> None:
        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=parent))
        try:
            context = staging / "context"
            context.mkdir()
            (context / "Dockerfile").write_text(dockerfile_text)
            for name, asset in assets:
                source = self._asset_path(project_id, asset)
                if source.is_symlink() or not source.is_dir():
                    raise ValueError("validated asset directory is missing")
                shutil.copytree(source, context / name, symlinks=True)
                staged_files = {
                    entry.relative_to(context / name).as_posix(): (entry, None)
                    for entry in (context / name).rglob("*") if entry.is_file() and not entry.is_symlink()
                }
                for entry in (context / name).rglob("*"):
                    if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
                        raise ValueError("generated context contains an unsafe asset entry")
                if collection_hash(staged_files, asset.kind) != asset.content_hash:
                    raise ValueError("generated context asset content hash does not match persisted asset")
            self._fsync_tree(context)
            os.replace(staging, destination)
            self._fsync_directory(parent)
        finally:
            if staging.exists() and not staging.is_symlink():
                shutil.rmtree(staging)

    @classmethod
    def _fsync_tree(cls, root: Path) -> None:
        for directory, _, files in os.walk(root, topdown=False):
            folder = Path(directory)
            for name in files:
                with (folder / name).open("rb") as handle:
                    os.fsync(handle.fileno())
            cls._fsync_directory(folder)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _remove_context(path: Path, parent: Path) -> None:
        if path.parent.resolve(strict=True) != parent.resolve(strict=True):
            raise RuntimeError("generated context escaped its project")
        if path.is_symlink():
            path.unlink()
        else:
            shutil.rmtree(path)


class ProjectLayerService(_GeneratedLayerService):
    """Build project dependencies, the only generated layer allowed build-time network access."""

    _kind = "project"
    _parent_kind = "repository"
    _network_allowed = True
    _dockerfile_asset_index = 0

    def prepare(
        self, project, repository_manifest: LayerManifest, build_asset, sink,
        cancellation_signal=None,
    ) -> LayerManifest:
        parent_image = self._inspector.inspect(repository_manifest.tag).image_id
        build_name = self._asset_entrypoint(build_asset)
        template = (
            "FROM {parent}\nWORKDIR /src\nCOPY build/ /bigeye/build/\n"
            "RUN /bin/sh /bigeye/build/" + build_name + "\n"
            f"LABEL bigeye.project=\"{project.id}\" bigeye.commit=\"{project.commit_sha}\" "
            "bigeye.layer=\"project\" bigeye.content-hash=\"{content_hash}\" "
            f"bigeye.parent-image=\"{parent_image}\"\n"
        )
        return self._prepare(
            project, repository_manifest, (("build", build_asset),), template, sink, None,
            cancellation_signal,
        )
