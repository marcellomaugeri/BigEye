"""Exact-label cleanup of disposable BigEye campaign resources."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
import shutil
import stat
from uuid import uuid4

from backend.fuzzing.docker.fuzz_contract import (
    CAMPAIGN_LABEL,
    COMMIT_LABEL,
    ENGINE_LABEL,
    IMAGE_LABEL,
    MANAGED_LABEL,
    PROJECT_LABEL,
)


_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_TEMPORARY_MARKER = ".bigeye-temporary.json"
_MAX_MARKER_BYTES = 4_096
_MAX_IMAGES = 4_096
_MAX_CONTAINERS = 4_096
_LAYER_ORDER = {"coverage": 0, "target": 1, "project": 2, "repository": 3}
_ACTIVE_STATES = frozenset({"created", "running", "restarting", "paused"})


@dataclass(frozen=True)
class CleanupResult:
    removed_contexts: tuple[str, ...]
    removed_container_ids: tuple[str, ...]
    removed_image_ids: tuple[str, ...]


class ProjectCleaner:
    """Remove only old, exact-identity disposable state for one project commit."""

    def __init__(self, client, workspace_root: Path, *, grace_seconds: int = 300, clock):
        if type(grace_seconds) is not int or not 1 <= grace_seconds <= 86_400:
            raise ValueError("cleanup grace must be between one second and one day")
        self._client = client
        self._workspace = Path(os.path.abspath(workspace_root))
        descriptor = _open_absolute_directory(self._workspace)
        try:
            current = os.fstat(descriptor)
            self._workspace_identity = (current.st_dev, current.st_ino)
        finally:
            os.close(descriptor)
        self._grace = timedelta(seconds=grace_seconds)
        self._clock = clock
        self._removed_containers: set[str] = set()
        self._removed_images: set[str] = set()

    def clean(
        self, project_id: int, commit_sha: str, *, referenced_image_ids,
    ) -> CleanupResult:
        _positive(project_id, "project ID")
        _commit(commit_sha)
        referenced = _image_ids(referenced_image_ids)
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("cleanup clock must return an aware datetime")

        images = self._owned_images(project_id, commit_sha)
        image_by_id = {str(image.id): image for image in images}
        removed_contexts = self._clean_contexts(project_id, commit_sha, now)
        removed_containers = self._clean_containers(
            project_id, commit_sha, now, image_by_id,
        )
        removed_images = self._clean_images(
            project_id, commit_sha, now, referenced, images,
        )
        return CleanupResult(
            tuple(sorted(removed_contexts)),
            tuple(sorted(removed_containers)),
            tuple(sorted(removed_images)),
        )

    def _owned_images(self, project_id: int, commit_sha: str) -> tuple:
        images = self._client.images.list(filters={"label": [
            f"bigeye.project={project_id}", f"bigeye.commit={commit_sha}",
        ]})
        if not isinstance(images, list) or len(images) > _MAX_IMAGES:
            raise ValueError("cleanup image listing is invalid or exceeds its bound")
        return tuple(
            image for image in images
            if self._image_matches(image, project_id, commit_sha)
        )

    def _clean_containers(self, project_id: int, commit_sha: str, now: datetime, image_by_id) -> list[str]:
        containers = self._client.containers.list(all=True, filters={"label": [
            f"{MANAGED_LABEL}=fuzz-campaign", f"{PROJECT_LABEL}={project_id}",
        ]})
        if not isinstance(containers, list) or len(containers) > _MAX_CONTAINERS:
            raise ValueError("cleanup container listing is invalid or exceeds its bound")
        removed = []
        for container in containers:
            container_id = str(getattr(container, "id", ""))
            if not container_id or container_id in self._removed_containers:
                continue
            container.reload()
            attrs = getattr(container, "attrs", None)
            if not self._container_matches(attrs, project_id, commit_sha, image_by_id):
                continue
            state = attrs["State"]["Status"]
            if state in _ACTIVE_STATES or not self._old_enough(attrs["State"].get("FinishedAt"), now):
                continue
            container.remove(force=False)
            self._removed_containers.add(container_id)
            removed.append(container_id)
        return removed

    def _clean_images(
        self, project_id: int, commit_sha: str, now: datetime,
        referenced: frozenset[str], images: tuple,
    ) -> list[str]:
        removed = []
        ordered = sorted(
            images,
            key=lambda image: _LAYER_ORDER.get(
                ((image.attrs.get("Config") or {}).get("Labels") or {}).get("bigeye.layer"),
                99,
            ),
        )
        for image in ordered:
            image_id = str(image.id)
            if image_id in referenced or image_id in self._removed_images:
                continue
            if not self._old_enough(image.attrs.get("Created"), now):
                continue
            users = self._client.containers.list(all=True, filters={"ancestor": image_id})
            if users:
                continue
            self._client.images.remove(image_id, force=False, noprune=True)
            self._removed_images.add(image_id)
            removed.append(image_id)
        return removed

    def _clean_contexts(self, project_id: int, commit_sha: str, now: datetime) -> list[str]:
        root = self._open_workspace()
        parent = None
        try:
            parent = root
            for component in ("projects", str(project_id), "build-contexts"):
                try:
                    child = _open_component(parent, component)
                except FileNotFoundError:
                    return []
                if parent != root:
                    os.close(parent)
                parent = child
            removed = []
            for name in sorted(os.listdir(parent)):
                if not name.startswith(".temporary-"):
                    continue
                try:
                    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(current.st_mode):
                    continue
                candidate = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent,
                )
                try:
                    marker = self._read_context_marker(candidate)
                    if not self._context_marker_matches(marker, project_id, commit_sha, now):
                        continue
                    held = os.fstat(candidate)
                    quarantine_name = f".cleanup-{uuid4().hex}"
                    os.rename(name, quarantine_name, src_dir_fd=parent, dst_dir_fd=parent)
                    renamed = os.open(
                        quarantine_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent,
                    )
                    try:
                        after = os.fstat(renamed)
                        if (after.st_dev, after.st_ino) != (held.st_dev, held.st_ino):
                            raise RuntimeError("temporary context identity changed during cleanup")
                    finally:
                        os.close(renamed)
                    shutil.rmtree(quarantine_name, dir_fd=parent)
                    os.fsync(parent)
                    removed.append(
                        (self._workspace / "projects" / str(project_id) / "build-contexts" / name).as_posix()
                    )
                finally:
                    os.close(candidate)
            return removed
        finally:
            if parent is not None and parent != root:
                os.close(parent)
            os.close(root)

    @staticmethod
    def _read_context_marker(directory: int):
        try:
            descriptor = os.open(
                _TEMPORARY_MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory,
            )
        except FileNotFoundError:
            return None
        try:
            current = os.fstat(descriptor)
            if not stat.S_ISREG(current.st_mode) or current.st_size > _MAX_MARKER_BYTES:
                return None
            content = os.read(descriptor, _MAX_MARKER_BYTES + 1)
            if len(content) > _MAX_MARKER_BYTES:
                return None
            value = json.loads(content.decode("utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        finally:
            os.close(descriptor)

    def _context_marker_matches(
        self, marker, project_id: int, commit_sha: str, now: datetime,
    ) -> bool:
        return (
            isinstance(marker, dict)
            and set(marker) == {"managed", "project_id", "commit_sha", "created_at"}
            and marker.get("managed") == "temporary-build-context"
            and marker.get("project_id") == project_id
            and marker.get("commit_sha") == commit_sha
            and self._old_enough(marker.get("created_at"), now)
        )

    @staticmethod
    def _image_matches(image, project_id: int, commit_sha: str) -> bool:
        attrs = getattr(image, "attrs", None)
        if not isinstance(attrs, dict) or str(getattr(image, "id", "")) != attrs.get("Id"):
            return False
        labels = (attrs.get("Config") or {}).get("Labels") or {}
        if (
            attrs.get("Os") != "linux"
            or attrs.get("Architecture") != "amd64"
            or _IMAGE_ID.fullmatch(attrs.get("Id", "")) is None
            or labels.get("bigeye.project") != str(project_id)
            or labels.get("bigeye.commit") != commit_sha
            or labels.get("bigeye.layer") not in _LAYER_ORDER
            or _SHA256.fullmatch(labels.get("bigeye.content-hash", "")) is None
            or _IMAGE_ID.fullmatch(labels.get("bigeye.parent-image", "")) is None
        ):
            return False
        if labels["bigeye.layer"] == "target":
            return (
                _positive_text(labels.get("bigeye.target-asset"))
                and _SHA256.fullmatch(labels.get("bigeye.target-content-hash", "")) is not None
            )
        if labels["bigeye.layer"] == "coverage":
            return all(_positive_text(labels.get(key)) for key in (
                "bigeye.target-asset-id", "bigeye.configuration-asset-id", "bigeye.coverage-asset-id",
            ))
        return True

    @staticmethod
    def _container_matches(attrs, project_id: int, commit_sha: str, image_by_id) -> bool:
        if not isinstance(attrs, dict):
            return False
        labels = (attrs.get("Config") or {}).get("Labels") or {}
        state = attrs.get("State") or {}
        image_id = attrs.get("Image")
        expected = {
            MANAGED_LABEL: "fuzz-campaign",
            PROJECT_LABEL: str(project_id),
            COMMIT_LABEL: commit_sha,
            IMAGE_LABEL: image_id,
        }
        return (
            attrs.get("Platform") == "linux"
            and image_id in image_by_id
            and all(labels.get(key) == value for key, value in expected.items())
            and _positive_text(labels.get(CAMPAIGN_LABEL))
            and labels.get(ENGINE_LABEL) in {"afl", "libfuzzer"}
            and isinstance(state.get("Status"), str)
        )

    def _old_enough(self, value, now: datetime) -> bool:
        parsed = _timestamp(value)
        return parsed is not None and parsed <= now - self._grace

    def _open_workspace(self) -> int:
        descriptor = _open_absolute_directory(self._workspace)
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != self._workspace_identity:
            os.close(descriptor)
            raise ValueError("cleanup workspace root changed after initialisation")
        return descriptor


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("cleanup workspace root must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = _open_component(descriptor, component)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_component(parent: int, component: str) -> int:
    if not component or component in {".", ".."} or "/" in component:
        raise ValueError("cleanup path component is invalid")
    return os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


def _timestamp(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _image_ids(values) -> frozenset[str]:
    if (
        not isinstance(values, (tuple, list, set, frozenset))
        or len(values) > _MAX_IMAGES
        or any(not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None for value in values)
    ):
        raise ValueError("referenced cleanup image IDs are invalid or exceed their bound")
    return frozenset(values)


def _positive(value, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"cleanup {name} must be positive")


def _positive_text(value) -> bool:
    return isinstance(value, str) and value.isdigit() and int(value) > 0


def _commit(value) -> None:
    if not isinstance(value, str) or _OBJECT_ID.fullmatch(value) is None:
        raise ValueError("cleanup commit must be a lowercase hexadecimal object ID")
