"""Exact-label cleanup of disposable BigEye campaign resources."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
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
_MAX_COPIES = 20_000
_MAX_COPY_BYTES = 16 * 1_048_576
_LAYER_ORDER = {"coverage": 0, "target": 1}
_ACTIVE_STATES = frozenset({"created", "running", "restarting", "paused"})


@dataclass(frozen=True, order=True)
class CleanupAssetIdentity:
    """One persisted asset identity used to author a disposable image."""

    role: str
    asset_id: int
    content_hash: str

    def __post_init__(self) -> None:
        if (
            self.role not in {"target", "configuration", "coverage"}
            or type(self.asset_id) is not int
            or self.asset_id <= 0
            or not isinstance(self.content_hash, str)
            or _SHA256.fullmatch(self.content_hash) is None
        ):
            raise ValueError("cleanup asset identity is invalid")


@dataclass(frozen=True)
class CleanupImageIdentity:
    """Persisted manifest identity required before deleting one target or coverage image."""

    image_id: str
    layer: str
    content_hash: str
    parent_image_id: str
    asset_identities: tuple[CleanupAssetIdentity, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.image_id, str)
            or _IMAGE_ID.fullmatch(self.image_id) is None
            or self.layer not in _LAYER_ORDER
            or not isinstance(self.content_hash, str)
            or _SHA256.fullmatch(self.content_hash) is None
            or not isinstance(self.parent_image_id, str)
            or _IMAGE_ID.fullmatch(self.parent_image_id) is None
            or not isinstance(self.asset_identities, tuple)
            or not self.asset_identities
            or len(self.asset_identities) > 3
            or any(not isinstance(item, CleanupAssetIdentity) for item in self.asset_identities)
        ):
            raise ValueError("cleanup image identity is invalid")
        assets = tuple(sorted(self.asset_identities))
        if len({item.role for item in assets}) != len(assets):
            raise ValueError("cleanup image asset roles must be unique")
        expected_roles = {"target"} if self.layer == "target" else {
            "target", "configuration", "coverage",
        }
        if {item.role for item in assets} != expected_roles:
            raise ValueError("cleanup image asset roles do not match its layer")
        object.__setattr__(self, "asset_identities", assets)


@dataclass(frozen=True)
class RedundantCorpusCopy:
    """Persisted proof that one raw queue file has an exact durable corpus copy."""

    campaign_id: int
    raw_relative_path: str
    durable_relative_path: str
    content_sha256: str
    provenance_id: str

    def __post_init__(self) -> None:
        _recorded_copy(self, "queue", "corpus")


@dataclass(frozen=True)
class DuplicateCrashCopy:
    """Persisted proof that one raw crash has an exact durable finding copy."""

    campaign_id: int
    raw_relative_path: str
    durable_relative_path: str
    content_sha256: str
    provenance_id: str

    def __post_init__(self) -> None:
        _recorded_copy(self, "crashes", "finding")


@dataclass(frozen=True)
class CleanupResult:
    removed_contexts: tuple[str, ...]
    removed_container_ids: tuple[str, ...]
    removed_image_ids: tuple[str, ...]
    removed_raw_corpus_copies: tuple[str, ...] = ()
    removed_duplicate_crash_copies: tuple[str, ...] = ()


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
        persisted_image_identities,
        redundant_corpus_copies=(),
        duplicate_crash_copies=(),
    ) -> CleanupResult:
        _positive(project_id, "project ID")
        _commit(commit_sha)
        referenced = _image_ids(referenced_image_ids)
        image_identities = _persisted_images(persisted_image_identities)
        corpus_copies = _recorded_copies(
            redundant_corpus_copies, RedundantCorpusCopy, "redundant corpus copies",
        )
        crash_copies = _recorded_copies(
            duplicate_crash_copies, DuplicateCrashCopy, "duplicate crash copies",
        )
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("cleanup clock must return an aware datetime")

        images = self._owned_images(project_id, commit_sha, image_identities)
        image_by_id = {str(image.id): image for image in images}
        removed_contexts = self._clean_contexts(project_id, commit_sha, now)
        removed_containers = self._clean_containers(
            project_id, commit_sha, now, image_by_id,
        )
        removed_images = self._clean_images(
            project_id, commit_sha, now, referenced, images,
        )
        removed_corpus = self._clean_recorded_copies(project_id, corpus_copies)
        removed_crashes = self._clean_recorded_copies(project_id, crash_copies)
        return CleanupResult(
            tuple(sorted(removed_contexts)),
            tuple(sorted(removed_containers)),
            tuple(sorted(removed_images)),
            tuple(sorted(removed_corpus)),
            tuple(sorted(removed_crashes)),
        )

    def _owned_images(self, project_id: int, commit_sha: str, identities) -> tuple:
        images = self._client.images.list(filters={"label": [
            f"bigeye.project={project_id}", f"bigeye.commit={commit_sha}",
        ]})
        if not isinstance(images, list) or len(images) > _MAX_IMAGES:
            raise ValueError("cleanup image listing is invalid or exceeds its bound")
        all_images = {
            str(getattr(image, "id", "")): image for image in images
            if self._base_image_matches(image, project_id, commit_sha)
        }
        return tuple(
            image for image in images
            if (identity := identities.get(str(getattr(image, "id", "")))) is not None
            and self._image_matches(
                image, project_id, commit_sha, identity,
                all_images.get(identity.parent_image_id),
            )
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

    def _clean_recorded_copies(self, project_id: int, copies) -> list[str]:
        if not copies:
            return []
        root = self._open_workspace()
        project = None
        try:
            projects = _open_component(root, "projects")
            try:
                project = _open_component(projects, str(project_id))
            finally:
                os.close(projects)
            removed = []
            for copy in copies:
                raw_parts = (
                    "campaigns", str(copy.campaign_id),
                    *PurePosixPath(copy.raw_relative_path).parts,
                )
                durable_parts = PurePosixPath(copy.durable_relative_path).parts
                if self._remove_verified_copy(project, raw_parts, durable_parts, copy.content_sha256):
                    removed.append(self._workspace.joinpath("projects", str(project_id), *raw_parts).as_posix())
            return removed
        finally:
            if project is not None:
                os.close(project)
            os.close(root)

    @staticmethod
    def _remove_verified_copy(project: int, raw_parts, durable_parts, expected_hash: str) -> bool:
        raw_parent = durable_parent = raw = durable = None
        try:
            raw_parent = _open_relative_parent(project, raw_parts[:-1])
            durable_parent = _open_relative_parent(project, durable_parts[:-1])
            raw = os.open(raw_parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=raw_parent)
            durable = os.open(durable_parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=durable_parent)
            raw_content, raw_identity = _read_bounded_file(raw, _MAX_COPY_BYTES)
            durable_content, _ = _read_bounded_file(durable, _MAX_COPY_BYTES)
            if (
                sha256(raw_content).hexdigest() != expected_hash
                or sha256(durable_content).hexdigest() != expected_hash
                or raw_content != durable_content
            ):
                return False
            current = os.stat(raw_parts[-1], dir_fd=raw_parent, follow_symlinks=False)
            if _file_identity(current) != raw_identity:
                return False
            os.unlink(raw_parts[-1], dir_fd=raw_parent)
            os.fsync(raw_parent)
            return True
        except (FileNotFoundError, NotADirectoryError, OSError, ValueError):
            return False
        finally:
            for descriptor in (durable, raw, durable_parent, raw_parent):
                if descriptor is not None:
                    os.close(descriptor)

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
    def _base_image_matches(image, project_id: int, commit_sha: str) -> bool:
        attrs = getattr(image, "attrs", None)
        if not isinstance(attrs, dict) or str(getattr(image, "id", "")) != attrs.get("Id"):
            return False
        labels = (attrs.get("Config") or {}).get("Labels") or {}
        return (
            attrs.get("Os") == "linux"
            and attrs.get("Architecture") == "amd64"
            and _IMAGE_ID.fullmatch(attrs.get("Id", "")) is not None
            and labels.get("bigeye.project") == str(project_id)
            and labels.get("bigeye.commit") == commit_sha
            and isinstance((attrs.get("RootFS") or {}).get("Layers"), list)
        )

    @classmethod
    def _image_matches(cls, image, project_id: int, commit_sha: str, identity, parent) -> bool:
        if not cls._base_image_matches(image, project_id, commit_sha):
            return False
        if parent is None or not cls._base_image_matches(parent, project_id, commit_sha):
            return False
        attrs = image.attrs
        labels = (attrs.get("Config") or {}).get("Labels") or {}
        expected = {
            "bigeye.layer": identity.layer,
            "bigeye.content-hash": identity.content_hash,
            "bigeye.parent-image": identity.parent_image_id,
        }
        if any(labels.get(key) != value for key, value in expected.items()):
            return False
        assets = {item.role: item for item in identity.asset_identities}
        if identity.layer == "target" and (
            labels.get("bigeye.target-asset") != str(assets["target"].asset_id)
            or labels.get("bigeye.target-content-hash") != assets["target"].content_hash
        ):
            return False
        if identity.layer == "coverage" and any(
            labels.get(f"bigeye.{role}-asset-id") != str(assets[role].asset_id)
            for role in ("target", "configuration", "coverage")
        ):
            return False
        child_layers = _rootfs_layers(attrs)
        parent_layers = _rootfs_layers(parent.attrs)
        return (
            str(getattr(parent, "id", "")) == identity.parent_image_id
            and len(child_layers) > len(parent_layers)
            and child_layers[:len(parent_layers)] == parent_layers
        )

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


def _persisted_images(values) -> dict[str, CleanupImageIdentity]:
    if (
        not isinstance(values, (tuple, list))
        or len(values) > _MAX_IMAGES
        or any(not isinstance(value, CleanupImageIdentity) for value in values)
    ):
        raise ValueError("persisted cleanup image identities are invalid or exceed their bound")
    identities = {value.image_id: value for value in values}
    if len(identities) != len(values):
        raise ValueError("persisted cleanup image identities must be unique")
    return identities


def _recorded_copy(value, raw_kind: str, durable_kind: str) -> None:
    _positive(value.campaign_id, "campaign ID")
    raw = _safe_relative(value.raw_relative_path, "raw copy path")
    durable = _safe_relative(value.durable_relative_path, "durable copy path")
    raw_parts = raw.parts
    durable_parts = durable.parts
    if (
        len(raw_parts) < 4
        or raw_parts[0] != "output"
        or raw_kind not in raw_parts[1:-1]
        or not isinstance(value.content_sha256, str)
        or _SHA256.fullmatch(value.content_sha256) is None
        or not isinstance(value.provenance_id, str)
        or not 1 <= len(value.provenance_id) <= 512
        or not value.provenance_id.strip()
        or any(character in value.provenance_id for character in "\x00\r\n")
    ):
        raise ValueError("recorded cleanup copy is invalid")
    if durable_kind == "corpus":
        expected = ("campaigns", str(value.campaign_id), "corpus")
        if durable_parts[:3] != expected or len(durable_parts) < 4:
            raise ValueError("durable corpus copy path is invalid")
    elif (
        durable_parts[0] != "findings"
        and durable_parts[:2] != ("crashes", "quarantine")
    ):
        raise ValueError("durable crash copy path is invalid")
    object.__setattr__(value, "raw_relative_path", raw.as_posix())
    object.__setattr__(value, "durable_relative_path", durable.as_posix())


def _recorded_copies(values, expected_type, label: str) -> tuple:
    if (
        not isinstance(values, (tuple, list))
        or len(values) > _MAX_COPIES
        or any(not isinstance(value, expected_type) for value in values)
    ):
        raise ValueError(f"cleanup {label} are invalid or exceed their bound")
    paths = [
        (value.campaign_id, value.raw_relative_path)
        for value in values
    ]
    if len(paths) != len(set(paths)):
        raise ValueError(f"cleanup {label} must have unique raw paths")
    return tuple(values)


def _safe_relative(value, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise ValueError(f"cleanup {label} is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or len(path.parts) > 32
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"cleanup {label} must be contained and relative")
    return path


def _open_relative_parent(root: int, parts) -> int:
    descriptor = os.dup(root)
    try:
        for component in parts:
            child = _open_component(descriptor, component)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_bounded_file(descriptor: int, maximum: int):
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("cleanup copy is not a bounded regular file")
    content = bytearray()
    while len(content) <= maximum:
        block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(content)))
        if not block:
            break
        content.extend(block)
    after = os.fstat(descriptor)
    if len(content) > maximum or _file_identity(before) != _file_identity(after):
        raise ValueError("cleanup copy changed while being read")
    return bytes(content), _file_identity(before)


def _file_identity(details):
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns


def _rootfs_layers(attrs) -> tuple[str, ...]:
    layers = (attrs.get("RootFS") or {}).get("Layers") if isinstance(attrs, dict) else None
    if (
        not isinstance(layers, list)
        or not layers
        or any(not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None for value in layers)
    ):
        return ()
    return tuple(layers)


def _positive(value, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"cleanup {name} must be positive")


def _positive_text(value) -> bool:
    return isinstance(value, str) and value.isdigit() and int(value) > 0


def _commit(value) -> None:
    if not isinstance(value, str) or _OBJECT_ID.fullmatch(value) is None:
        raise ValueError("cleanup commit must be a lowercase hexadecimal object ID")
