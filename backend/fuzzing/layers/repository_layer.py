"""Build an immutable Docker layer from a checked-out repository."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import threading
from hashlib import sha256
from pathlib import Path

from backend.fuzzing.layers.manifest import LayerManifest


_EXCLUDED_DIRECTORIES = frozenset({".git", "workspace", ".aws", ".ssh", "credentials", "secrets"})
_EXCLUDED_FILE_NAMES = frozenset({".env", ".netrc", "credentials", "credentials.json", "id_rsa", "id_ed25519"})
_EXCLUDED_SUFFIXES = (".env", ".key", ".pem", ".p12", ".pfx")


class RepositoryLayerService:
    """Create and reuse repository layers only from a safe, immutable context."""

    _tag_locks: dict[str, threading.Lock] = {}
    _tag_locks_guard = threading.Lock()

    def __init__(self, workspace: Path, image_builder, inspector):
        self._workspace = Path(workspace)
        self._image_builder = image_builder
        self._inspector = inspector

    def prepare(self, project_id: int, repository_root: Path, commit_sha: str, parent_tag: str, sink) -> LayerManifest:
        repository_root = Path(repository_root).resolve(strict=True)
        parent = self._inspector.inspect(parent_tag)
        context_digest = self._context_digest(repository_root)
        template = self._dockerfile(parent_tag, parent.image_id, project_id, commit_sha, "{content_hash}")
        content_hash = self._digest(parent.image_id, commit_sha, template, context_digest)
        labels = {
            "bigeye.project": str(project_id),
            "bigeye.commit": commit_sha,
            "bigeye.layer": "repository",
            "bigeye.content-hash": content_hash,
            "bigeye.parent-image": parent.image_id,
        }
        dockerfile_text = self._dockerfile(parent_tag, parent.image_id, project_id, commit_sha, content_hash)
        tag_hash = self._digest(parent.image_id, commit_sha, dockerfile_text, context_digest)
        tag = f"bigeye-repository:{tag_hash[:20]}"
        layer_root = self._workspace / "projects" / str(project_id) / "layers" / tag_hash
        context_dir = layer_root / "context"
        dockerfile = context_dir / "Dockerfile"
        with self._lock_for(tag):
            layers_root = layer_root.parent
            layers_root.mkdir(parents=True, exist_ok=True)
            if layer_root.exists() or layer_root.is_symlink():
                if not self._valid_context(context_dir, dockerfile_text, context_digest):
                    self._remove_generated(layer_root, layers_root)
            if not layer_root.exists():
                self._publish_context(layers_root, layer_root, repository_root, dockerfile_text, context_digest)
            manifest = LayerManifest("repository", tag, content_hash, parent_tag, dockerfile, context_dir, labels)
            if self._image_builder.inspect_matching(tag, labels) is None:
                self._image_builder.build(dockerfile, tag, sink)
            return manifest

    @classmethod
    def _lock_for(cls, tag: str) -> threading.Lock:
        with cls._tag_locks_guard:
            return cls._tag_locks.setdefault(tag, threading.Lock())

    @staticmethod
    def _digest(parent_id: str, commit_sha: str, dockerfile: str, context_digest: str) -> str:
        return sha256(b"\0".join(item.encode("utf-8") for item in (parent_id, commit_sha, dockerfile, context_digest))).hexdigest()

    @classmethod
    def _context_digest(cls, root: Path) -> str:
        digest = sha256()
        for kind, relative, source, mode, link_target in cls._safe_entries(root):
            cls._hash_field(digest, kind.encode("ascii"))
            cls._hash_field(digest, relative.as_posix().encode("utf-8"))
            cls._hash_field(digest, f"{mode:o}".encode("ascii") if mode is not None else b"")
            if kind == "file":
                cls._hash_field(digest, source.read_bytes())
            elif kind == "symlink":
                cls._hash_field(digest, link_target.encode("utf-8"))
        return digest.hexdigest()

    @classmethod
    def _populate_context(cls, root: Path, destination: Path) -> None:
        entries = list(cls._safe_entries(root))
        directories = [entry for entry in entries if entry[0] == "directory"]
        for _, relative, _, _, _ in directories:
            (destination / relative).mkdir(parents=True, exist_ok=True)
        for kind, relative, source, mode, link_target in entries:
            target = destination / relative
            if kind == "symlink":
                target.symlink_to(link_target)
            elif kind == "file":
                shutil.copyfile(source, target)
                target.chmod(mode)
        for _, relative, _, mode, _ in reversed(directories):
            (destination / relative).chmod(mode)

    @classmethod
    def _safe_entries(cls, root: Path):
        root = root.resolve(strict=True)
        yield "directory", Path("."), root, stat.S_IMODE(root.stat().st_mode), ""
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(root)
            if cls._is_excluded(relative):
                continue
            if path.is_symlink():
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(root)
                except (FileNotFoundError, ValueError):
                    continue
                link_target = Path(os.path.relpath(resolved, start=path.parent)).as_posix()
                yield "symlink", relative, path, None, link_target
            elif path.is_dir():
                yield "directory", relative, path, stat.S_IMODE(path.stat().st_mode), ""
            elif path.is_file():
                yield "file", relative, path, stat.S_IMODE(path.stat().st_mode), ""

    @staticmethod
    def _hash_field(digest, value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    @staticmethod
    def _is_excluded(relative: Path) -> bool:
        return (
            any(part in _EXCLUDED_DIRECTORIES for part in relative.parts)
            or relative.name in _EXCLUDED_FILE_NAMES
            or relative.name.endswith(_EXCLUDED_SUFFIXES)
        )

    @classmethod
    def _valid_context(cls, context_dir: Path, dockerfile_text: str, expected_digest: str) -> bool:
        repository = context_dir / "repository"
        dockerfile = context_dir / "Dockerfile"
        if (
            context_dir.is_symlink()
            or repository.is_symlink()
            or dockerfile.is_symlink()
            or not repository.is_dir()
            or not dockerfile.is_file()
        ):
            return False
        try:
            if (
                {path.name for path in context_dir.iterdir()} != {"Dockerfile", "repository"}
                or dockerfile.read_text() != dockerfile_text
                or not cls._contains_only_safe_entries(repository)
            ):
                return False
            return cls._context_digest(repository) == expected_digest
        except OSError:
            return False

    @classmethod
    def _contains_only_safe_entries(cls, root: Path) -> bool:
        for path in root.rglob("*"):
            relative = path.relative_to(root)
            if cls._is_excluded(relative):
                return False
            if path.is_symlink():
                if os.path.isabs(os.readlink(path)):
                    return False
                try:
                    path.resolve(strict=True).relative_to(root)
                except (FileNotFoundError, ValueError):
                    return False
            elif not (path.is_dir() or path.is_file()):
                return False
        return True

    @classmethod
    def _publish_context(
        cls,
        layers_root: Path,
        layer_root: Path,
        repository_root: Path,
        dockerfile_text: str,
        expected_digest: str,
    ) -> None:
        staging = Path(tempfile.mkdtemp(prefix=f".{layer_root.name}.staging-", dir=layers_root))
        try:
            context = staging / "context"
            cls._populate_context(repository_root, context / "repository")
            context.mkdir(parents=True, exist_ok=True)
            (context / "Dockerfile").write_text(dockerfile_text)
            if not cls._valid_context(context, dockerfile_text, expected_digest):
                raise RuntimeError("generated repository context failed validation")
            os.replace(staging, layer_root)
        finally:
            if staging.exists() and not staging.is_symlink():
                shutil.rmtree(staging)

    @staticmethod
    def _remove_generated(layer_root: Path, layers_root: Path) -> None:
        if layer_root.parent.resolve(strict=True) != layers_root.resolve(strict=True):
            raise RuntimeError("generated repository context escaped its layer root")
        if layer_root.is_symlink() or not layer_root.is_dir():
            layer_root.unlink()
        else:
            shutil.rmtree(layer_root)

    @staticmethod
    def _dockerfile(parent_tag: str, parent_id: str, project_id: int, commit_sha: str, content_hash: str) -> str:
        return (
            f"FROM {parent_tag}\n"
            "WORKDIR /src\n"
            "COPY repository/ /src/\n"
            f"LABEL bigeye.project=\"{project_id}\" bigeye.commit=\"{commit_sha}\" "
            f"bigeye.layer=\"repository\" bigeye.content-hash=\"{content_hash}\" "
            f"bigeye.parent-image=\"{parent_id}\"\n"
        )
