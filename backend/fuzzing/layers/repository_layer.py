"""Build an immutable Docker layer from a checked-out repository."""

from __future__ import annotations

import os
import shutil
from hashlib import sha256
from pathlib import Path

from backend.fuzzing.layers.manifest import LayerManifest


_EXCLUDED_DIRECTORIES = frozenset({".git", "workspace", ".aws", ".ssh", "credentials", "secrets"})
_EXCLUDED_FILE_NAMES = frozenset({".env", ".netrc", "credentials", "credentials.json", "id_rsa", "id_ed25519"})
_EXCLUDED_SUFFIXES = (".env", ".key", ".pem", ".p12", ".pfx")


class RepositoryLayerService:
    """Create and reuse repository layers only from a safe, immutable context."""

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
        if not dockerfile.exists():
            self._populate_context(repository_root, context_dir / "repository")
            context_dir.mkdir(parents=True, exist_ok=True)
            dockerfile.write_text(dockerfile_text)
        manifest = LayerManifest("repository", tag, content_hash, parent_tag, dockerfile, context_dir, labels)
        if self._image_builder.inspect_matching(tag, labels) is None:
            self._image_builder.build(dockerfile, tag, sink)
        return manifest

    @staticmethod
    def _digest(parent_id: str, commit_sha: str, dockerfile: str, context_digest: str) -> str:
        return sha256(b"\0".join(item.encode("utf-8") for item in (parent_id, commit_sha, dockerfile, context_digest))).hexdigest()

    @classmethod
    def _context_digest(cls, root: Path) -> str:
        digest = sha256()
        for path in cls._safe_paths(root):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                digest.update(b"L\0" + relative.encode() + b"\0" + os.readlink(path).encode())
            elif path.is_file():
                digest.update(b"F\0" + relative.encode() + b"\0")
                digest.update(path.read_bytes())
        return digest.hexdigest()

    @classmethod
    def _populate_context(cls, root: Path, destination: Path) -> None:
        destination.mkdir(parents=True, exist_ok=True)
        for source in cls._safe_paths(root):
            target = destination / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                target.symlink_to(os.readlink(source))
            elif source.is_file():
                shutil.copyfile(source, target)

    @classmethod
    def _safe_paths(cls, root: Path):
        root = root.resolve(strict=True)
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(root)
            if any(part in _EXCLUDED_DIRECTORIES for part in relative.parts):
                continue
            if path.name in _EXCLUDED_FILE_NAMES or path.name.endswith(_EXCLUDED_SUFFIXES):
                continue
            if path.is_symlink():
                try:
                    path.resolve(strict=True).relative_to(root)
                except (FileNotFoundError, ValueError):
                    continue
            if path.is_file() or path.is_symlink():
                yield path

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
