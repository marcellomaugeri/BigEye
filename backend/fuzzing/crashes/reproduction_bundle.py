"""Immutable, contained finding reproduction bundles for safe asset lifecycle changes."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from types import MappingProxyType
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")


class ReproductionBundleRequest(BaseModel):
    """Exact validated dependencies that must survive source-asset deletion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: int = Field(ge=1)
    finding_id: int = Field(ge=1)
    commit_sha: str
    image_id: str
    command: tuple[str, ...] = Field(min_length=1, max_length=128)
    environment: tuple[tuple[str, str], ...] = Field(max_length=128)
    sanitizer: str = Field(min_length=1, max_length=200)
    configuration: str = Field(min_length=1, max_length=2_000)
    minimal_testcase: bytes = Field(max_length=16 * 1024 * 1024)
    target_asset_hash: str
    configuration_asset_hash: str
    coverage_asset_hash: str

    @model_validator(mode="after")
    def validate_exact_bundle(self):
        if _COMMIT.fullmatch(self.commit_sha) is None:
            raise ValueError("reproduction bundle commit is invalid")
        if _IMAGE.fullmatch(self.image_id) is None:
            raise ValueError("reproduction bundle image identity is invalid")
        if any(_DIGEST.fullmatch(value) is None for value in (
            self.target_asset_hash,
            self.configuration_asset_hash,
            self.coverage_asset_hash,
        )):
            raise ValueError("reproduction bundle asset hash is invalid")
        if not self.minimal_testcase:
            raise ValueError("reproduction bundle requires a minimal testcase")
        if any(
            not isinstance(value, str) or not value or len(value) > 4_096 or "\x00" in value
            for value in self.command
        ):
            raise ValueError("reproduction bundle command is invalid")
        if len(self.environment) != len({name for name, _value in self.environment}) or any(
            not isinstance(name, str) or not name or len(name) > 256
            or not isinstance(value, str) or len(value) > 8_192
            or "\x00" in name or "\x00" in value
            for name, value in self.environment
        ):
            raise ValueError("reproduction bundle environment is invalid")
        if "\x00" in self.sanitizer or "\x00" in self.configuration:
            raise ValueError("reproduction bundle configuration is invalid")
        return self


@dataclass(frozen=True)
class ReproductionBundle:
    bundle_id: str
    project_id: int
    finding_id: int
    root: Path
    manifest: MappingProxyType
    verified: bool


class ReproductionBundleStore:
    """Write and verify exact immutable bundle data below one workspace root."""

    def __init__(self, workspace: Path):
        root = Path(os.path.abspath(os.fspath(workspace)))
        if root.is_symlink():
            raise ValueError("reproduction bundle workspace must not be a symlink")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._workspace = root.resolve(strict=True)

    async def freeze(self, request: ReproductionBundleRequest) -> ReproductionBundle:
        """Atomically freeze and verify one immutable finding reproduction bundle."""
        if not isinstance(request, ReproductionBundleRequest):
            raise TypeError("reproduction bundle freeze requires a validated request")
        testcase_hash = sha256(request.minimal_testcase).hexdigest()
        identity = {
            "project_id": request.project_id,
            "finding_id": request.finding_id,
            "commit_sha": request.commit_sha,
            "image_id": request.image_id,
            "command": list(request.command),
            "environment": [list(value) for value in request.environment],
            "sanitizer": request.sanitizer,
            "configuration": request.configuration,
            "testcase_sha256": testcase_hash,
            "target_asset_hash": request.target_asset_hash,
            "configuration_asset_hash": request.configuration_asset_hash,
            "coverage_asset_hash": request.coverage_asset_hash,
        }
        encoded_identity = json.dumps(
            identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        bundle_id = sha256(encoded_identity).hexdigest()
        manifest = {"bundle_id": bundle_id, **identity}
        encoded_manifest = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        parent = self._bundle_parent(request.project_id, request.finding_id)
        destination = parent / bundle_id
        if destination.exists():
            return self._verified_bundle(request, destination, manifest)
        staging = parent / f".{bundle_id}.{uuid4().hex}.staging"
        staging.mkdir(mode=0o700)
        try:
            testcase = staging / "testcase.input"
            manifest_file = staging / "manifest.json"
            testcase.write_bytes(request.minimal_testcase)
            manifest_file.write_bytes(encoded_manifest)
            testcase.chmod(0o400)
            manifest_file.chmod(0o400)
            self._fsync(testcase)
            self._fsync(manifest_file)
            staging.chmod(0o500)
            self._fsync_directory(staging)
            try:
                staging.rename(destination)
            except FileExistsError:
                staging.chmod(0o700)
                self._remove_staging(staging)
            self._fsync_directory(parent)
        except BaseException:
            if staging.exists():
                staging.chmod(0o700)
                self._remove_staging(staging)
            raise
        return self._verified_bundle(request, destination, manifest)

    def _bundle_parent(self, project_id: int, finding_id: int) -> Path:
        current = self._workspace
        for name in ("projects", str(project_id), "findings", str(finding_id), "bundle"):
            candidate = current / name
            if candidate.is_symlink():
                raise ValueError("reproduction bundle path contains a symlink")
            candidate.mkdir(exist_ok=True, mode=0o700)
            if not candidate.is_dir():
                raise ValueError("reproduction bundle path is not a directory")
            current = candidate
        try:
            current.resolve(strict=True).relative_to(self._workspace)
        except ValueError as error:
            raise ValueError("reproduction bundle path escaped its workspace") from error
        return current

    def _verified_bundle(self, request, root: Path, expected: dict) -> ReproductionBundle:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("reproduction bundle identity is unsafe")
        manifest_path = root / "manifest.json"
        testcase_path = root / "testcase.input"
        if manifest_path.is_symlink() or testcase_path.is_symlink():
            raise ValueError("reproduction bundle file is unsafe")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            testcase = testcase_path.read_bytes()
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("reproduction bundle is incomplete") from error
        if manifest != expected or sha256(testcase).hexdigest() != expected["testcase_sha256"]:
            raise ValueError("reproduction bundle verification failed")
        if testcase != request.minimal_testcase:
            raise ValueError("reproduction bundle testcase identity changed")
        return ReproductionBundle(
            expected["bundle_id"],
            request.project_id,
            request.finding_id,
            root,
            MappingProxyType(dict(manifest)),
            True,
        )

    @staticmethod
    def _remove_staging(root: Path) -> None:
        for name in ("manifest.json", "testcase.input"):
            path = root / name
            if path.exists() and not path.is_symlink():
                path.chmod(0o600)
                path.unlink()
        root.rmdir()

    @staticmethod
    def _fsync(path: Path) -> None:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
