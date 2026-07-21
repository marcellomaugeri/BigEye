"""Immutable, contained finding reproduction bundles for safe asset lifecycle changes."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import inspect
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

    def __init__(self, workspace: Path, resolver=None):
        root = Path(os.path.abspath(os.fspath(workspace)))
        if root.is_symlink():
            raise ValueError("reproduction bundle workspace must not be a symlink")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._workspace = root.resolve(strict=True)
        self._resolver = resolver

    async def freeze(self, request: ReproductionBundleRequest) -> ReproductionBundle:
        """Atomically freeze and verify one immutable finding reproduction bundle."""
        if not isinstance(request, ReproductionBundleRequest):
            raise TypeError("reproduction bundle freeze requires a validated request")
        if self._resolver is None:
            raise ValueError("reproduction bundle authoritative resolver is unavailable")
        verified = self._resolver.verify(request)
        if inspect.isawaitable(verified):
            verified = await verified
        if verified is not True:
            raise ValueError("reproduction bundle dependencies do not match authoritative stores")
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

    async def freeze_for_finding(self, project_id: int, finding_id: int) -> ReproductionBundle:
        """Resolve and freeze the currently selected validated finding generation."""
        if type(project_id) is not int or project_id <= 0 or type(finding_id) is not int or finding_id <= 0:
            raise ValueError("reproduction bundle identity is invalid")
        resolve = getattr(self._resolver, "resolve", None)
        if resolve is None:
            raise ValueError("reproduction bundle authoritative resolver cannot construct a bundle")
        request = resolve(project_id, finding_id)
        if inspect.isawaitable(request):
            request = await request
        if (
            not isinstance(request, ReproductionBundleRequest)
            or request.project_id != project_id
            or request.finding_id != finding_id
        ):
            raise ValueError("resolved reproduction bundle identity is invalid")
        return await self.freeze(request)

    async def verify(self, project_id: int, bundle_id: str) -> bool:
        if type(project_id) is not int or project_id <= 0 or _DIGEST.fullmatch(bundle_id) is None:
            return False
        root = self._workspace / "projects" / str(project_id) / "findings"
        if root.is_symlink() or not root.is_dir():
            return False
        for finding in root.iterdir():
            candidate = finding / "bundle" / bundle_id
            if not candidate.is_dir() or candidate.is_symlink():
                continue
            try:
                manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
                testcase = (candidate / "testcase.input").read_bytes()
                request = ReproductionBundleRequest(
                    project_id=manifest["project_id"], finding_id=manifest["finding_id"],
                    commit_sha=manifest["commit_sha"], image_id=manifest["image_id"],
                    command=tuple(manifest["command"]),
                    environment=tuple(tuple(item) for item in manifest["environment"]),
                    sanitizer=manifest["sanitizer"], configuration=manifest["configuration"],
                    minimal_testcase=testcase,
                    target_asset_hash=manifest["target_asset_hash"],
                    configuration_asset_hash=manifest["configuration_asset_hash"],
                    coverage_asset_hash=manifest["coverage_asset_hash"],
                )
                bundle = self._verified_bundle(request, candidate, manifest)
                verified = self._resolver.verify(request)
                if inspect.isawaitable(verified):
                    verified = await verified
                return bundle.verified and verified is True
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                return False
        return False

    def load_sealed(self, project_id: int, finding_id: int) -> ReproductionBundle:
        """Self-verify one finding-scoped bundle after mutable lifecycle data is gone."""
        if type(project_id) is not int or project_id <= 0 or type(finding_id) is not int or finding_id <= 0:
            raise ValueError("sealed reproduction bundle identity is invalid")
        parent = self._workspace / "projects" / str(project_id) / "findings" / str(finding_id) / "bundle"
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("sealed reproduction bundle is unavailable")
        candidates = [
            item for item in parent.iterdir()
            if item.is_dir() and not item.is_symlink() and _DIGEST.fullmatch(item.name)
        ]
        if len(candidates) != 1:
            raise ValueError("sealed reproduction bundle selection is ambiguous or incomplete")
        root = candidates[0]
        manifest_path, testcase_path = root / "manifest.json", root / "testcase.input"
        if manifest_path.is_symlink() or testcase_path.is_symlink():
            raise ValueError("sealed reproduction bundle path is unsafe")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("sealed reproduction manifest is not an object")
            testcase = testcase_path.read_bytes()
            identity = {key: value for key, value in manifest.items() if key != "bundle_id"}
            encoded = json.dumps(
                identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            request = ReproductionBundleRequest(
                project_id=identity["project_id"], finding_id=identity["finding_id"],
                commit_sha=identity["commit_sha"], image_id=identity["image_id"],
                command=tuple(identity["command"]),
                environment=tuple(tuple(item) for item in identity["environment"]),
                sanitizer=identity["sanitizer"], configuration=identity["configuration"],
                minimal_testcase=testcase,
                target_asset_hash=identity["target_asset_hash"],
                configuration_asset_hash=identity["configuration_asset_hash"],
                coverage_asset_hash=identity["coverage_asset_hash"],
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("sealed reproduction bundle verification failed") from error
        if (
            request.project_id != project_id or request.finding_id != finding_id
            or manifest.get("bundle_id") != root.name
            or sha256(encoded).hexdigest() != root.name
            or sha256(testcase).hexdigest() != identity.get("testcase_sha256")
        ):
            raise ValueError("sealed reproduction bundle verification failed")
        return self._verified_bundle(request, root, manifest)

    async def pinned_image_ids(self, project_id: int) -> tuple[str, ...]:
        if type(project_id) is not int or project_id <= 0:
            raise ValueError("reproduction bundle project ID is invalid")
        root = self._workspace / "projects" / str(project_id) / "findings"
        if not root.is_dir() or root.is_symlink():
            return ()
        values = set()
        for manifest_path in root.glob("*/bundle/*/manifest.json"):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                bundle_id = manifest.get("bundle_id")
                if await self.verify(project_id, bundle_id):
                    values.add(manifest["image_id"])
            except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
                continue
        return tuple(sorted(values))

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


class ProductionReproductionBundleResolver:
    """Resolve bundle dependencies against projects, findings, assets, contracts, and Docker."""

    def __init__(self, *, projects, findings, finding_artifacts, assets, campaigns, invocations, docker):
        self._projects = projects
        self._findings = findings
        self._finding_artifacts = finding_artifacts
        self._assets = assets
        self._campaigns = campaigns
        self._invocations = invocations
        self._docker = docker

    async def resolve(self, project_id: int, finding_id: int) -> ReproductionBundleRequest:
        """Construct the bundle only from the selected generation and exact clean contract."""
        if type(project_id) is not int or project_id <= 0 or type(finding_id) is not int or finding_id <= 0:
            raise ValueError("reproduction bundle identity is invalid")
        project = await self._projects.get(project_id)
        finding = await self._findings.get(finding_id)
        if (
            project is None or finding is None or finding.project_id != project_id
            or not finding.reproducible or finding.error is not None
        ):
            raise ValueError("reproducible finding is unavailable")
        evidence = self._finding_artifacts.detail(finding)
        replay = evidence.get("replay") if isinstance(evidence, dict) else None
        clean = replay.get("clean_variant") if isinstance(replay, dict) else None
        if (
            not isinstance(clean, dict) or clean.get("crashed") is not True
            or clean.get("error") is not None
            or _IMAGE.fullmatch(str(clean.get("image_id"))) is None
            or not isinstance(clean.get("sanitizer"), str) or not clean["sanitizer"]
        ):
            raise ValueError("selected finding lacks a validated clean replay")
        reproducer = self._finding_artifacts.read_reproducer(finding)
        assets = await self._assets.list_for_project(project_id)
        by_id = {
            asset.id: asset for asset in assets
            if asset.project_id == project_id and asset.validated_at is not None and asset.error is None
        }
        campaigns = await self._campaigns.for_finding(project_id, finding.fingerprint)
        candidates: list[ReproductionBundleRequest] = []
        for campaign in campaigns:
            if campaign.project_id != project_id:
                continue
            try:
                coverage = self._invocations.load_coverage(project_id, campaign.id)
            except (FileNotFoundError, ValueError):
                continue
            configuration_id = coverage.clean_build_configuration_asset_id
            if (
                coverage.project_id != project_id or coverage.commit_sha != project.commit_sha
                or coverage.clean_image_id != clean["image_id"]
                or coverage.target_asset_id != campaign.target_asset_id
                or coverage.configuration_asset_id != campaign.configuration_asset_id
                or configuration_id is None
            ):
                continue
            try:
                target = by_id[coverage.target_asset_id]
                configuration = by_id[configuration_id]
                coverage_asset = by_id[coverage.coverage_asset_id]
            except KeyError:
                continue
            lineage = json.dumps({
                "campaign_id": campaign.id,
                "clean_content_hash": coverage.clean_content_hash,
                "target_asset_id": coverage.target_asset_id,
                "configuration_asset_id": coverage.configuration_asset_id,
                "clean_build_configuration_asset_id": configuration_id,
                "coverage_asset_id": coverage.coverage_asset_id,
            }, sort_keys=True, separators=(",", ":"))
            candidates.append(ReproductionBundleRequest(
                project_id=project_id,
                finding_id=finding_id,
                commit_sha=project.commit_sha,
                image_id=coverage.clean_image_id,
                command=tuple(coverage.replay_command),
                environment=tuple(coverage.replay_environment),
                sanitizer=clean["sanitizer"],
                configuration=lineage,
                minimal_testcase=reproducer,
                target_asset_hash=target.content_hash,
                configuration_asset_hash=configuration.content_hash,
                coverage_asset_hash=coverage_asset.content_hash,
            ))
        if not candidates or any(candidate != candidates[0] for candidate in candidates[1:]):
            raise ValueError("finding reproduction contract is unavailable or ambiguous")
        return candidates[0]

    async def verify(self, request: ReproductionBundleRequest) -> bool:
        try:
            authoritative = await self.resolve(request.project_id, request.finding_id)
        except (FileNotFoundError, OSError, TypeError, ValueError):
            return False
        if authoritative != request:
            return False
        client = self._docker.connect()
        try:
            image = client.images.get(request.image_id)
            return getattr(image, "id", None) == request.image_id
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()
