"""Incrementally publish, build, and probe one proposed fuzz target."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from hashlib import sha256
import inspect
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Hashable, Mapping
import unicodedata

from backend.agents.outputs.campaign_review import TargetProposalRecord
from backend.agents.outputs.target_proposal import TargetProposal
from backend.fuzzing.campaigns.probe import (
    ProbeAcceptance,
    ProbeEvidence,
    ProbeInvocation,
    ProbePolicy,
)
from backend.fuzzing.docker.image_builder import (
    BuildCancellationSignal,
    ImageBuildCancelled,
    ImageCompilationFailed,
)
from backend.fuzzing.layers.manifest import LayerManifest
from backend.fuzzing.sanitizer_environment import BASELINE_SANITIZER_ENVIRONMENT


_REQUIRED_ASSET_ROLES = frozenset({
    "target", "configuration", "coverage_adapter", "coverage_configuration",
})
_ALLOWED_ASSET_ROLES = _REQUIRED_ASSET_ROLES | {"fuzz_patch"}
_LUNA = "gpt-5.6-luna"
_TERRA = "gpt-5.6-terra"


class DeterministicPreparationError(ValueError):
    """A proposal, generated asset, layer, or probe failed reproducible validation."""


class ProbeRejected(DeterministicPreparationError):
    """A complete supervised probe was rejected while retaining its evidence."""

    def __init__(self, message: str, evidence: ProbeEvidence):
        super().__init__(message)
        self.evidence = evidence
        self.repairable = not (evidence.immediate_crash or bool(evidence.sanitizer_output))


class TargetPreparationFailed(DeterministicPreparationError):
    """Both bounded model attempts failed without replacing a validated target."""

    def __init__(
        self,
        message: str,
        *,
        agent_attempts: tuple[str, ...],
        retained_target: "PreparedTarget | None",
        probe_evidence: ProbeEvidence | None = None,
    ):
        super().__init__(message)
        self.agent_attempts = agent_attempts
        self.retained_target = retained_target
        self.probe_evidence = probe_evidence


@dataclass(frozen=True)
class TargetRepair:
    """One typed repair response with the model that actually produced it."""

    proposal: TargetProposal
    model: str

    def __post_init__(self) -> None:
        if not isinstance(self.proposal, TargetProposal):
            raise TypeError("target repair requires a validated proposal")
        if not isinstance(self.model, str) or not self.model.strip() or len(self.model) > 200:
            raise ValueError("target repair model identity is invalid")


@dataclass(frozen=True)
class AssetVersionRequest:
    """One explicit logical asset version selected by deterministic planning."""

    role: str
    kind: str
    name: str
    files: Mapping[str, object]
    proposal_paths: tuple[str, ...]
    parent_id: int | None = None

    def __post_init__(self) -> None:
        if self.role not in _ALLOWED_ASSET_ROLES:
            raise ValueError("asset version role is invalid")
        for field in ("kind", "name"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip() or len(value) > 500:
                raise ValueError(f"asset version {field} is invalid")
        if not isinstance(self.files, Mapping) or not self.files:
            raise ValueError("asset version files must be a non-empty mapping")
        if (
            not isinstance(self.proposal_paths, tuple)
            or not self.proposal_paths
            or len(self.proposal_paths) != len(set(self.proposal_paths))
        ):
            raise ValueError("asset version proposed paths are invalid")
        for value in self.proposal_paths:
            self._validate_proposal_path(value)
        if self.parent_id is not None and (
            isinstance(self.parent_id, bool) or not isinstance(self.parent_id, int) or self.parent_id <= 0
        ):
            raise ValueError("asset version parent ID is invalid")
        object.__setattr__(self, "files", MappingProxyType(dict(self.files)))

    @staticmethod
    def _validate_proposal_path(value: str) -> None:
        if not isinstance(value, str) or not value or len(value) > 500 or "\\" in value or "\x00" in value:
            raise ValueError("asset version proposed path is invalid")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} or part.casefold() == ".git" for part in path.parts):
            raise ValueError("asset version proposed path is invalid")


@dataclass(frozen=True)
class PreparationPlan:
    """The explicit assets and contained argv probes for one proposal attempt."""

    asset_versions: tuple[AssetVersionRequest, ...]
    probe_invocations: tuple[ProbeInvocation, ...]
    existing_assets: Mapping[str, object] = field(default_factory=dict)
    normal_build_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.asset_versions, tuple) or any(
            not isinstance(value, AssetVersionRequest) for value in self.asset_versions
        ):
            raise ValueError("preparation asset versions are invalid")
        if not isinstance(self.existing_assets, Mapping):
            raise ValueError("preparation existing assets are invalid")
        if (
            not isinstance(self.normal_build_paths, tuple)
            or len(self.normal_build_paths) != len(set(self.normal_build_paths))
        ):
            raise ValueError("normal-build proposal paths are invalid")
        for value in self.normal_build_paths:
            AssetVersionRequest._validate_proposal_path(value)
        requested_roles = tuple(value.role for value in self.asset_versions)
        existing_roles = tuple(self.existing_assets)
        roles = (*requested_roles, *existing_roles)
        if (
            not _REQUIRED_ASSET_ROLES.issubset(roles)
            or not set(roles).issubset(_ALLOWED_ASSET_ROLES)
            or len(roles) != len(set(roles))
        ):
            raise ValueError("preparation requires one version for every dependent layer role")
        if not isinstance(self.probe_invocations, tuple) or any(
            not isinstance(value, ProbeInvocation) for value in self.probe_invocations
        ):
            raise ValueError("preparation probe invocations are invalid")
        probe_roles = tuple(value.role for value in self.probe_invocations)
        if probe_roles.count("empty") != 1 or probe_roles.count("minimum") != 1 or probe_roles.count("seed") < 1:
            raise ValueError("preparation requires empty, minimum, and real seed probes")
        object.__setattr__(self, "existing_assets", MappingProxyType(dict(self.existing_assets)))


@dataclass(frozen=True)
class PreparedTarget:
    """One empirically accepted target plus its clean-coverage counterpart."""

    project_id: int
    commit_sha: str
    target_name: str
    configuration: str
    target_manifest: LayerManifest
    coverage_manifest: LayerManifest
    target_image_id: str
    coverage_image_id: str
    assets: tuple[object, ...]
    probe_invocations: tuple[ProbeInvocation, ...]
    probe_evidence: ProbeEvidence
    probe: ProbeAcceptance
    agent_attempts: tuple[str, ...]
    replay_environment: tuple[tuple[str, str], ...]

    @property
    def image(self) -> str:
        return self.target_image_id


@dataclass(frozen=True)
class _BuiltTarget:
    project_id: int
    commit_sha: str
    target_name: str
    configuration: str
    target_manifest: LayerManifest
    coverage_manifest: LayerManifest
    target_image_id: str
    coverage_image_id: str
    assets: tuple[object, ...]
    probe_invocations: tuple[ProbeInvocation, ...]
    replay_environment: tuple[tuple[str, str], ...]

    @property
    def image(self) -> str:
        return self.target_image_id


@dataclass
class _LockRecord:
    lock: asyncio.Lock
    users: int = 0


class _LockPool:
    """Keep canonical service locks only while an operation or waiter uses them."""

    def __init__(self) -> None:
        self._guard = asyncio.Lock()
        self._records: dict[Hashable, _LockRecord] = {}

    @asynccontextmanager
    async def acquire(self, key: Hashable):
        async with self.acquire_many((key,)):
            yield

    @asynccontextmanager
    async def acquire_many(self, keys: tuple[Hashable, ...]):
        canonical_keys = tuple(sorted(set(keys), key=repr))
        if not canonical_keys:
            yield
            return
        async with self._guard:
            records = []
            for key in canonical_keys:
                record = self._records.setdefault(key, _LockRecord(asyncio.Lock()))
                record.users += 1
                records.append((key, record))
        acquired: list[_LockRecord] = []
        try:
            for _key, record in records:
                await record.lock.acquire()
                acquired.append(record)
            yield
        finally:
            for record in reversed(acquired):
                record.lock.release()
            async with self._guard:
                for key, record in records:
                    record.users -= 1
                    if record.users == 0:
                        self._records.pop(key, None)


class TargetPreparationService:
    """Validate normal build first, then change only proposal-dependent layers."""

    def __init__(
        self,
        *,
        normal_build,
        planner,
        asset_store,
        target_layers,
        coverage_layers,
        image_inspector,
        probe,
        repairer=None,
        activity=None,
        sink=None,
    ):
        self._normal_build = normal_build
        self._planner = planner
        self._asset_store = asset_store
        self._target_layers = target_layers
        self._coverage_layers = coverage_layers
        self._image_inspector = image_inspector
        self._probe = probe
        self._repairer = repairer
        self._activity = activity
        self._sink = sink or (lambda _text: None)
        self._locks = _LockPool()
        self._validated: dict[str, PreparedTarget] = {}

    async def prepare(self, project, proposal: TargetProposal | TargetProposalRecord) -> PreparedTarget:
        self._validate_project(project)
        candidate, initial_model = self._proposal(proposal)
        project_manifest = self._normal_build.validate(project, candidate)
        if inspect.isawaitable(project_manifest):
            project_manifest = await project_manifest
        if not isinstance(project_manifest, LayerManifest) or project_manifest.kind != "project":
            raise DeterministicPreparationError("normal build did not produce a validated project layer")

        identity_key = self._target_identity_lock_key(project.id, candidate)
        async with self._locks.acquire(identity_key):
            return await self._prepare_with_repair(
                project, project_manifest, candidate, initial_model,
            )

    async def _prepare_with_repair(
        self,
        project,
        project_manifest: LayerManifest,
        candidate: TargetProposal,
        initial_model: str,
    ) -> PreparedTarget:
        attempts: list[str] = []
        while True:
            model = initial_model if not attempts else _TERRA
            attempts.append(model)
            try:
                prepared = await self._prepare_once(
                    project, project_manifest, candidate, tuple(attempts),
                )
            except DeterministicPreparationError as error:
                retained = self._validated.get(self._target_key(project, candidate))
                await self._record_activity(
                    project.id,
                    "target preparation rejected",
                    candidate.target_name,
                    str(error),
                    tuple(attempts),
                )
                repairable = not isinstance(error, ProbeRejected) or error.repairable
                if model == _LUNA and self._repairer is not None and repairable:
                    repaired = self._repairer.repair(project, candidate, error, _TERRA)
                    if inspect.isawaitable(repaired):
                        repaired = await repaired
                    if not isinstance(repaired, TargetRepair):
                        raise TargetPreparationFailed(
                            "bounded repair must return a typed TargetRepair",
                            agent_attempts=tuple(attempts),
                            retained_target=retained,
                            probe_evidence=getattr(error, "evidence", None),
                        )
                    repaired_candidate = repaired.proposal
                    repaired_model = repaired.model
                    if repaired_model != _TERRA:
                        raise TargetPreparationFailed(
                            "bounded repair must be produced by exactly Terra (gpt-5.6-terra)",
                            agent_attempts=(*attempts, repaired_model),
                            retained_target=retained,
                            probe_evidence=getattr(error, "evidence", None),
                        )
                    if self._proposal_identity(repaired_candidate) != self._proposal_identity(candidate):
                        raise TargetPreparationFailed(
                            "bounded repair changed the target identity",
                            agent_attempts=(*attempts, repaired_model),
                            retained_target=retained,
                            probe_evidence=getattr(error, "evidence", None),
                        )
                    candidate = repaired_candidate
                    continue
                raise TargetPreparationFailed(
                    str(error), agent_attempts=tuple(attempts), retained_target=retained,
                    probe_evidence=getattr(error, "evidence", None),
                ) from error
            self._validated[self._target_key(project, candidate)] = prepared
            await self._record_activity(
                project.id,
                "target preparation accepted",
                candidate.target_name,
                prepared.probe.reason,
                tuple(attempts),
            )
            return prepared

    async def _prepare_once(
        self,
        project,
        project_manifest: LayerManifest,
        proposal: TargetProposal,
        attempts: tuple[str, ...],
    ) -> PreparedTarget:
        try:
            plan = self._planner.plan(project, proposal)
            if inspect.isawaitable(plan):
                plan = await plan
            if not isinstance(plan, PreparationPlan):
                raise ValueError("proposal planner returned an invalid preparation plan")
            proposed_paths = tuple(
                path for request in plan.asset_versions for path in request.proposal_paths
            )
            intended_paths = tuple(intent.relative_path for intent in proposal.generated_asset_intents)
            if (
                len(proposed_paths) != len(set(proposed_paths))
                or set(proposed_paths).intersection(plan.normal_build_paths)
                or set((*proposed_paths, *plan.normal_build_paths)) != set(intended_paths)
            ):
                raise ValueError("asset versions do not match the proposal's proposed paths")
            assets = dict(plan.existing_assets)
            for asset in assets.values():
                self._validate_published_asset(project.id, asset)
            for request in plan.asset_versions:
                asset = await self._asset_store.create(
                    project.id,
                    request.kind,
                    request.name,
                    dict(request.files),
                    request.parent_id,
                )
                self._validate_published_asset(project.id, asset)
                assets[request.role] = asset
            asset_lock_keys = tuple(
                ("asset", project.id, asset.id) for asset in assets.values()
            )
            async with self._locks.acquire_many(asset_lock_keys):
                target_manifest = await self._run_layer(
                    self._target_layers.prepare,
                    project,
                    project_manifest,
                    assets["target"],
                    assets["configuration"],
                    self._sink,
                    assets.get("fuzz_patch"),
                )
                coverage_manifest = await self._run_layer(
                    self._coverage_layers.prepare,
                    project,
                    project_manifest,
                    assets["coverage_adapter"],
                    assets["coverage_configuration"],
                    self._sink,
                    target_asset_id=assets["target"].id,
                    configuration_asset_id=assets["configuration"].id,
                    coverage_asset_id=assets["coverage_adapter"].id,
                )
                self._validate_manifest(target_manifest, "target")
                self._validate_manifest(coverage_manifest, "coverage")
                target_image_id = self._inspect_image(target_manifest.tag)
                coverage_image_id = self._inspect_image(coverage_manifest.tag)
                built = _BuiltTarget(
                    project.id,
                    project.commit_sha,
                    proposal.target_name,
                    proposal.configuration,
                    target_manifest,
                    coverage_manifest,
                    target_image_id,
                    coverage_image_id,
                    tuple(assets[role] for role in sorted(assets)),
                    plan.probe_invocations,
                    BASELINE_SANITIZER_ENVIRONMENT,
                )
                evidence = await self._probe.run(built)
                acceptance = ProbePolicy.accept(evidence)
                if not acceptance.accepted:
                    raise ProbeRejected(acceptance.reason, evidence)
                return PreparedTarget(
                    project.id,
                    project.commit_sha,
                    proposal.target_name,
                    proposal.configuration,
                    target_manifest,
                    coverage_manifest,
                    target_image_id,
                    coverage_image_id,
                    built.assets,
                    plan.probe_invocations,
                    evidence,
                    acceptance,
                    attempts,
                    built.replay_environment,
                )
        except DeterministicPreparationError:
            raise
        except ValueError as error:
            raise DeterministicPreparationError(str(error)) from error

    @staticmethod
    async def _run_layer(method, *arguments, **keywords):
        cancellation_signal = BuildCancellationSignal()
        if inspect.iscoroutinefunction(method):
            worker = asyncio.create_task(method(
                *arguments, **keywords, cancellation_signal=cancellation_signal,
            ))
        else:
            worker = asyncio.create_task(asyncio.to_thread(
                method, *arguments, **keywords, cancellation_signal=cancellation_signal,
            ))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError as cancelled:
            cancellation_signal.set()
            cleanup_error = None
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    continue
                except ImageBuildCancelled:
                    break
                except BaseException as error:
                    cleanup_error = error
                    break
            if worker.done():
                try:
                    worker.result()
                except ImageBuildCancelled:
                    pass
                except BaseException as error:
                    cleanup_error = cleanup_error or error
            if cleanup_error is not None:
                cancelled.add_note(f"layer worker cleanup failed: {cleanup_error}")
            raise
        except ImageCompilationFailed as error:
            raise DeterministicPreparationError(str(error)) from error

    async def _record_activity(
        self,
        project_id: int,
        decision: str,
        target_name: str,
        motivation: str,
        attempts: tuple[str, ...],
    ) -> None:
        if self._activity is None:
            return
        payload = {
            "decision": decision,
            "target": target_name,
            "motivation": motivation,
            "agent_attempts": list(attempts),
        }
        result = self._activity.append(project_id, "activity", payload)
        if inspect.isawaitable(result):
            await result

    @staticmethod
    def _validate_project(project) -> None:
        if isinstance(getattr(project, "id", None), bool) or not isinstance(getattr(project, "id", None), int) or project.id <= 0:
            raise ValueError("project ID must be positive")
        commit = getattr(project, "commit_sha", None)
        if not isinstance(commit, str) or len(commit) not in {40, 64} or any(
            value not in "0123456789abcdef" for value in commit
        ):
            raise ValueError("project requires an exact resolved commit")

    @staticmethod
    def _proposal(value) -> tuple[TargetProposal, str]:
        if isinstance(value, TargetProposalRecord):
            if value.model not in {_LUNA, _TERRA}:
                raise ValueError("target proposal model is unsupported")
            return value.proposal, value.model
        if isinstance(value, TargetProposal):
            return value, _LUNA
        raise TypeError("target preparation requires a validated target proposal")

    @staticmethod
    def _validate_published_asset(project_id: int, asset) -> None:
        if (
            type(getattr(asset, "id", None)) is not int
            or asset.id <= 0
            or
            getattr(asset, "project_id", None) != project_id
            or getattr(asset, "validated_at", None) is None
            or getattr(asset, "error", None) is not None
        ):
            raise DeterministicPreparationError("asset store did not return a validated project asset")

    @staticmethod
    def _validate_manifest(manifest, kind: str) -> None:
        if not isinstance(manifest, LayerManifest) or manifest.kind != kind or not manifest.tag:
            raise DeterministicPreparationError(f"{kind} build did not return a valid layer manifest")

    def _inspect_image(self, tag: str) -> str:
        value = self._image_inspector.inspect(tag)
        image_id = getattr(value, "image_id", None)
        if (
            getattr(value, "os", None) != "linux"
            or getattr(value, "architecture", None) != "amd64"
            or not isinstance(image_id, str)
            or not image_id.startswith("sha256:")
            or len(image_id) != 71
            or any(character not in "0123456789abcdef" for character in image_id[7:])
        ):
            raise DeterministicPreparationError("prepared image is not an exact linux/amd64 image ID")
        return image_id

    @classmethod
    def _proposal_identity(cls, proposal: TargetProposal) -> tuple[str, str, str]:
        return tuple(
            cls._normalize_identity_field(value)
            for value in (proposal.instance_type, proposal.target_name, proposal.configuration)
        )

    @classmethod
    def _target_key(cls, project, proposal: TargetProposal) -> str:
        return cls._target_identity_digest(project.id, proposal)

    @classmethod
    def _target_identity_lock_key(cls, project_id: int, proposal: TargetProposal) -> tuple[str, str]:
        return "target", cls._target_identity_digest(project_id, proposal)

    @classmethod
    def _target_identity_digest(cls, project_id: int, proposal: TargetProposal) -> str:
        fields = (
            str(project_id),
            proposal.instance_type,
            proposal.target_name,
            proposal.configuration,
        )
        digest = sha256()
        for value in fields:
            normalized = cls._normalize_identity_field(value)
            encoded = normalized.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.hexdigest()

    @staticmethod
    def _normalize_identity_field(value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip()
        if not normalized:
            raise ValueError("target identity fields must not be blank")
        return normalized
