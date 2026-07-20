"""Compose the existing deterministic preparation components for local production use."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import shutil
from tempfile import mkdtemp

from backend.agents.tools.code_navigation import (
    _open_contained_file,
    _opened_repository_root,
    _relative_parts,
)
from backend.agents.tools.generated_assets import (
    GeneratedAssetError,
    read_asset_file,
    write_asset_file,
)
from backend.fuzzing.assets.store import AssetStore
from backend.fuzzing.campaigns.probe import (
    AttestedCoverage,
    CleanCoverageProvenance,
    ProbeInvocation,
    ProbeRunner,
    ProbeService,
)
from backend.fuzzing.campaigns.target_preparation import (
    AssetVersionRequest,
    PreparationPlan,
    TargetPreparationService,
)
from backend.fuzzing.coverage.llvm_coverage import DockerCoverageExecutor, LlvmCoverage
from backend.fuzzing.docker.container_runner import ContainerRunner
from backend.fuzzing.docker.client import DockerClient
from backend.fuzzing.docker.image_builder import ImageBuilder
from backend.fuzzing.docker.image_inspector import ImageInspector
from backend.fuzzing.layers.coverage_layer import CoverageLayerService
from backend.fuzzing.layers.project_layer import ProjectLayerService
from backend.fuzzing.layers.repository_layer import RepositoryLayerService
from backend.fuzzing.layers.target_layer import TargetLayerService
from backend.fuzzing.toolchain.builder import ToolchainBuilder
from backend.agents.target_repair import TargetRepairAgent


_MAX_SEED_BYTES = 16 * 1024 * 1024
_SHELL_OPERATOR_TOKENS = frozenset({";", "|", "||", "&&", ">", ">>", "<", "<<", "2>", "2>>"})


class DeferredRepositoryLayerBootstrap:
    """Publish the exact fixed-revision repository layer before the first manager review."""

    def __init__(self, workspace: Path, dockerfile: Path, logs, docker_client=None):
        self._workspace = Path(workspace)
        self._dockerfile = Path(dockerfile)
        self._logs = logs
        self._docker_client = docker_client or DockerClient()

    async def prepare(self, project, task):
        client = await asyncio.to_thread(self._docker_client.connect)
        output: list[str] = []

        def sink(value):
            if sum(len(item) for item in output) < 1_000_000:
                output.append(str(value))

        try:
            inspector = ImageInspector(client)
            builder = ImageBuilder(client)
            tag = ToolchainBuilder(self._dockerfile, builder, inspector).tag()
            repository_root = self._workspace / "projects" / str(project.id) / "repository"
            manifest = await asyncio.to_thread(
                RepositoryLayerService(self._workspace, builder, inspector).prepare,
                project.id, repository_root, project.commit_sha, tag, sink,
            )
            if output:
                await self._logs.append(task, "".join(output))
            return manifest
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                await asyncio.to_thread(close)


class NormalBuildPreparation:
    """Build the immutable repository and reusable dependency layer before target changes.

    This layer installs project dependencies only. Target/configuration compilation remains in
    the dependent target and clean-coverage layers, so harness-only edits reuse this layer.
    """

    def __init__(
        self, *, discovery, asset_store, repository_layers, project_layers,
        toolchain_tag: str, sink,
    ):
        self._discovery = discovery
        self._assets = asset_store
        self._repository_layers = repository_layers
        self._project_layers = project_layers
        self._toolchain_tag = toolchain_tag
        self._sink = sink

    async def validate(self, project, proposal):
        context = self._discovery.context(project.id)
        dependency_intent = _dependency_intent(proposal)
        if dependency_intent is None:
            source = _application_file(
                context,
                "application/project-dependencies.sh",
                "#!/bin/sh\nset -eu\n# BigEye intentionally has no project dependency command for this target.\n",
            )
        else:
            if not dependency_intent.relative_path.casefold().endswith(".sh"):
                raise ValueError("project dependency preparation must be a generated shell script")
            read_asset_file(context, dependency_intent.relative_path)
            source = context.generated_assets_root / dependency_intent.relative_path
        creator = getattr(self._assets, "create_reusable", self._assets.create)
        build_asset = await creator(
            project.id, "script", "project-dependencies.sh",
            {"project-dependencies.sh": source}, None,
        )
        repository = await asyncio.to_thread(
            self._repository_layers.prepare,
            project.id,
            context.repository_root,
            project.commit_sha,
            self._toolchain_tag,
            self._sink,
        )
        return await asyncio.to_thread(
            self._project_layers.prepare,
            project,
            repository,
            build_asset,
            self._sink,
        )


class ProposalPreparationPlanner:
    """Bind model-written drafts and application scripts to one explicit preparation plan."""

    def __init__(self, *, discovery, asset_store):
        self._discovery = discovery
        self._assets = asset_store

    async def plan(self, project, proposal) -> PreparationPlan:
        context = self._discovery.context(project.id)
        target_files: dict[str, Path] = {}
        coverage_files: dict[str, Path] = {}
        patch_files: dict[str, Path] = {}
        target_paths: list[str] = []
        coverage_paths: list[str] = []
        patch_paths: list[str] = []
        for intent in proposal.generated_asset_intents:
            if _is_dependency_intent(intent):
                continue
            record = read_asset_file(context, intent.relative_path)
            source = context.generated_assets_root / intent.relative_path
            if source.name == "Dockerfile":
                raise ValueError("BigEye owns generated layer Dockerfiles and their exact parent image")
            purpose = intent.purpose.casefold()
            suffix = source.suffix.casefold()
            if suffix in {".patch", ".diff"}:
                patch_files[source.name] = source
                patch_paths.append(intent.relative_path)
            elif "coverage" in purpose or "adapter" in purpose:
                coverage_files[intent.relative_path] = source
                coverage_paths.append(intent.relative_path)
            else:
                target_files[intent.relative_path] = source
                target_paths.append(intent.relative_path)
            del record
        if len(patch_files) > 1:
            raise ValueError("one target preparation may apply at most one fuzz-only patch")

        empty = _application_file(context, "application/probe-empty.txt", "")
        minimum = _application_file(context, "application/probe-minimum.txt", "0")
        target_files.update({"probe/empty.txt": empty, "probe/minimum.txt": minimum})
        target_script = _application_file(
            context,
            "application/target-build.sh",
            _build_script(proposal.build_command, coverage=False),
        )
        coverage_script = _application_file(
            context,
            "application/coverage-build.sh",
            _build_script(proposal.build_command, coverage=True),
        )
        coverage_manifest = _application_file(
            context,
            "application/coverage-build-manifest.txt",
            "Clean coverage uses the validated project source and the proposal coverage build command.\n",
        )

        configuration = await self._assets.create(
            project.id, "script", "target-build.sh",
            {"target-build.sh": target_script}, None,
        )
        coverage_configuration = await self._assets.create(
            project.id, "script", "coverage-build.sh",
            {"coverage-build.sh": coverage_script}, None,
        )
        requests: list[AssetVersionRequest] = []
        existing = {
            "configuration": configuration,
            "coverage_configuration": coverage_configuration,
        }
        if target_paths:
            requests.append(AssetVersionRequest(
                "target", "harness", "target", target_files, tuple(target_paths),
            ))
        else:
            existing["target"] = await self._assets.create(
                project.id, "harness", "target", target_files, None,
            )
        if coverage_paths:
            requests.append(AssetVersionRequest(
                "coverage_adapter", "adapter", "coverage-adapter",
                coverage_files, tuple(coverage_paths),
            ))
        else:
            existing["coverage_adapter"] = await self._assets.create(
                project.id, "manifest", "coverage-build-manifest.txt",
                {"coverage-build-manifest.txt": coverage_manifest}, None,
            )
        if patch_paths:
            patch_name = next(iter(patch_files))
            requests.append(AssetVersionRequest(
                "fuzz_patch", "fuzz_patch", patch_name,
                patch_files, tuple(patch_paths),
            ))
        invocations = _probe_invocations(context, proposal)
        dependency_paths = tuple(
            intent.relative_path for intent in proposal.generated_asset_intents
            if _is_dependency_intent(intent)
        )
        return PreparationPlan(tuple(requests), invocations, existing, dependency_paths)


class PreparedCleanCoverageCollector:
    """Attest each supervised input in the exact clean coverage layer."""

    def __init__(self, client, workspace: Path, discovery):
        self._client = client
        self._workspace = Path(workspace)
        self._discovery = discovery

    async def collect(self, prepared, invocation: ProbeInvocation, _process) -> AttestedCoverage:
        target_labels = prepared.target_manifest.labels
        coverage_labels = prepared.coverage_manifest.labels
        try:
            target_id = int(target_labels["bigeye.target-asset"])
            configuration_id = int(coverage_labels["bigeye.configuration-asset-id"])
            coverage_id = int(coverage_labels["bigeye.coverage-asset-id"])
            parent_id = coverage_labels["bigeye.parent-image"]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("clean probe layer provenance is incomplete") from error
        replay_command = list(invocation.command)
        if not replay_command:
            raise ValueError("clean probe command is empty")
        if not replay_command[-1].startswith(("/bigeye/target/", "/src/")):
            raise ValueError("clean probe requires an explicit file input path")
        replay_command[-1] = "{input}"
        context = self._discovery.context(prepared.project_id)
        root = self._workspace / "projects" / str(prepared.project_id) / "probe-inputs"
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = Path(mkdtemp(prefix="probe-", dir=root))
        source = directory / f"{invocation.testcase_sha256}.input"
        source.write_bytes(invocation.testcase_bytes)
        source.chmod(0o400)
        campaign = _CleanCampaign(
            id=target_id,
            project_id=prepared.project_id,
            target_asset_id=target_id,
            configuration_asset_id=configuration_id,
            strategy_asset_id=configuration_id,
            coverage_asset_id=coverage_id,
            commit_sha=prepared.commit_sha,
            clean_image=prepared.coverage_manifest.tag,
            clean_image_id=prepared.coverage_image_id,
            clean_content_hash=prepared.coverage_manifest.content_hash,
            clean_parent_image_id=parent_id,
            binary_path=replay_command[0],
            replay_command=tuple(replay_command),
            cpu_exposure_seconds=0.0,
            repository_root=context.repository_root,
        )
        try:
            snapshot = await asyncio.to_thread(
                LlvmCoverage(
                    self._client,
                    DockerCoverageExecutor(self._client),
                    self._workspace / "coverage-probes",
                    max_inputs=1,
                ).replay,
                campaign,
                (source,),
            )
        finally:
            shutil.rmtree(directory)
        lines = frozenset(
            f"{line.source_path}:{line.line_number}" for line in snapshot.lines
        )
        return AttestedCoverage(
            lines,
            frozenset(),
            frozenset(),
            True,
            CleanCoverageProvenance(
                prepared.project_id,
                prepared.commit_sha,
                prepared.coverage_image_id,
                invocation.testcase_sha256,
            ),
        )


@dataclass(frozen=True)
class _CleanCampaign:
    id: int
    project_id: int
    target_asset_id: int
    configuration_asset_id: int | None
    strategy_asset_id: int
    coverage_asset_id: int
    commit_sha: str
    clean_image: str
    clean_image_id: str
    clean_content_hash: str
    clean_parent_image_id: str
    binary_path: str
    replay_command: tuple[str, ...]
    cpu_exposure_seconds: float
    repository_root: Path
    source_root: str = "/src"


class ProductionTargetPreparationFactory:
    """Create one fully concrete TargetPreparationService for an exact Docker client."""

    def __init__(self, *, workspace: Path, discovery, assets, dockerfile: Path, events=None):
        self._workspace = Path(workspace)
        self._discovery = discovery
        self._assets = assets
        self._dockerfile = Path(dockerfile)
        self._events = events

    def __call__(self, client) -> TargetPreparationService:
        inspector = ImageInspector(client)
        builder = ImageBuilder(client)
        asset_store = AssetStore(self._workspace, self._assets)
        normal = NormalBuildPreparation(
            discovery=self._discovery,
            asset_store=asset_store,
            repository_layers=RepositoryLayerService(self._workspace, builder, inspector),
            project_layers=ProjectLayerService(self._workspace, builder, inspector),
            toolchain_tag=ToolchainBuilder(self._dockerfile, builder, inspector).tag(),
            sink=lambda _text: None,
        )
        planner = ProposalPreparationPlanner(
            discovery=self._discovery, asset_store=asset_store,
        )
        probe = ProbeService(
            ProbeRunner(ContainerRunner(client)),
            PreparedCleanCoverageCollector(client, self._workspace, self._discovery),
            timeout_seconds=10.0,
        )
        return TargetPreparationService(
            normal_build=normal,
            planner=planner,
            asset_store=asset_store,
            target_layers=TargetLayerService(self._workspace, builder, inspector),
            coverage_layers=CoverageLayerService(self._workspace, builder, inspector),
            image_inspector=inspector,
            probe=probe,
            repairer=TargetRepairAgent(self._discovery, self._events),
            activity=self._events,
        )


def _application_file(context, relative_path: str, content: str) -> Path:
    try:
        existing = read_asset_file(context, relative_path)
    except GeneratedAssetError:
        write_asset_file(context, relative_path, content, None)
    else:
        if existing["content"] != content:
            raise ValueError("application-owned generated preparation file changed")
    return context.generated_assets_root / relative_path


def _is_dependency_intent(intent) -> bool:
    purpose = getattr(intent, "purpose", "")
    return isinstance(purpose, str) and "dependenc" in purpose.casefold()


def _dependency_intent(proposal):
    values = tuple(
        intent for intent in getattr(proposal, "generated_asset_intents", ())
        if _is_dependency_intent(intent)
    )
    if len(values) > 1:
        raise ValueError("one target proposal may define at most one project dependency script")
    return values[0] if values else None


def _build_script(command: str, *, coverage: bool) -> str:
    if not isinstance(command, str) or not command.strip() or any(
        character in command for character in ("\x00", "\r", "\n")
    ):
        raise ValueError("target build command must be one non-empty line")
    flags = ""
    if coverage:
        flags = (
            'export CFLAGS="${CFLAGS:-} -fprofile-instr-generate -fcoverage-mapping"\n'
            'export CXXFLAGS="${CXXFLAGS:-} -fprofile-instr-generate -fcoverage-mapping"\n'
            'export RUSTFLAGS="${RUSTFLAGS:-} -C instrument-coverage"\n'
        )
    return "#!/bin/sh\nset -eu\n" + flags + command + "\n"


def _probe_invocations(context, proposal) -> tuple[ProbeInvocation, ...]:
    try:
        command = tuple(shlex.split(proposal.run_command, posix=True))
    except ValueError as error:
        raise ValueError("target run command is not valid shell-free argv") from error
    if not command or not command[0].startswith("/opt/bigeye/"):
        raise ValueError("target run command must start with an /opt/bigeye executable")
    if any(item in _SHELL_OPERATOR_TOKENS for item in command):
        raise ValueError("target run command cannot contain shell operators")
    command = tuple("{input}" if value == "@@" else value for value in command)
    if command.count("{input}") > 1:
        raise ValueError("target run command may contain one input placeholder")
    if "{input}" not in command and proposal.instance_type == "component-level":
        command = (*command, "{input}")

    values = [
        ("empty", "empty", b"", "/bigeye/target/probe/empty.txt"),
        ("minimum", "minimum", b"0", "/bigeye/target/probe/minimum.txt"),
    ]
    for seed in proposal.seeds:
        content = _repository_bytes(context.repository_root, seed.path)
        values.append((f"seed:{seed.path}", "seed", content, f"/src/{seed.path}"))
    if len(values) == 2:
        raise ValueError("target proposal requires at least one repository seed")
    return tuple(
        ProbeInvocation(
            name,
            role,
            tuple(actual if part == "{input}" else part for part in command),
            content,
        )
        for name, role, content, actual in values
    )


def _repository_bytes(repository_root: Path, relative_path: str) -> bytes:
    parts = _relative_parts(relative_path)
    with _opened_repository_root(repository_root) as (_, root):
        descriptor = _open_contained_file(root, parts)
        try:
            details = os.fstat(descriptor)
            if details.st_size > _MAX_SEED_BYTES:
                raise ValueError("repository seed exceeds its size limit")
            content = os.read(descriptor, _MAX_SEED_BYTES + 1)
        finally:
            os.close(descriptor)
    if len(content) > _MAX_SEED_BYTES:
        raise ValueError("repository seed exceeds its size limit")
    return content
