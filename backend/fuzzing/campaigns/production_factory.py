"""Compose the existing deterministic preparation components for local production use."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
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
from backend.fuzzing.sanitizer_environment import BASELINE_SANITIZER_ENVIRONMENT
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
        target_script = _application_preparation_file(
            context,
            "target-build.sh",
            _build_script(
                proposal.build_command,
                instance_type=proposal.instance_type,
                coverage=False,
            ),
        )
        coverage_script = _application_preparation_file(
            context,
            "coverage-build.sh",
            _build_script(
                proposal.build_command,
                instance_type=proposal.instance_type,
                coverage=True,
            ),
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
        if replay_command[-1] == "{stdin}":
            pass
        elif replay_command[-1].startswith(("/bigeye/target/", "/src/")):
            replay_command[-1] = "{input}"
        else:
            raise ValueError("clean probe requires one file or stdin input marker")
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
            clean_build_configuration_asset_id=configuration_id,
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
    clean_build_configuration_asset_id: int | None
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
    replay_environment: tuple[tuple[str, str], ...] = BASELINE_SANITIZER_ENVIRONMENT


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
        try:
            write_asset_file(context, relative_path, content, None)
        except GeneratedAssetError as error:
            try:
                concurrent = read_asset_file(context, relative_path)
            except GeneratedAssetError:
                raise error
            if concurrent["content"] != content:
                raise error
    else:
        if existing["content"] != content:
            raise ValueError("application-owned generated preparation source changed")
    return context.generated_assets_root / relative_path


def _application_preparation_file(context, name: str, content: str) -> tuple[Path, str]:
    digest = sha256(content.encode("utf-8")).hexdigest()
    source = _application_file(
        context, f"application/preparation/{digest}/{name}", content,
    )
    return source, digest


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


def _build_script(command: str, *, instance_type: str, coverage: bool) -> str:
    if not isinstance(command, str) or not command.strip() or any(
        character in command for character in ("\x00", "\r", "\n")
    ):
        raise ValueError("target build command must be one non-empty line")
    if instance_type not in {"system-level", "component-level"}:
        raise ValueError("target instance type must be system-level or component-level")

    try:
        arguments = shlex.split(command, posix=True)
    except ValueError as error:
        raise ValueError("target build command is not valid shell syntax") from error
    _reject_agent_compiler_policy(arguments)

    component = instance_type == "component-level"
    compiler = "clang-18" if coverage or component else "afl-clang-fast"
    cxx_compiler = "clang++-18" if coverage or component else "afl-clang-fast++"
    compile_sanitizers = (
        "-fsanitize=fuzzer-no-link,address,undefined"
        if component
        else "-fsanitize=address,undefined"
    )
    link_sanitizers = (
        "-fsanitize=fuzzer,address,undefined"
        if component
        else "-fsanitize=address,undefined"
    )
    compile_flags = f"{compile_sanitizers} -fno-omit-frame-pointer"
    link_flags = link_sanitizers
    if coverage:
        compile_flags += " -fprofile-instr-generate -fcoverage-mapping"
        link_flags += " -fprofile-instr-generate"
    cmake_command = _instrument_cmake_build(
        arguments,
        instance_type=instance_type,
        coverage=coverage,
        compiler=compiler,
        cxx_compiler=cxx_compiler,
        compile_flags=compile_flags,
        link_flags=link_flags,
    )
    if cmake_command is None:
        selected_command = _instrument_direct_compiler(
            arguments,
            instance_type=instance_type,
            coverage=coverage,
            compile_flags=compile_flags,
            link_flags=link_flags,
        )
    else:
        selected_command = cmake_command
    flags = (
        f"export CC={compiler}\n"
        f"export CXX={cxx_compiler}\n"
        f'export CFLAGS="{compile_flags}"\n'
        f'export CXXFLAGS="{compile_flags}"\n'
        f'export LDFLAGS="{link_flags}"\n'
    )
    if coverage:
        flags += 'export RUSTFLAGS="-C instrument-coverage"\n'
    return "#!/bin/sh\nset -eu\n" + flags + selected_command + "\n"


def _reject_agent_compiler_policy(arguments: list[str]) -> None:
    controlled_assignments = (
        "CC=", "CXX=", "CFLAGS=", "CXXFLAGS=", "LDFLAGS=", "RUSTFLAGS=",
        "BIGEYE_SOURCE_DIR=", "BIGEYE_BUILD_ROOT=",
        "-DCMAKE_C_COMPILER", "-DCMAKE_CXX_COMPILER",
        "-DCMAKE_C_FLAGS", "-DCMAKE_CXX_FLAGS",
        "-DCMAKE_EXE_LINKER_FLAGS", "-DCMAKE_SHARED_LINKER_FLAGS",
        "-DCMAKE_MODULE_LINKER_FLAGS",
        "-DCMAKE_TOOLCHAIN_FILE", "--TOOLCHAIN",
    )
    for argument in arguments:
        upper = argument.upper()
        sanitizer_option = upper.startswith("-D") and any(
            marker in upper.split("=", 1)[0]
            for marker in ("SANIT", "ASAN", "UBSAN", "MSAN", "TSAN")
        )
        if (
            _is_compiler_policy_override(argument)
            or argument.startswith("@")
            or sanitizer_option
            or any(upper.startswith(prefix) for prefix in controlled_assignments)
        ):
            raise ValueError("target build command cannot override BigEye compiler or sanitizer policy")


def _is_compiler_policy_override(argument: str) -> bool:
    upper = argument.upper()
    exact_or_assigned_options = (
        "--FOR-LINKER",
        "--LD-PATH",
        "--CONFIG",
        "--CONFIG-SYSTEM-DIR",
        "--CONFIG-USER-DIR",
        "--DRIVER-MODE",
        "--GCC-TOOLCHAIN",
        "-GCC-TOOLCHAIN",
        "--GCC-INSTALL-DIR",
        "--RESOURCE-DIR",
        "-RESOURCE-DIR",
        "-CCC-INSTALL-DIR",
        "-CC1",
        "-CC1AS",
    )
    if upper == "--NO-DEFAULT-CONFIG" or any(
        upper == option or upper.startswith(option + "=")
        for option in exact_or_assigned_options
    ):
        return True
    if upper.startswith((
        "-FSANITIZE", "-FNO-SANITIZE", "-FOMIT-FRAME-POINTER",
        "-FPROFILE-INSTR", "-FNO-PROFILE-INSTR",
        "-FCOVERAGE-MAPPING", "-FNO-COVERAGE-MAPPING",
        "-MLLVM", "-XCLANG", "-XLINKER",
        "-XARCH_", "-XOFFLOAD-LINKER", "--OFFLOAD-LINKER",
        "-FPLUGIN", "-FPASS-PLUGIN",
        "-SPECS=", "--SPECS=", "-FUSE-LD=", "-WRAPPER",
    )):
        return True
    if upper.startswith("-WL,"):
        linker_arguments = upper.removeprefix("-WL,").split(",")
        return any(
            value.startswith(("-PLUGIN", "--PLUGIN", "-PLUGIN-OPT", "--PLUGIN-OPT"))
            or value.startswith(("@", "-WRAP", "--WRAP"))
            for value in linker_arguments
        )
    return False


_CMAKE_POLICY_VALUE = re.compile(
    r"(?:^|[\s;,:=>])(?:"
    r"@|"
    r"-f(?:no-)?sanitize(?:[=-]|(?=$|[\s;,:>]))|"
    r"-fomit-frame-pointer(?:=|(?=$|[\s;,:>]))|"
    r"-f(?:no-)?profile-instr(?:[=-]|(?=$|[\s;,:>]))|"
    r"-f(?:no-)?coverage-mapping(?:=|(?=$|[\s;,:>]))|"
    r"-mllvm(?==|$|[\s;,:>])|-Xclang(?==|$|[\s;,:>])|"
    r"-Xlinker(?==|$|[\s;,:>])|"
    r"-fplugin(?:[=-]|(?=$|[\s;,:>]))|"
    r"-fpass-plugin(?:[=-]|(?=$|[\s;,:>]))|"
    r"-{1,2}specs=|-fuse-ld=|-wrapper(?==|$|[\s;,:>])|"
    r"-B(?:[=/]|(?=$|[\s;,:>]))|"
    r"LINKER:(?:SHELL:)?(?:-{1,2}(?:plugin|wrap)(?:[=,]|(?=$|[\s;:>]))|@)|"
    r"-Wl,(?:-{1,2}plugin(?:[=,]|(?=$|[\s;:>]))|"
    r"-{1,2}wrap(?:[=,]|(?=$|[\s;:>]))|@)"
    r")",
    re.IGNORECASE,
)


def _cmake_value_overrides_compiler_policy(value: str) -> bool:
    return _CMAKE_POLICY_VALUE.search(value) is not None


def _validate_cmake_scalar(value: str) -> None:
    stripped = value.lstrip()
    transformation = re.search(r"(?:^|\s)(?:SHELL|LINKER):", value, re.IGNORECASE)
    if (
        any(character in value for character in ("\x00", "\r", "\n", ";", "$", "`"))
        or stripped.startswith(("-", "@"))
        or transformation is not None
    ):
        raise ValueError(
            "CMake project option values must be safe scalars under BigEye "
            "compiler or sanitizer policy"
        )


def _instrument_cmake_build(
    arguments: list[str],
    *,
    instance_type: str,
    coverage: bool,
    compiler: str,
    cxx_compiler: str,
    compile_flags: str,
    link_flags: str,
) -> str | None:
    if arguments[0] != "cmake":
        return None
    operators = tuple(
        (index, value) for index, value in enumerate(arguments)
        if value in _SHELL_OPERATOR_TOKENS
    )
    configure_options: list[str] = []
    source_expression = "$BIGEYE_SOURCE_DIR"
    if len(arguments) >= 2 and arguments[1] == "--build" and not operators:
        build_arguments = arguments
        original_build_directory = _cmake_build_directory(build_arguments)
        cache_guard = _cmake_cache_guard(original_build_directory)
    elif len(operators) == 1 and operators[0][1] == "&&":
        separator = operators[0][0]
        configure_arguments = arguments[:separator]
        build_arguments = arguments[separator + 1:]
        if len(build_arguments) < 2 or build_arguments[:2] != ["cmake", "--build"]:
            raise ValueError("CMake configuration must be followed by one cmake --build command")
        source_directory, configured_build_directory, configure_options = (
            _parse_cmake_configuration(configure_arguments)
        )
        original_build_directory = _cmake_build_directory(build_arguments)
        if configured_build_directory != original_build_directory:
            raise ValueError("CMake configure and build directories must match")
        source_expression = _cmake_source_expression(source_directory)
        cache_guard = ""
    else:
        raise ValueError(
            "CMake target compilation must be a build command or one explicit configure-and-build pair"
        )

    profile = f"{instance_type.removesuffix('-level')}-{'coverage' if coverage else 'target'}"
    build_name = f"build-{profile}"
    build_directory = f"$BIGEYE_BUILD_ROOT/{build_name}"
    definitions = (
        f"-DCMAKE_C_COMPILER:FILEPATH={compiler}",
        f"-DCMAKE_CXX_COMPILER:FILEPATH={cxx_compiler}",
        f"-DCMAKE_C_FLAGS:STRING={compile_flags}",
        f"-DCMAKE_CXX_FLAGS:STRING={compile_flags}",
        f"-DCMAKE_EXE_LINKER_FLAGS:STRING={link_flags}",
        f"-DCMAKE_SHARED_LINKER_FLAGS:STRING={link_flags}",
        f"-DCMAKE_MODULE_LINKER_FLAGS:STRING={link_flags}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON",
        *(
            ("-DCMAKE_TRY_COMPILE_TARGET_TYPE:STRING=STATIC_LIBRARY",)
            if instance_type == "component-level"
            else ()
        ),
    )
    configure = (
        'BIGEYE_SOURCE_DIR="${BIGEYE_SOURCE_DIR:-/src}"\n'
        'BIGEYE_BUILD_ROOT="${BIGEYE_BUILD_ROOT:-/opt/bigeye}"\n'
        + cache_guard
        + f'rm -rf "{build_directory}"\n'
        f'cmake -S "{source_expression}" -B "{build_directory}" '
        + " ".join(shlex.quote(value) for value in (*configure_options, *definitions))
    )
    build = f'cmake --build "{build_directory}"'
    if len(build_arguments) > 3:
        build += " " + shlex.join(build_arguments[3:])
    publish = (
        'rm -rf "$BIGEYE_BUILD_ROOT/build"\n'
        f'ln -s "{build_name}" "$BIGEYE_BUILD_ROOT/build"'
    )
    return configure + "\n" + build + "\n" + publish


def _cmake_build_directory(arguments: list[str]) -> str:
    if (
        len(arguments) < 3
        or arguments[0] != "cmake"
        or arguments[1] != "--build"
    ):
        raise ValueError("CMake build command must provide one build directory")
    directory = arguments[2]
    if directory != "/opt/bigeye/build":
        raise ValueError("CMake requires the canonical /opt/bigeye/build directory")
    _validate_cmake_build_options(arguments[3:])
    return directory


def _parse_cmake_configuration(arguments: list[str]) -> tuple[str, str, list[str]]:
    if not arguments or arguments[0] != "cmake":
        raise ValueError("CMake configuration must start with cmake")
    source = None
    build = None
    options: list[str] = []
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-S", "-B"}:
            if index + 1 >= len(arguments):
                raise ValueError(f"CMake {argument} requires a directory")
            value = arguments[index + 1]
            index += 2
            if argument == "-S":
                source = value
            else:
                build = value
            continue
        if argument.startswith("-S") and len(argument) > 2:
            source = argument[2:]
        elif argument.startswith("-B") and len(argument) > 2:
            build = argument[2:]
        else:
            options.append(argument)
        index += 1
    if source is None or build is None:
        raise ValueError("explicit CMake configuration requires both -S and -B")
    return source, build, _validate_cmake_project_options(options)


def _cmake_source_expression(source: str) -> str:
    if source == "/src":
        return "$BIGEYE_SOURCE_DIR"
    if source.startswith("/src/"):
        relative = source.removeprefix("/src/")
        if (
            not relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or any(character in relative for character in '"$~\\`')
        ):
            raise ValueError("CMake source directory must stay inside /src")
        return "$BIGEYE_SOURCE_DIR/" + relative
    raise ValueError("CMake source directory must stay inside /src")


def _validate_cmake_project_options(options: list[str]) -> list[str]:
    validated: list[str] = []
    pattern = re.compile(
        r"-D([A-Za-z][A-Za-z0-9_]*)(?::(BOOL|STRING|PATH|FILEPATH))?=(.*)",
        re.DOTALL,
    )
    for option in options:
        match = pattern.fullmatch(option)
        if match is None:
            raise ValueError("CMake accepts only explicit project -D options")
        key = match.group(1).upper()
        value = match.group(3)
        if key.startswith("CMAKE_"):
            raise ValueError("CMake application-owned options cannot be overridden")
        _validate_cmake_scalar(value)
        if (
            key in {"CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS", "RUSTFLAGS"}
            or key.endswith(("_CC", "_CXX", "_CFLAGS", "_CXXFLAGS", "_LDFLAGS"))
            or "COMPILER" in key
            or any(marker in key for marker in ("SANIT", "ASAN", "UBSAN", "MSAN", "TSAN"))
            or _cmake_value_overrides_compiler_policy(value)
        ):
            raise ValueError("target build command cannot override BigEye compiler or sanitizer policy")
        validated.append(option)
    return validated


def _validate_cmake_build_options(options: list[str]) -> None:
    index = 0
    while index < len(options):
        option = options[index]
        if option == "--target":
            index += 1
            start = index
            while index < len(options) and not options[index].startswith("-"):
                if re.fullmatch(r"[A-Za-z0-9_.:+/-]+", options[index]) is None:
                    raise ValueError("CMake target name is invalid")
                index += 1
            if index == start:
                raise ValueError("CMake --target requires at least one target")
            continue
        if option == "--parallel":
            index += 1
            if index < len(options) and not options[index].startswith("-"):
                if not options[index].isdigit() or not 1 <= int(options[index]) <= 128:
                    raise ValueError("CMake parallelism must be between 1 and 128")
                index += 1
            continue
        if option.startswith("--parallel="):
            value = option.removeprefix("--parallel=")
            if not value.isdigit() or not 1 <= int(value) <= 128:
                raise ValueError("CMake parallelism must be between 1 and 128")
            index += 1
            continue
        if option == "--config":
            if index + 1 >= len(options) or re.fullmatch(
                r"[A-Za-z0-9_.-]+", options[index + 1]
            ) is None:
                raise ValueError("CMake --config value is invalid")
            index += 2
            continue
        if option in {"--clean-first", "--verbose"}:
            index += 1
            continue
        raise ValueError("CMake build option is not supported")


def _cmake_cache_guard(build_directory: str) -> str:
    cache = build_directory.rstrip("/") + "/CMakeCache.txt"
    message = (
        "existing CMake configuration requires explicit "
        "cmake -S ... -B ... && cmake --build"
    )
    return (
        f"if [ -f {shlex.quote(cache)} ]; then\n"
        f"  printf '%s\\n' {shlex.quote(message)} >&2\n"
        "  exit 2\n"
        "fi\n"
    )


def _instrument_direct_compiler(
    arguments: list[str],
    *,
    instance_type: str,
    coverage: bool,
    compile_flags: str,
    link_flags: str,
) -> str:
    compiler_name = arguments[0]
    if re.fullmatch(
        r"(?:cc|c\+\+|gcc(?:-[0-9]+(?:\.[0-9]+)*)?|g\+\+(?:-[0-9]+(?:\.[0-9]+)*)?"
        r"|clang(?:-[0-9]+(?:\.[0-9]+)*)?|clang\+\+(?:-[0-9]+(?:\.[0-9]+)*)?"
        r"|afl-clang-fast(?:\+\+)?)",
        compiler_name,
    ) is None:
        raise ValueError("target build command must use a supported build frontend")
    if any(argument in _SHELL_OPERATOR_TOKENS for argument in arguments):
        raise ValueError("direct compiler build command must be shell-free")
    if any(argument == "-B" or argument.startswith("-B") for argument in arguments[1:]):
        raise ValueError("target build command cannot override BigEye compiler or sanitizer policy")

    cxx = "++" in compiler_name
    if coverage or instance_type == "component-level":
        selected_compiler = "clang++-18" if cxx else "clang-18"
    else:
        selected_compiler = "afl-clang-fast++" if cxx else "afl-clang-fast"
    if "-c" in arguments:
        direct_flags = compile_flags
    else:
        direct_flags = link_flags + " -fno-omit-frame-pointer"
        if coverage:
            direct_flags += " -fcoverage-mapping"
    return shlex.join((selected_compiler, *shlex.split(direct_flags), *arguments[1:]))


def _probe_invocations(context, proposal) -> tuple[ProbeInvocation, ...]:
    try:
        command = tuple(shlex.split(proposal.run_command, posix=True))
    except ValueError as error:
        raise ValueError("target run command is not valid shell-free argv") from error
    if not command or not command[0].startswith("/opt/bigeye/"):
        raise ValueError("target run command must start with an /opt/bigeye executable")
    if any(item in _SHELL_OPERATOR_TOKENS for item in command):
        raise ValueError("target run command cannot contain shell operators")
    if any("{stdin}" in item for item in command):
        raise ValueError("target run command cannot contain the application-owned stdin marker")
    command = tuple("{input}" if value == "@@" else value for value in command)
    if command.count("{input}") > 1:
        raise ValueError("target run command may contain one input placeholder")
    if "{input}" not in command and proposal.instance_type == "component-level":
        command = (*command, "{input}")
    if "{input}" not in command and proposal.instance_type == "system-level":
        command = (*command, "{stdin}")

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
