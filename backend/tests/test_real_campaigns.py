"""Opt-in first-party AFL++ and libFuzzer acceptance against Docker Desktop/Engine."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
import os
from pathlib import Path
import shutil
from threading import Event
from time import monotonic
from types import SimpleNamespace

import pytest


pytestmark = pytest.mark.docker

PROJECT_ID = 900_001
COMMIT = "a" * 40


def _docker_client():
    from backend.fuzzing.docker.client import DockerClient, DockerUnavailable

    try:
        return DockerClient().connect()
    except DockerUnavailable as error:
        pytest.skip(f"Docker is unavailable: {error}")


def _tree_hash(root: Path) -> str:
    digest = sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        for value in (relative, content):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
    return digest.hexdigest()


def _fixture_image(client, temporary: Path, name: str, toolchain_tag: str, parent_id: str):
    from backend.fuzzing.docker.image_builder import ImageBuilder

    source = Path(__file__).parent / "fixtures" / name
    source_hash = _tree_hash(source)
    recipe = "system-v2" if name == "system_project" else "component-v2-both-harnesses"
    content_hash = sha256(f"{source_hash}:{recipe}".encode("ascii")).hexdigest()
    context = temporary / f"{name}-context"
    fixture = context / "fixture"
    fixture.parent.mkdir(parents=True)
    shutil.copytree(source, fixture)
    asset_id = "91001" if name == "system_project" else "91002"
    binary = "bigeye_system_fixture" if name == "system_project" else "bigeye_component_correct"
    build_target = binary if name == "system_project" else "bigeye_component_correct bigeye_component_incorrect"
    installs = (
        f"install -m 0755 /build/{binary} /opt/bigeye/{binary}"
        if name == "system_project"
        else "install -m 0755 /build/bigeye_component_correct /opt/bigeye/bigeye_component_correct "
             "&& install -m 0755 /build/bigeye_component_incorrect /opt/bigeye/bigeye_component_incorrect"
    )
    compiler = "afl-clang-fast" if name == "system_project" else "clang-18"
    flags = (
        '-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" '
        if name == "system_project" else ""
    )
    dockerfile = context / "Dockerfile"
    dockerfile.write_text(
        f"FROM {toolchain_tag}\n"
        "COPY fixture/ /fixture/\n"
        f"RUN cmake -S /fixture -B /build -DCMAKE_C_COMPILER={compiler} "
        f"-DCMAKE_BUILD_TYPE=RelWithDebInfo {flags}"
        f"&& cmake --build /build --target {build_target} --parallel 2 "
        f"&& install -d -m 0755 /opt/bigeye "
        f"&& {installs}\n"
        f'LABEL bigeye.project="{PROJECT_ID}" bigeye.commit="{COMMIT}" '
        f'bigeye.layer="target" bigeye.content-hash="{content_hash}" '
        f'bigeye.parent-image="{parent_id}" bigeye.target-asset="{asset_id}" '
        f'bigeye.target-content-hash="{content_hash}" bigeye.test="task19a"\n',
        encoding="utf-8",
    )
    tag = f"bigeye-task19a-{name.replace('_project', '')}:{content_hash[:20]}"
    labels = {
        "bigeye.project": str(PROJECT_ID),
        "bigeye.commit": COMMIT,
        "bigeye.layer": "target",
        "bigeye.content-hash": content_hash,
        "bigeye.parent-image": parent_id,
        "bigeye.target-asset": asset_id,
        "bigeye.target-content-hash": content_hash,
        "bigeye.test": "task19a",
    }
    try:
        builder = ImageBuilder(client)
        image_id = builder.inspect_matching(tag, labels)
        if image_id is None:
            image_id = builder.build(dockerfile, tag, lambda _text: None, network_mode="none")
        inspected = client.api.inspect_image(image_id)
        assert (inspected["Os"], inspected["Architecture"]) == ("linux", "amd64")
        assert all(inspected["Config"]["Labels"].get(key) == value for key, value in labels.items())
        return image_id
    finally:
        shutil.rmtree(context)


def _coverage_fixture_image(client, temporary: Path, toolchain_tag: str, parent_id: str):
    from backend.fuzzing.docker.image_builder import ImageBuilder

    source = Path(__file__).parent / "fixtures" / "system_project"
    content_hash = sha256(f"{_tree_hash(source)}:clean-coverage-v1".encode("ascii")).hexdigest()
    context = temporary / "system-coverage-context"
    fixture = context / "fixture"
    fixture.parent.mkdir(parents=True)
    shutil.copytree(source, fixture)
    labels = {
        "bigeye.project": str(PROJECT_ID),
        "bigeye.commit": COMMIT,
        "bigeye.layer": "coverage",
        "bigeye.content-hash": content_hash,
        "bigeye.parent-image": parent_id,
        "bigeye.target-asset-id": "91001",
        "bigeye.configuration-asset-id": "",
        "bigeye.coverage-asset-id": "91003",
        "bigeye.test": "task19a",
    }
    dockerfile = context / "Dockerfile"
    dockerfile.write_text(
        f"FROM {toolchain_tag}\n"
        "COPY fixture/ /src/\n"
        "RUN install -d -m 0755 /opt/bigeye "
        "&& clang-18 -O1 -g -fprofile-instr-generate -fcoverage-mapping "
        "-fsanitize=address,undefined -fno-omit-frame-pointer "
        "/src/src/main.c -o /opt/bigeye/bigeye_system_coverage\n"
        + "".join(f'LABEL {key}="{value}"\n' for key, value in labels.items()),
        encoding="utf-8",
    )
    tag = f"bigeye-task19a-coverage:{content_hash[:20]}"
    try:
        builder = ImageBuilder(client)
        image_id = builder.inspect_matching(tag, labels)
        if image_id is None:
            image_id = builder.build(dockerfile, tag, lambda _text: None, network_mode="none")
        return image_id, content_hash
    finally:
        shutil.rmtree(context)


def _incorrect_component_image(client, temporary: Path, component_image_id: str):
    from backend.fuzzing.docker.image_builder import ImageBuilder

    content_hash = sha256(f"{component_image_id}:incorrect-harness-v1".encode("ascii")).hexdigest()
    context = temporary / "incorrect-component-context"
    context.mkdir()
    labels = {
        "bigeye.project": str(PROJECT_ID),
        "bigeye.commit": COMMIT,
        "bigeye.layer": "target",
        "bigeye.content-hash": content_hash,
        "bigeye.parent-image": component_image_id,
        "bigeye.target-asset": "91004",
        "bigeye.target-content-hash": sha256(
            (Path(__file__).parent / "fixtures/component_project/harnesses/incorrect.c").read_bytes()
        ).hexdigest(),
        "bigeye.parent-target-asset": "91002",
        "bigeye.test": "task19a",
    }
    dockerfile = context / "Dockerfile"
    dockerfile.write_text(
        f"FROM {component_image_id}\n"
        + "".join(f'LABEL {key}="{value}"\n' for key, value in labels.items()),
        encoding="utf-8",
    )
    tag = f"bigeye-task19a-incorrect:{content_hash[:20]}"
    try:
        builder = ImageBuilder(client)
        image_id = builder.inspect_matching(tag, labels)
        if image_id is None:
            image_id = builder.build(dockerfile, tag, lambda _text: None, network_mode="none")
        return image_id, labels
    finally:
        shutil.rmtree(context)


def _campaign_workspace(root: Path, campaign_id: int, seed: Path) -> Path:
    campaign = root / "projects" / str(PROJECT_ID) / "campaigns" / str(campaign_id)
    for name in ("corpus", "output", "config", "logs"):
        (campaign / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(seed, campaign / "corpus" / seed.name)
    return campaign


def _wait_for(description: str, probe, timeout: float = 40.0):
    deadline = monotonic() + timeout
    signal = Event()
    last_error = None
    while monotonic() < deadline:
        try:
            value = probe()
            if value:
                return value
        except (FileNotFoundError, ValueError) as error:
            last_error = error
        signal.wait(min(0.2, max(deadline - monotonic(), 0.0)))
    detail = f": {last_error}" if last_error is not None else ""
    raise AssertionError(f"timed out waiting for {description}{detail}")


class _ArtifactJournal:
    def __init__(self):
        self.records = {}

    async def get(self, project_id, campaign_id, kind, content_sha256):
        return self.records.get((project_id, campaign_id, kind, content_sha256))

    async def record(self, record):
        self.records[(
            record.project_id, record.campaign_id, record.kind, record.content_sha256,
        )] = record
        return record

    async def accepted_count(self, project_id, campaign_id, kind):
        return sum(
            int(record.accepted)
            for key, record in self.records.items()
            if key[:3] == (project_id, campaign_id, kind)
        )


class _Traceability:
    def __init__(self):
        self.snapshots = []

    async def record(self, snapshot):
        self.snapshots.append(snapshot)
        return (SimpleNamespace(id=len(self.snapshots)),)


class _Findings:
    def __init__(self):
        self.rows = {}
        self.links = []

    async def create_or_increment(
        self, *, project_id, fingerprint, classification, description,
        reproducible, candidate_selected,
    ):
        from backend.models.finding import Finding

        existing = self.rows.get((project_id, fingerprint))
        selected = existing is None or candidate_selected
        current_classification = classification if selected else existing.classification
        current_description = description if selected else existing.description
        current_reproducible = reproducible if selected else existing.reproducible
        count = 1 if existing is None else existing.occurrence_count + 1
        finding = Finding(
            id=1 if existing is None else existing.id,
            project_id=project_id,
            fingerprint=fingerprint,
            classification=current_classification,
            priority_rank=1,
            priority_reason=(
                f"{current_classification}; "
                f"{'reproducible' if current_reproducible else 'not reproducible'}; "
                f"observed {count} {'time' if count == 1 else 'times'}"
            ),
            description=current_description,
            reproducible=current_reproducible,
            occurrence_count=count,
            created_at=datetime.now(UTC),
            triaged_at=datetime.now(UTC),
            error=None,
        )
        self.rows[(project_id, fingerprint)] = finding
        return finding

    async def link_campaign(self, campaign_id, project_id, fingerprint):
        value = (campaign_id, project_id, fingerprint)
        if value not in self.links:
            self.links.append(value)


class _EvidenceBoundSpecialist:
    async def triage(self, evidence):
        from backend.agents.outputs.triage_result import TriageResult

        return TriageResult(
            classification="unresolved",
            description="Retained deterministic crash evidence.",
            evidence_ids=list(evidence.evidence_ids),
            uncertainty="The correction experiment determines whether the harness caused the failure.",
            priority_rationale="Await deterministic correction evidence.",
            repair_intent="Compare the original and corrected harness contracts.",
        )


class _NoopCrashMinimiser:
    async def minimise(self, _crash, input_bytes, _expected_signature):
        return input_bytes


def test_real_linux_amd64_probe_uses_the_application_sanitizer_runtime(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.probe import ProbeInvocation, ProbeRunner
    from backend.fuzzing.docker.container_runner import ContainerRunner
    from backend.fuzzing.docker.image_builder import ImageBuilder
    from backend.fuzzing.docker.image_inspector import ImageInspector
    from backend.fuzzing.toolchain.builder import ToolchainBuilder

    client = _docker_client()
    image_id = None
    try:
        toolchain = ToolchainBuilder(
            Path("backend/fuzzing/images/Dockerfile"),
            ImageBuilder(client),
            ImageInspector(client),
        )
        toolchain_info = toolchain.ensure(lambda _text: None)
        image_id = _fixture_image(
            client, tmp_path, "system_project", toolchain.tag(), toolchain_info.image_id,
        )
        invocation = ProbeInvocation(
            "plain seed",
            "seed",
            (
                "/opt/bigeye/bigeye_system_fixture",
                "--mode",
                "plain",
                "--file",
                "/fixture/seeds/plain.txt",
            ),
            b"plain-seed\n",
        )

        observation = asyncio.run(ProbeRunner(ContainerRunner(client)).run(
            image_id, invocation, 10.0, lambda _text: None,
            BASELINE_SANITIZER_ENVIRONMENT,
        ))

        inspected = client.api.inspect_image(image_id)
        assert (inspected["Os"], inspected["Architecture"]) == ("linux", "amd64")
        assert observation.exit_code == 0
        assert observation.immediate_crash is False
        assert "LeakSanitizer" not in observation.sanitizer_output
    finally:
        if image_id is not None:
            try:
                client.images.remove(image_id, force=True)
            except Exception:
                pass
        client.close()


def test_real_linux_amd64_target_and_coverage_stdin_reach_eof(tmp_path: Path) -> None:
    from backend.fuzzing.coverage.llvm_coverage import DockerCoverageExecutor
    from backend.fuzzing.docker.container_runner import ContainerRunner
    from backend.fuzzing.docker.image_builder import ImageBuilder
    from backend.fuzzing.docker.image_inspector import ImageInspector
    from backend.fuzzing.sanitizer_environment import BASELINE_SANITIZER_ENVIRONMENT
    from backend.fuzzing.toolchain.builder import ToolchainBuilder

    client = _docker_client()
    image_ids = []
    try:
        toolchain = ToolchainBuilder(
            Path("backend/fuzzing/images/Dockerfile"),
            ImageBuilder(client),
            ImageInspector(client),
        )
        toolchain_info = toolchain.ensure(lambda _text: None)
        target_image = _fixture_image(
            client, tmp_path, "system_project", toolchain.tag(), toolchain_info.image_id,
        )
        image_ids.append(target_image)
        coverage_image, _content_hash = _coverage_fixture_image(
            client, tmp_path, toolchain.tag(), toolchain_info.image_id,
        )
        image_ids.append(coverage_image)

        target_runner = ContainerRunner(client)
        coverage_runner = DockerCoverageExecutor(client, timeout_seconds=10)
        profile_directory = tmp_path / "stdin-profiles"
        profile_directory.mkdir()
        for index, content in enumerate((b"stdin-eof\n", b"")):
            target = asyncio.run(target_runner.run(
                target_image,
                ["/opt/bigeye/bigeye_system_fixture", "--mode", "plain"],
                10,
                lambda _text: None,
                stdin_bytes=content,
                environment=dict(BASELINE_SANITIZER_ENVIRONMENT),
            ))
            assert target.exit_code == 0
            assert target.output.endswith("\n")

            profile_name = f"stdin-{index}.profraw"
            coverage_environment = dict(BASELINE_SANITIZER_ENVIRONMENT)
            coverage_environment["LLVM_PROFILE_FILE"] = f"/coverage/profiles/{profile_name}"
            coverage_output = coverage_runner.run(
                coverage_image,
                ("/opt/bigeye/bigeye_system_coverage", "--mode", "plain"),
                coverage_environment,
                profile_directory,
                stdin_bytes=content,
            )
            assert coverage_output.endswith(b"\n")
            assert (profile_directory / profile_name).is_file()

        for image_id in image_ids:
            inspected = client.api.inspect_image(image_id)
            assert (inspected["Os"], inspected["Architecture"]) == ("linux", "amd64")
    finally:
        for image_id in reversed(image_ids):
            try:
                client.images.remove(image_id, force=True)
            except Exception:
                pass
        client.close()


class _RealHarnessCorrection:
    def __init__(
        self, replay, corrected_image_id, base_manifest_hash, corrected_manifest_hash,
        target_hash, corrected_hash,
    ):
        self._replay = replay
        self._corrected_image_id = corrected_image_id
        self._base_manifest_hash = base_manifest_hash
        self._corrected_manifest_hash = corrected_manifest_hash
        self._target_hash = target_hash
        self._corrected_hash = corrected_hash
        self.calls = 0

    async def run(self, crash, input_bytes, expected_signature):
        from backend.fuzzing.crashes.correction import CorrectionEvidence
        from backend.fuzzing.crashes.fingerprint import failure_signature

        self.calls += 1
        corrected = replace(
            crash,
            target_asset_id=91002,
            image_id=self._corrected_image_id,
            command=(
                "/opt/bigeye/bigeye_component_correct", "-runs=1", "/bigeye/input/crash",
            ),
        )
        replayed = await self._replay.replay(corrected, input_bytes, "original")
        corrected_signature = failure_signature(replayed) if replayed.crashed else None
        identity = sha256(
            f"{crash.project_id}:{crash.target_asset_id}:91002:{crash.image_id}:"
            f"{self._corrected_image_id}:{expected_signature}:{corrected_signature}".encode("ascii")
        ).hexdigest()
        return CorrectionEvidence(
            project_id=crash.project_id,
            target_asset_id=crash.target_asset_id,
            corrected_asset_id=91002,
            base_image_id=crash.image_id,
            corrected_image_id=self._corrected_image_id,
            target_asset_content_hash=self._target_hash,
            corrected_asset_content_hash=self._corrected_hash,
            base_manifest_hash=self._base_manifest_hash,
            corrected_manifest_hash=self._corrected_manifest_hash,
            commit_sha=crash.commit_sha,
            base_signature=expected_signature,
            corrected_signature=corrected_signature,
            signature_disappeared=corrected_signature is None,
            evidence_id=f"correction:{identity}",
        )


def test_real_system_and_component_campaigns_run_concurrently_and_clean_up(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.fuzzing.campaigns.recovery import (
        CampaignRecovery,
        RecoverableCampaign,
        RecoveryAssetIdentity,
    )
    from backend.fuzzing.coverage.llvm_coverage import DockerCoverageExecutor, LlvmCoverage
    from backend.fuzzing.coverage.replay_verifier import ResolvedCoverageTarget
    from backend.fuzzing.crashes.minimisation import CrashMinimiser
    from backend.fuzzing.crashes.quarantine import CrashObservation, CrashQuarantine
    from backend.fuzzing.crashes.triage import CrashPipeline
    from backend.fuzzing.docker.fuzz_container import FuzzCampaign, FuzzContainerService
    from backend.fuzzing.docker.image_builder import ImageBuilder
    from backend.fuzzing.docker.image_inspector import ImageInspector
    from backend.fuzzing.engines.afl.command import AflCommand
    from backend.fuzzing.engines.afl.stats import AflStats
    from backend.fuzzing.engines.contracts import EngineSpec
    from backend.fuzzing.engines.libfuzzer.command import LibFuzzerCommand
    from backend.fuzzing.engines.libfuzzer.stats import LibFuzzerStats
    from backend.fuzzing.toolchain.builder import ToolchainBuilder
    from backend.models.campaign_artifact import ProcessedCampaignArtifact
    from backend.services.campaigns.production_artifacts import ProductionCorpusArtifactHandler
    from backend.services.campaigns.production_evidence_factory import (
        DockerCrashReplayExecutor,
        ProductionNativeCorpusMinimisation,
    )

    client = _docker_client()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fixture_root = Path(__file__).parent / "fixtures"
    nonce = os.getpid() * 10_000 + (monotonic_ns() % 10_000)
    system_campaign_id = nonce * 10 + 1
    component_campaign_id = nonce * 10 + 2
    service = FuzzContainerService(client, workspace, stop_timeout_seconds=5)
    started = []
    test_image_ids = []
    try:
        inspector = ImageInspector(client)
        toolchain = ToolchainBuilder(
            Path("backend/fuzzing/images/Dockerfile"), ImageBuilder(client), inspector,
        )
        toolchain_info = toolchain.ensure(lambda _text: None)
        assert (toolchain_info.os, toolchain_info.architecture) == ("linux", "amd64")
        system_image = _fixture_image(
            client, tmp_path, "system_project", toolchain.tag(), toolchain_info.image_id,
        )
        test_image_ids.append(system_image)
        component_image = _fixture_image(
            client, tmp_path, "component_project", toolchain.tag(), toolchain_info.image_id,
        )
        test_image_ids.append(component_image)
        coverage_image, coverage_content_hash = _coverage_fixture_image(
            client, tmp_path, toolchain.tag(), toolchain_info.image_id,
        )
        test_image_ids.append(coverage_image)
        incorrect_image, incorrect_labels = _incorrect_component_image(
            client, tmp_path, component_image,
        )
        test_image_ids.append(incorrect_image)

        system_path = _campaign_workspace(
            workspace, system_campaign_id, fixture_root / "system_project" / "seeds" / "plain.txt",
        )
        component_path = _campaign_workspace(
            workspace, component_campaign_id,
            fixture_root / "component_project" / "seeds" / "record.input",
        )
        system_campaign = FuzzCampaign(system_campaign_id, PROJECT_ID, COMMIT)
        component_campaign = FuzzCampaign(component_campaign_id, PROJECT_ID, COMMIT)
        system_invocation = AflCommand.build(EngineSpec(
            engine="afl",
            image_id=system_image,
            target_command=("/opt/bigeye/bigeye_system_fixture", "--mode", "plain", "--file"),
            input_mode="file",
            corpus_path="/campaign/corpus",
            output_path="/campaign/output",
            role="main",
            sanitizer_environment={
                "ASAN_OPTIONS": "abort_on_error=1:symbolize=0:detect_leaks=0",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=0",
                "AFL_SKIP_CPUFREQ": "1",
            },
            timeout_ms=1_000,
            memory_limit_mb=512,
            campaign_labels={"bigeye.test": "task19a", "bigeye.configuration": "plain"},
        ))
        component_invocation = LibFuzzerCommand.build(EngineSpec(
            engine="libfuzzer",
            image_id=component_image,
            target_command=("/opt/bigeye/bigeye_component_correct",),
            input_mode="inprocess",
            corpus_path="/campaign/corpus",
            output_path="/campaign/output",
            role="main",
            sanitizer_environment={"ASAN_OPTIONS": "abort_on_error=1:symbolize=0:detect_leaks=0"},
            timeout_ms=1_000,
            memory_limit_mb=512,
            campaign_labels={"bigeye.test": "task19a", "bigeye.configuration": "correct-harness"},
        ))

        system_identity = service.start(system_campaign, system_invocation)
        started.append(system_identity)
        component_identity = service.start(component_campaign, component_invocation)
        started.append(component_identity)
        assert service.recover(system_campaign, system_invocation).state == "running"
        assert service.recover(component_campaign, component_invocation).state == "running"

        afl_stats = _wait_for(
            "AFL++ execution statistics",
            lambda: _afl_evidence(system_path / "output" / "main" / "fuzzer_stats", AflStats),
        )
        libfuzzer_stats = _wait_for(
            "libFuzzer execution statistics",
            lambda: _libfuzzer_evidence(service, component_identity, LibFuzzerStats),
        )
        assert afl_stats.execution_count > 0 and afl_stats.execution_rate > 0
        assert libfuzzer_stats.execution_count > 0 and libfuzzer_stats.corpus_count > 1
        assert system_identity.container_id != component_identity.container_id
        assert component_path.joinpath("corpus").is_dir()

        coverage_target = ResolvedCoverageTarget(
            id=system_campaign_id,
            project_id=PROJECT_ID,
            commit_sha=COMMIT,
            clean_image=coverage_image,
            clean_image_id=coverage_image,
            clean_content_hash=coverage_content_hash,
            clean_parent_image_id=toolchain_info.image_id,
            binary_path="/opt/bigeye/bigeye_system_coverage",
            replay_command=(
                "/opt/bigeye/bigeye_system_coverage", "--mode", "plain", "--file", "{input}",
            ),
            target_asset_id=91001,
            configuration_asset_id=None,
            clean_build_configuration_asset_id=None,
            strategy_asset_id=91001,
            coverage_asset_id=91003,
            cpu_exposure_seconds=max(
                afl_stats.execution_count / max(afl_stats.execution_rate, 1.0), 0.001,
            ),
            repository_root=fixture_root / "system_project",
            replay_environment=(
                ("ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0"),
                ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=0"),
            ),
        )
        coverage = LlvmCoverage(
            client, DockerCoverageExecutor(client), tmp_path / "clean-coverage", max_inputs=32,
        )
        clean_snapshot = coverage.replay(
            coverage_target, (system_path / "corpus" / "plain.txt",),
        )
        assert clean_snapshot.build_kind == "clean"
        assert clean_snapshot.lines
        assert clean_snapshot.hits
        assert clean_snapshot.replay_environment == coverage_target.replay_environment

        queue_file = _wait_for(
            "an AFL++ queue input",
            lambda: _first_regular_file(system_path / "output" / "main" / "queue"),
        )
        queue_content = queue_file.read_bytes()
        queue_digest = sha256(queue_content).hexdigest()
        queue_artifact = CampaignArtifactObservation(
            "corpus",
            queue_file.relative_to(system_path).as_posix(),
            queue_digest,
            len(queue_content),
        )
        journal = _ArtifactJournal()
        traceability = _Traceability()
        class CoverageTargetResolver:
            async def resolve(self, **_values):
                return coverage_target

        target_resolver = CoverageTargetResolver()
        corpus_handler = ProductionCorpusArtifactHandler(
            workspace=workspace,
            journal=journal,
            target_resolver=target_resolver,
            clean_coverage=coverage,
            traceability=traceability,
        )
        project = SimpleNamespace(id=PROJECT_ID, commit_sha=COMMIT)
        persisted_campaign = SimpleNamespace(
            id=system_campaign_id,
            project_id=PROJECT_ID,
            target_asset_id=91001,
            configuration_asset_id=None,
        )
        admitted = asyncio.run(corpus_handler.process(
            project=project,
            campaign=persisted_campaign,
            invocation=system_invocation,
            progress=SimpleNamespace(),
            artifact=queue_artifact,
        ))
        assert admitted.accepted is True
        assert traceability.snapshots and traceability.snapshots[0].build_kind == "clean"
        assert (system_path / "corpus" / queue_digest).read_bytes() == queue_content

        second_content = b"AIGEYE!x\n"
        second_digest = sha256(second_content).hexdigest()
        (system_path / "corpus" / second_digest).write_bytes(second_content)
        asyncio.run(journal.record(ProcessedCampaignArtifact(
            PROJECT_ID,
            system_campaign_id,
            "corpus",
            second_digest,
            True,
            f"corpus:{system_campaign_id}:{second_digest}",
            "clean replay added first-hit project coverage",
            f"campaigns/{system_campaign_id}/corpus/{second_digest}",
        )))
        minimisation = ProductionNativeCorpusMinimisation(
            client=client,
            workspace=workspace,
            artifact_repository=journal,
            target_resolver=target_resolver,
            coverage=coverage,
            threshold=2,
        )
        minimisation_evidence = asyncio.run(minimisation.minimise_if_needed(
            project=project,
            campaign=persisted_campaign,
            invocation=system_invocation,
        ))
        assert minimisation_evidence is not None
        assert minimisation_evidence.startswith(
            f"corpus-minimisation:{PROJECT_ID}:{system_campaign_id}:"
        )
        previous_system_identity = system_identity
        replacement_identity = service.recover(system_campaign, system_invocation)
        assert replacement_identity is not None
        assert replacement_identity.state == "running"
        assert replacement_identity.container_id != previous_system_identity.container_id
        started.remove(previous_system_identity)
        system_identity = replacement_identity
        started.append(system_identity)

        system_container = client.containers.get(system_identity.container_id)
        system_container.pause()
        system_container.reload()
        assert system_container.status == "paused"
        system_container.unpause()
        system_container.reload()
        assert system_container.status == "running"

        service.stop(system_identity)
        started.remove(system_identity)

        class RestartControl:
            def __init__(self):
                self.identity = None

            def adopt(self, _campaign, _container):
                raise AssertionError("a removed campaign container cannot be adopted")

            def quarantine(self, _campaign, _container, _reason):
                raise AssertionError("an exact removed campaign cannot require quarantine")

            def restart(self, _campaign, _container):
                assert _container is None
                self.identity = service.start(system_campaign, system_invocation)

        restart_control = RestartControl()
        recovery_records = CampaignRecovery(workspace, restart_control).recover(
            PROJECT_ID,
            (RecoverableCampaign(
                PROJECT_ID,
                system_campaign_id,
                COMMIT,
                system_image,
                (RecoveryAssetIdentity(
                    91001,
                    client.api.inspect_image(system_image)["Config"]["Labels"][
                        "bigeye.target-content-hash"
                    ],
                ),),
                True,
                (f"corpus-minimisation:{system_campaign_id}",),
            ),),
            (),
        )
        assert [record.action for record in recovery_records] == ["restarted"]
        assert restart_control.identity is not None
        system_identity = restart_control.identity
        started.append(system_identity)
        assert service.recover(system_campaign, system_invocation).state == "running"

        replay = DockerCrashReplayExecutor(client, workspace, timeout_seconds=10)
        corrected_labels = client.api.inspect_image(component_image)["Config"]["Labels"]
        target_hash = incorrect_labels["bigeye.target-content-hash"]
        corrected_hash = sha256(
            (fixture_root / "component_project/harnesses/correct.c").read_bytes()
        ).hexdigest()
        correction = _RealHarnessCorrection(
            replay,
            component_image,
            incorrect_labels["bigeye.content-hash"],
            corrected_labels["bigeye.content-hash"],
            target_hash,
            corrected_hash,
        )
        findings = _Findings()
        crash_pipeline = CrashPipeline(
            quarantine=CrashQuarantine(workspace),
            replayer=replay,
            minimiser=CrashMinimiser(_NoopCrashMinimiser()),
            findings=findings,
            specialist=_EvidenceBoundSpecialist(),
            correction=correction,
        )
        incorrect_observation = CrashObservation(
            project_id=PROJECT_ID,
            campaign_id=component_campaign_id,
            commit_sha=COMMIT,
            engine="libfuzzer",
            image_id=incorrect_image,
            target_asset_id=91004,
            configuration_asset_id=None,
            sanitizer="address+undefined",
            command=(
                "/opt/bigeye/bigeye_component_incorrect", "-runs=1", "/bigeye/input/crash",
            ),
            input_bytes=b"\x01\x00",
            clean_image_id=component_image,
            clean_command=(
                "/opt/bigeye/bigeye_component_correct", "-runs=1", "/bigeye/input/crash",
            ),
            harness_misuse_evidence=("probe:invalid-output-contract",),
        )
        first_finding = asyncio.run(crash_pipeline.process(incorrect_observation))
        second_observation = replace(incorrect_observation, input_bytes=b"\x02\x00")
        second_finding = asyncio.run(crash_pipeline.process(second_observation))
        assert first_finding.id == second_finding.id
        assert second_finding.occurrence_count == 2
        assert second_finding.classification == "harness-induced false positive"
        assert correction.calls == 1
        groups = list(
            (workspace / "projects" / str(PROJECT_ID) / "crashes" / "quarantine").iterdir()
        )
        retained_inputs = {
            (group / "1" / "original.bin").read_bytes()
            for group in groups
            if (group / "1" / "original.bin").is_file()
        }
        assert {incorrect_observation.input_bytes, second_observation.input_bytes} <= retained_inputs
    finally:
        for identity in reversed(started):
            try:
                service.stop(identity)
            except Exception:
                container = client.containers.get(identity.container_id)
                try:
                    container.kill()
                finally:
                    container.remove(force=True)
        leftovers = client.containers.list(all=True, filters={"label": [
            "com.bigeye.managed=fuzz-campaign", f"com.bigeye.project-id={PROJECT_ID}",
            "bigeye.test=task19a",
        ]})
        assert leftovers == []
        for image_id in reversed(test_image_ids):
            try:
                client.images.remove(image_id, force=True)
            except Exception:
                pass
        for _attempt in range(8):
            labelled = client.images.list(all=True, filters={"label": "bigeye.test=task19a"})
            if not labelled:
                break
            removed = False
            for image in labelled:
                try:
                    client.images.remove(image.id, force=True)
                    removed = True
                except Exception:
                    continue
            if not removed:
                break
        assert client.images.list(
            all=True, filters={"label": "bigeye.test=task19a"},
        ) == []
        assert list(tmp_path.glob("*-context")) == []
        client.close()


def monotonic_ns() -> int:
    return int(monotonic() * 1_000_000_000)


def _afl_evidence(path: Path, parser):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1_048_576:
        return None
    statistics = parser.parse(path.read_text(encoding="utf-8"))
    return statistics if statistics.execution_count > 0 else None


def _libfuzzer_evidence(service, identity, parser):
    chunks = []
    service.stream_logs(identity, chunks.append, follow=False)
    statistics = parser.parse("".join(chunks))
    return statistics if statistics.execution_count > 0 else None


def _first_regular_file(directory: Path):
    if not directory.is_dir() or directory.is_symlink():
        return None
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024:
            return path
    return None
