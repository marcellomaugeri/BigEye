"""Opt-in first-party AFL++ and libFuzzer acceptance against Docker Desktop/Engine."""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
from threading import Event
from time import monotonic

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
    content_hash = _tree_hash(source)
    context = temporary / f"{name}-context"
    fixture = context / "fixture"
    fixture.parent.mkdir(parents=True)
    shutil.copytree(source, fixture)
    asset_id = "91001" if name == "system_project" else "91002"
    binary = "bigeye_system_fixture" if name == "system_project" else "bigeye_component_correct"
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
        f"&& cmake --build /build --target {binary} --parallel 2 "
        f"&& install -d -m 0755 /opt/bigeye "
        f"&& install -m 0755 /build/{binary} /opt/bigeye/{binary}\n"
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
    builder = ImageBuilder(client)
    image_id = builder.inspect_matching(tag, labels)
    if image_id is None:
        image_id = builder.build(dockerfile, tag, lambda _text: None, network_mode="none")
    inspected = client.api.inspect_image(image_id)
    assert (inspected["Os"], inspected["Architecture"]) == ("linux", "amd64")
    assert all(inspected["Config"]["Labels"].get(key) == value for key, value in labels.items())
    return image_id


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


def test_real_system_and_component_campaigns_run_concurrently_and_clean_up(tmp_path: Path) -> None:
    from backend.fuzzing.docker.fuzz_container import FuzzCampaign, FuzzContainerService
    from backend.fuzzing.docker.image_builder import ImageBuilder
    from backend.fuzzing.docker.image_inspector import ImageInspector
    from backend.fuzzing.engines.afl.command import AflCommand
    from backend.fuzzing.engines.afl.stats import AflStats
    from backend.fuzzing.engines.contracts import EngineSpec
    from backend.fuzzing.engines.libfuzzer.command import LibFuzzerCommand
    from backend.fuzzing.engines.libfuzzer.stats import LibFuzzerStats
    from backend.fuzzing.toolchain.builder import ToolchainBuilder

    client = _docker_client()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fixture_root = Path(__file__).parent / "fixtures"
    nonce = os.getpid() * 10_000 + (monotonic_ns() % 10_000)
    system_campaign_id = nonce * 10 + 1
    component_campaign_id = nonce * 10 + 2
    service = FuzzContainerService(client, workspace, stop_timeout_seconds=5)
    started = []
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
        component_image = _fixture_image(
            client, tmp_path, "component_project", toolchain.tag(), toolchain_info.image_id,
        )

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
