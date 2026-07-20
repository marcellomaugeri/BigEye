"""Deterministic contracts for target preparation and supervised startup probes."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from hashlib import sha256
import threading
import time
from types import SimpleNamespace

import pytest

from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.campaign_review import CampaignReviewResult, TargetProposalRecord
from backend.agents.outputs.target_proposal import TargetProposal
from backend.fuzzing.campaigns.probe import (
    AttestedCoverage,
    CleanCoverageProvenance,
    ProbeEvidence,
    ProbeExecutionEvidence,
    ProbeInputEvidence,
    ProbeInvocation,
    ProbeEvidenceMismatch,
    ProbePolicy,
    ProbeProcessObservation,
    ProbeRunner,
    ProbeService,
)
from backend.fuzzing.campaigns.target_preparation import (
    AssetVersionRequest,
    DeterministicPreparationError,
    PreparationPlan,
    PreparedTarget,
    TargetRepair,
    TargetPreparationFailed,
    TargetPreparationService,
)
from backend.fuzzing.docker.container_runner import ContainerResult, ContainerTimedOut
from backend.fuzzing.docker.image_builder import ImageBuildCancelled, ImageBuildFailed, ImageCompilationFailed
from backend.fuzzing.layers.manifest import LayerManifest
from backend.fuzzing.sanitizer_environment import BASELINE_SANITIZER_ENVIRONMENT
from backend.services.campaigns.decision_executor import ActionError, ActionResult, DecisionExecutor


def run(awaitable):
    return asyncio.run(awaitable)


def proposal(target_name: str = "parser") -> TargetProposal:
    return TargetProposal(
        target_name=target_name,
        instance_type="component-level",
        byte_path="bytes -> parse_message",
        expected_project_reach="src/parser.cc:parse_message",
        build_command="cmake --build build --target parser_fuzz",
        run_command="/opt/bigeye/parser_fuzz",
        seeds=[{"path": "tests/data/message.bin", "provenance": "repository fixture"}],
        configuration="default",
        sanitizer_plan="address and undefined",
        generated_asset_intents=[{
            "relative_path": f"component/{target_name}/harness.cc", "purpose": "component harness",
        }],
        probe_assertions=["seed reaches parser project code"],
        evidence_ids=["source:parser"],
        uncertainty="target has not been probed",
    )


def project():
    return SimpleNamespace(id=7, commit_sha="a" * 40)


def input_evidence(
    name: str = "seed:message.bin",
    *,
    role: str = "seed",
    exit_code: int | None = 0,
    alive: bool = True,
    accepts_input: bool = True,
    deterministic: bool = True,
    project_lines: int = 8,
    harness_lines: int = 3,
    startup_lines: int = 1,
    immediate_crash: bool = False,
    timed_out: bool = False,
    sanitizer_output: str = "",
    invalid_api_use: bool = False,
    replayed_immediate_crash: bool = False,
) -> ProbeInputEvidence:
    project_set = frozenset(f"src/parser.cc:{index}" for index in range(1, project_lines + 1))
    harness_set = frozenset(f"harness.cc:{index}" for index in range(1, harness_lines + 1))
    startup_set = frozenset(f"src/main.cc:{index}" for index in range(1, startup_lines + 1))
    coverage = AttestedCoverage(
        project_set, harness_set, startup_set, not invalid_api_use,
        CleanCoverageProvenance(7, "a" * 40, "sha256:" + "c" * 64, "d" * 64),
    )

    def execution(crash):
        process = ProbeProcessObservation(exit_code, alive, timed_out, crash, sanitizer_output)
        return ProbeExecutionEvidence(process, coverage, accepts_input)

    return ProbeInputEvidence(
        name, role, execution(immediate_crash),
        execution(immediate_crash if replayed_immediate_crash or not immediate_crash else False),
        deterministic,
    )


def probe_evidence(*runs: ProbeInputEvidence) -> ProbeEvidence:
    values = runs or (input_evidence(),)
    return ProbeEvidence.from_inputs(values)


def healthy_evidence() -> ProbeEvidence:
    return probe_evidence(
        input_evidence("empty", role="empty", accepts_input=False, project_lines=0),
        input_evidence("minimum", role="minimum", project_lines=2),
        input_evidence(),
    )


def test_probe_rejects_target_that_only_reaches_harness_code() -> None:
    evidence = probe_evidence(input_evidence(project_lines=0, harness_lines=12))

    result = ProbePolicy.accept(evidence)

    assert result.accepted is False
    assert "project code" in result.reason


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"alive": False}, "healthy"),
        ({"accepts_input": False}, "real seed"),
        ({"deterministic": False}, "deterministic"),
        ({"timed_out": True, "exit_code": None}, "timed out"),
        ({"invalid_api_use": True}, "API contract"),
    ],
)
def test_probe_rejects_unhealthy_or_unreproducible_targets(change, reason) -> None:
    evidence = probe_evidence(input_evidence(**change))

    result = ProbePolicy.accept(evidence)

    assert result.accepted is False
    assert reason in result.reason


def test_probe_rejects_immediate_crashes_even_when_replayed() -> None:
    unreplayed = probe_evidence(input_evidence(immediate_crash=True))
    seed_independent = probe_evidence(
        input_evidence(
            "empty", role="empty", immediate_crash=True, replayed_immediate_crash=True,
            accepts_input=False, project_lines=0,
        ),
        input_evidence(immediate_crash=True, replayed_immediate_crash=True),
    )

    assert "immediate crash" in ProbePolicy.accept(unreplayed).reason
    assert "immediate crash" in ProbePolicy.accept(seed_independent).reason


def test_probe_requires_the_accepted_seed_itself_to_reach_project_code() -> None:
    evidence = probe_evidence(
        input_evidence("minimum", role="minimum", project_lines=9),
        input_evidence(project_lines=0, harness_lines=12),
    )

    result = ProbePolicy.accept(evidence)

    assert result.accepted is False
    assert "real seed" in result.reason and "project code" in result.reason


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"exit_code": 2}, "exit"),
        ({"sanitizer_output": "runtime error: invalid shift"}, "sanitizer"),
    ],
)
def test_probe_rejects_noncrash_exit_failures_and_sanitizer_reports(change, reason) -> None:
    result = ProbePolicy.accept(probe_evidence(input_evidence(**change)))

    assert result.accepted is False
    assert reason in result.reason


class _ProbeRunner:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    async def run(self, image, command, timeout, sink, **_options):
        self.calls.append((image, tuple(command), timeout, _options))
        value = self.outputs.pop(0)
        if isinstance(value, BaseException):
            raise value
        sink(value.output)
        return value


def _probe_output(**changes) -> ContainerResult:
    value = {
        "alive": True,
        "accepted_input": True,
        "project_lines": 5,
        "harness_lines": 2,
        "startup_lines": 1,
        "immediate_crash": False,
        "invalid_api_use": False,
        "sanitizer_output": "",
    }
    value.update(changes)
    import json

    return ContainerResult(0, "BIGEYE_PROBE_RESULT=" + json.dumps(value, sort_keys=True) + "\n")


def test_probe_runs_empty_minimum_and_real_seed_twice_and_records_exact_evidence() -> None:
    runner = _ProbeRunner([_probe_output() for _ in range(6)])
    target = SimpleNamespace(
        image="sha256:" + "b" * 64,
        probe_invocations=(
            ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty"), b""),
            ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum"), b"\x00"),
            ProbeInvocation(
                "seed:message.bin", "seed",
                ("/opt/bigeye/probe", "tests/data/message.bin"), b"seed-message",
            ),
        ),
    )

    target.project_id = 7
    target.commit_sha = "a" * 40
    target.coverage_image_id = "sha256:" + "c" * 64
    target.replay_environment = BASELINE_SANITIZER_ENVIRONMENT
    evidence = run(ProbeService(
        ProbeRunner(runner), _CleanCoverage(_attestations_for(target)), timeout_seconds=2.0,
    ).run(target))

    assert [call[1][-1] for call in runner.calls] == [
        "empty", "empty", "minimum", "minimum", "tests/data/message.bin", "tests/data/message.bin",
    ]
    assert evidence.exit_codes == (0, 0, 0, 0, 0, 0)
    assert evidence.alive and evidence.accepts_input and evidence.deterministic
    assert evidence.project_lines == frozenset({"src/parser.cc:12"})
    assert evidence.harness_lines == frozenset({"adapter.cc:4"})
    assert evidence.startup_lines == frozenset({"src/main.cc:8"})
    assert ProbePolicy.accept(evidence).accepted is True


def test_probe_runner_strips_internal_stdin_marker_and_feeds_exact_testcase_bytes() -> None:
    class BoundedRunner:
        async def run(
            self, image, command, timeout, sink, *, stdin_bytes=None, environment=None,
        ):
            self.call = (image, command, timeout, stdin_bytes)
            self.environment = environment
            return ContainerResult(0, "")

    bounded = BoundedRunner()
    invocation = ProbeInvocation(
        "seed", "seed", ("/opt/bigeye/stdin-parser", "--mode", "plain", "{stdin}"),
        b"\x00seed\xff",
    )

    result = run(ProbeRunner(bounded).run(
        "sha256:" + "b" * 64, invocation, 2.0, lambda _text: None,
        BASELINE_SANITIZER_ENVIRONMENT,
    ))

    assert result.exit_code == 0
    assert bounded.call == (
        "sha256:" + "b" * 64,
        ["/opt/bigeye/stdin-parser", "--mode", "plain"],
        2.0,
        b"\x00seed\xff",
    )


def test_probe_runner_resolves_a_middle_file_marker_to_the_exact_application_path() -> None:
    class BoundedRunner:
        async def run(
            self, image, command, timeout, sink, *, stdin_bytes=None, environment=None,
        ):
            self.call = (image, command, timeout, stdin_bytes)
            return ContainerResult(0, "")

    bounded = BoundedRunner()
    invocation = ProbeInvocation(
        "seed:tests/plain.txt", "seed",
        ("/opt/bigeye/parser", "--file", "{input}", "--mode", "plain"),
        b"exact-seed",
    )

    result = run(ProbeRunner(bounded).run(
        "sha256:" + "b" * 64, invocation, 2.0, lambda _text: None,
        BASELINE_SANITIZER_ENVIRONMENT,
    ))

    assert result.exit_code == 0
    assert bounded.call == (
        "sha256:" + "b" * 64,
        ["/opt/bigeye/parser", "--file", "/src/tests/plain.txt", "--mode", "plain"],
        2.0,
        None,
    )


@pytest.mark.parametrize("name", ["seed:", "seed:../plain.txt", "seed:/plain.txt", "seed:a\\b"])
def test_probe_runner_rejects_unsafe_file_marker_paths_before_execution(name) -> None:
    runner = _ProbeRunner([])
    invocation = ProbeInvocation(
        name, "seed", ("/opt/bigeye/parser", "{input}"), b"seed",
    )

    with pytest.raises(ValueError, match="input path"):
        run(ProbeRunner(runner).run(
            "sha256:" + "b" * 64, invocation, 2.0, lambda _text: None,
            BASELINE_SANITIZER_ENVIRONMENT,
        ))

    assert runner.calls == []


def test_probe_service_rejects_an_invalid_environment_before_execution() -> None:
    target = _probe_target()
    target.replay_environment = (("OPENAI_API_KEY", "must-not-reach-docker"),)
    runner = _ProbeRunner([])
    clean = _CleanCoverage([])

    with pytest.raises(ValueError, match="environment"):
        run(ProbeService(
            ProbeRunner(runner), clean, timeout_seconds=1.0,
        ).run(target))

    assert runner.calls == []
    assert clean.calls == []


@pytest.mark.parametrize(
    "command",
    [
        ("/opt/bigeye/parser", "{stdin}", "{stdin}"),
        ("/opt/bigeye/parser", "{input}", "{stdin}"),
    ],
)
def test_probe_invocation_rejects_multiple_or_mixed_internal_markers(command) -> None:
    with pytest.raises(ValueError, match="input marker"):
        ProbeInvocation("seed", "seed", command, b"seed")


@pytest.mark.parametrize(
    "command",
    [
        ("/opt/bigeye/parser", "--input={stdin}"),
        ("/opt/bigeye/parser", "--input={input}"),
        ("/opt/bigeye/parser", "{stdin}", "--plain"),
    ],
)
def test_probe_invocation_rejects_nonstandalone_or_nonfinal_stdin_marker(command) -> None:
    with pytest.raises(ValueError, match="input marker"):
        ProbeInvocation("seed", "seed", command, b"seed")


def test_probe_invocation_preserves_ordinary_file_mode_command() -> None:
    command = ("/opt/bigeye/parser", "--file", "/src/tests/seed.bin")

    invocation = ProbeInvocation("seed", "seed", command, b"seed")

    assert invocation.command == command


def test_system_stdin_planning_adds_one_internal_marker_and_file_mode_stays_canonical(
    tmp_path,
) -> None:
    from backend.fuzzing.campaigns.production_factory import _probe_invocations

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "seed.bin").write_bytes(b"exact-seed")
    context = SimpleNamespace(repository_root=repository)
    seed = proposal().seeds[0].model_copy(update={
        "path": "seed.bin", "provenance": "repository",
    })
    stdin_proposal = proposal().model_copy(update={
        "instance_type": "system-level",
        "run_command": "/opt/bigeye/parser --plain",
        "seeds": [seed],
    })
    file_proposal = stdin_proposal.model_copy(update={
        "run_command": "/opt/bigeye/parser --file @@ --mode plain",
    })

    stdin = _probe_invocations(context, stdin_proposal)
    file_mode = _probe_invocations(context, file_proposal)

    assert all(item.command[-1] == "{stdin}" for item in stdin)
    assert all(item.command.count("{stdin}") == 1 for item in stdin)
    assert all(item.command == (
        "/opt/bigeye/parser", "--file", "{input}", "--mode", "plain",
    ) for item in file_mode)
    assert all(item.command.count("{input}") == 1 for item in file_mode)
    assert all("{stdin}" not in item.command for item in file_mode)


def test_clean_probe_coverage_replays_same_stdin_bytes_without_an_argv_path(
    tmp_path, monkeypatch,
) -> None:
    from backend.fuzzing.campaigns.production_factory import PreparedCleanCoverageCollector
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    repository = tmp_path / "projects/7/repository"
    repository.mkdir(parents=True)
    captured = {}

    def replay(_self, campaign, inputs):
        captured["command"] = campaign.replay_command
        captured["environment"] = campaign.replay_environment
        captured["bytes"] = inputs[0].read_bytes()
        return SimpleNamespace(lines=())

    monkeypatch.setattr(LlvmCoverage, "replay", replay)
    prepared = SimpleNamespace(
        project_id=7,
        commit_sha="a" * 40,
        replay_environment=(("BIGEYE_MODE", "encrypted"),),
        coverage_image_id="sha256:" + "c" * 64,
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        coverage_manifest=SimpleNamespace(
            tag="bigeye-coverage:test",
            content_hash="d" * 64,
            labels={
                "bigeye.configuration-asset-id": "32",
                "bigeye.coverage-asset-id": "34",
                "bigeye.parent-image": "sha256:" + "e" * 64,
            },
        ),
    )
    invocation = ProbeInvocation(
        "seed", "seed", ("/opt/bigeye/stdin-parser", "--plain", "{stdin}"),
        b"\x00exact-clean\xff",
    )
    collector = PreparedCleanCoverageCollector(
        SimpleNamespace(), tmp_path,
        SimpleNamespace(context=lambda _project_id: SimpleNamespace(repository_root=repository)),
    )

    evidence = run(collector.collect(prepared, invocation, SimpleNamespace()))

    assert captured == {
        "command": ("/opt/bigeye/stdin-parser", "--plain", "{stdin}"),
        "environment": (("BIGEYE_MODE", "encrypted"),),
        "bytes": b"\x00exact-clean\xff",
    }
    assert evidence.provenance.testcase_sha256 == invocation.testcase_sha256


def test_clean_probe_coverage_canonicalises_an_exact_middle_file_path(
    tmp_path, monkeypatch,
) -> None:
    from backend.fuzzing.campaigns.production_factory import PreparedCleanCoverageCollector
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    repository = tmp_path / "projects/7/repository"
    repository.mkdir(parents=True)
    captured = {}

    def replay(_self, campaign, inputs):
        captured["command"] = campaign.replay_command
        captured["bytes"] = inputs[0].read_bytes()
        return SimpleNamespace(lines=())

    monkeypatch.setattr(LlvmCoverage, "replay", replay)
    prepared = SimpleNamespace(
        project_id=7,
        commit_sha="a" * 40,
        replay_environment=BASELINE_SANITIZER_ENVIRONMENT,
        coverage_image_id="sha256:" + "c" * 64,
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        coverage_manifest=SimpleNamespace(
            tag="bigeye-coverage:test",
            content_hash="d" * 64,
            labels={
                "bigeye.configuration-asset-id": "32",
                "bigeye.coverage-asset-id": "34",
                "bigeye.parent-image": "sha256:" + "e" * 64,
            },
        ),
    )
    invocation = ProbeInvocation(
        "seed:tests/plain.txt", "seed",
        ("/opt/bigeye/parser", "--file", "/src/tests/plain.txt", "--mode", "plain"),
        b"exact-clean",
    )
    collector = PreparedCleanCoverageCollector(
        SimpleNamespace(), tmp_path,
        SimpleNamespace(context=lambda _project_id: SimpleNamespace(repository_root=repository)),
    )

    evidence = run(collector.collect(prepared, invocation, SimpleNamespace()))

    assert captured == {
        "command": ("/opt/bigeye/parser", "--file", "{input}", "--mode", "plain"),
        "bytes": b"exact-clean",
    }
    assert evidence.provenance.testcase_sha256 == invocation.testcase_sha256


def test_probe_timeout_is_retained_as_evidence_instead_of_retried_as_transport() -> None:
    runner = _ProbeRunner([
        _probe_output(), _probe_output(), _probe_output(), _probe_output(),
        ContainerTimedOut("bounded probe timed out"), ContainerTimedOut("bounded probe timed out"),
    ])
    target = SimpleNamespace(
        image="sha256:" + "b" * 64,
        probe_invocations=(
            ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty"), b""),
            ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum"), b"\x00"),
            ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed"), b"seed"),
        ),
    )

    target.project_id = 7
    target.commit_sha = "a" * 40
    target.coverage_image_id = "sha256:" + "c" * 64
    target.replay_environment = BASELINE_SANITIZER_ENVIRONMENT
    evidence = run(ProbeService(
        ProbeRunner(runner), _CleanCoverage(_attestations_for(target)), timeout_seconds=1.0,
    ).run(target))

    assert evidence.timed_out is True
    assert evidence.exit_codes == (0, 0, 0, 0, None, None)
    assert "timed out" in ProbePolicy.accept(evidence).reason


def test_probe_preserves_sanitizer_report_emitted_outside_the_result_record() -> None:
    seed = _probe_output()
    seed = ContainerResult(seed.exit_code, "runtime error: invalid shift\n" + seed.output)
    runner = _ProbeRunner([_probe_output() for _ in range(4)] + [seed, seed])
    target = SimpleNamespace(
        image="sha256:" + "b" * 64,
        probe_invocations=(
            ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty"), b""),
            ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum"), b"\x00"),
            ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed"), b"seed"),
        ),
    )

    target.project_id = 7
    target.commit_sha = "a" * 40
    target.coverage_image_id = "sha256:" + "c" * 64
    target.replay_environment = BASELINE_SANITIZER_ENVIRONMENT
    evidence = run(ProbeService(
        ProbeRunner(runner), _CleanCoverage(_attestations_for(target)), timeout_seconds=1.0,
    ).run(target))

    assert "runtime error" in evidence.sanitizer_output
    assert ProbePolicy.accept(evidence).accepted is False


def _manifest(kind: str, tag: str) -> LayerManifest:
    return LayerManifest(
        kind=kind,
        tag=tag,
        content_hash=kind + "-hash",
        parent_tag="parent:tag",
        dockerfile=SimpleNamespace(),
        context_dir=SimpleNamespace(),
        labels={"bigeye.layer": kind},
    )


class _ImageInspector:
    def __init__(self):
        self.tags = []

    def inspect(self, tag):
        self.tags.append(tag)
        suffix = "b" if "target" in tag else "c"
        return SimpleNamespace(image_id="sha256:" + suffix * 64, os="linux", architecture="amd64")


class _NormalBuild:
    def __init__(self):
        self.calls = 0

    async def validate(self, selected_project, selected_proposal):
        self.calls += 1
        return _manifest("project", "bigeye-project:ready")


class _Planner:
    def plan(self, selected_project, selected_proposal):
        name = selected_proposal.target_name
        requests = (
            AssetVersionRequest(
                "target", "harness", "harness.cc", {"harness.cc": f"draft:{name}"},
                (f"component/{name}/harness.cc",),
            ),
        )
        return PreparationPlan(
            asset_versions=requests,
            existing_assets={
                "configuration": _existing_asset(101, "script", "build.sh"),
                "coverage_adapter": _existing_asset(102, "adapter", "adapter.cc"),
                "coverage_configuration": _existing_asset(103, "script", "coverage.sh"),
            },
            probe_invocations=(
                ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty"), b""),
                ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum"), b"\x00"),
                ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed"), b"seed"),
            ),
        )


def _existing_asset(asset_id: int, kind: str, name: str):
    return SimpleNamespace(
        id=asset_id,
        project_id=7,
        kind=kind,
        name=name,
        content_hash=f"hash-{asset_id}",
        validated_at=object(),
        error=None,
    )


class _AssetStore:
    def __init__(self):
        self.created = []
        self.active = 0
        self.max_active = 0

    async def create(self, project_id, kind, name, files, parent_id):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0.01)
        asset = SimpleNamespace(
            id=len(self.created) + 1,
            project_id=project_id,
            kind=kind,
            name=name,
            files=files,
            parent_id=parent_id,
            content_hash=f"hash-{len(self.created) + 1}",
            validated_at=object(),
            error=None,
        )
        self.created.append(asset)
        self.active -= 1
        return asset


class _TargetLayers:
    def __init__(self):
        self.calls = []
        self.fail = False

    def prepare(
        self, selected_project, project_manifest, target, configuration, sink,
        fuzz_patch_asset=None, cancellation_signal=None,
    ):
        self.calls.append((selected_project.id, target.id, configuration.id, fuzz_patch_asset))
        if self.fail:
            raise DeterministicPreparationError("target compilation failed")
        return _manifest("target", f"bigeye-target:{target.id}")


class _CoverageLayers:
    def __init__(self):
        self.calls = []

    def prepare(
        self, selected_project, project_manifest, adapter, configuration, sink,
        *, target_asset_id, configuration_asset_id, coverage_asset_id,
        cancellation_signal=None,
    ):
        self.calls.append((
            selected_project.id, adapter.id, configuration.id,
            target_asset_id, configuration_asset_id, coverage_asset_id,
        ))
        return _manifest("coverage", f"bigeye-coverage:{adapter.id}")


class _Probe:
    def __init__(self, evidence=None):
        self.evidence = evidence or healthy_evidence()
        self.calls = []

    async def run(self, prepared):
        self.calls.append(prepared)
        return self.evidence


class _Repairer:
    def __init__(self):
        self.calls = []

    async def repair(self, selected_project, selected_proposal, failure, model):
        self.calls.append((selected_proposal.target_name, str(failure), model))
        return TargetRepair(
            selected_proposal.model_copy(update={"uncertainty": "repaired target requires a fresh probe"}),
            "gpt-5.6-terra",
        )


def preparation(**changes):
    values = {
        "normal_build": _NormalBuild(),
        "planner": _Planner(),
        "asset_store": _AssetStore(),
        "target_layers": _TargetLayers(),
        "coverage_layers": _CoverageLayers(),
        "image_inspector": _ImageInspector(),
        "probe": _Probe(),
        "repairer": None,
    }
    values.update(changes)
    return TargetPreparationService(**values)


def test_preparation_validates_normal_build_publishes_only_plan_assets_and_builds_dependent_layers() -> None:
    normal = _NormalBuild()
    assets = _AssetStore()
    target_layers = _TargetLayers()
    coverage_layers = _CoverageLayers()
    service = preparation(
        normal_build=normal, asset_store=assets, target_layers=target_layers, coverage_layers=coverage_layers,
    )

    prepared = run(service.prepare(project(), proposal()))

    assert normal.calls == 1
    assert [asset.kind for asset in assets.created] == ["harness"]
    assert len(target_layers.calls) == len(coverage_layers.calls) == 1
    assert prepared.target_manifest.tag.startswith("bigeye-target:")
    assert prepared.coverage_manifest.tag.startswith("bigeye-coverage:")
    assert prepared.image == "sha256:" + "b" * 64
    assert prepared.coverage_image_id == "sha256:" + "c" * 64
    assert prepared.replay_environment == (
        ("ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0"),
        ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
    )
    assert prepared.agent_attempts == ("gpt-5.6-luna",)
    assert prepared.probe.accepted is True


def test_exact_probed_environment_is_published_with_the_accepted_target(
    tmp_path, monkeypatch,
) -> None:
    from backend.fuzzing.campaigns import target_preparation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    replay_environment = (("BIGEYE_MODE", "encrypted"),)
    monkeypatch.setattr(
        target_preparation, "BASELINE_SANITIZER_ENVIRONMENT", replay_environment,
    )

    class ReplayPlanner(_Planner):
        def plan(self, selected_project, selected_proposal):
            plan = super().plan(selected_project, selected_proposal)
            return replace(plan, probe_invocations=(
                ProbeInvocation(
                    "empty", "empty", ("/opt/bigeye/probe", "{input}"), b"",
                ),
                ProbeInvocation(
                    "minimum", "minimum", ("/opt/bigeye/probe", "{input}"), b"\x00",
                ),
                ProbeInvocation(
                    "seed:test.seed", "seed", ("/opt/bigeye/probe", "{input}"), b"seed",
                ),
            ))

    class CleanCoverage:
        def __init__(self):
            self.environments = []
            self.observations = None

        async def collect(self, built, _invocation, _process):
            self.environments.append(built.replay_environment)
            return self.observations.pop(0)

    class ExactProbe:
        def __init__(self):
            self.target_environments = []
            self.clean_coverage = CleanCoverage()

        async def run(self, built):
            bounded = _ProbeRunner([ContainerResult(0, "healthy\n") for _ in range(6)])
            self.clean_coverage.observations = _attestations_for(built)
            evidence = await ProbeService(
                ProbeRunner(bounded), self.clean_coverage, timeout_seconds=1.0,
            ).run(built)
            self.target_environments = [
                call[3]["environment"] for call in bounded.calls
            ]
            return evidence

    probe = ExactProbe()
    prepared = run(preparation(planner=ReplayPlanner(), probe=probe).prepare(
        project(), proposal(),
    ))

    assert probe.target_environments == [dict(replay_environment)] * 6
    assert probe.clean_coverage.environments == [replay_environment] * 6
    assert prepared.replay_environment == replay_environment

    prepared = replace(
        prepared,
        target_manifest=replace(
            prepared.target_manifest,
            labels={"bigeye.target-asset": "1"},
        ),
        coverage_manifest=replace(
            prepared.coverage_manifest,
            content_hash="d" * 64,
            labels={
                "bigeye.parent-image": "sha256:" + "e" * 64,
                "bigeye.configuration-asset-id": "101",
                "bigeye.coverage-asset-id": "102",
            },
        ),
    )
    store = CampaignInvocationStore(tmp_path)
    run(store.publish_coverage(7, 9, project().commit_sha, prepared))

    assert store.load_coverage(7, 9).replay_environment == replay_environment


def test_preparation_rejects_asset_versions_not_declared_by_the_proposal() -> None:
    class ExtraAssetPlanner(_Planner):
        def plan(self, selected_project, selected_proposal):
            plan = super().plan(selected_project, selected_proposal)
            request = replace(plan.asset_versions[0], proposal_paths=("component/other/extra.cc",))
            return replace(plan, asset_versions=(request,))

    assets = _AssetStore()
    service = preparation(asset_store=assets, planner=ExtraAssetPlanner())

    with pytest.raises(TargetPreparationFailed, match="proposed"):
        run(service.prepare(project(), proposal()))

    assert assets.created == []


def test_preparation_plan_requires_empty_minimum_and_real_seed_probes() -> None:
    with pytest.raises(ValueError, match="empty, minimum, and real seed"):
        PreparationPlan(
            asset_versions=(),
            existing_assets={
                "target": _existing_asset(100, "harness", "harness.cc"),
                "configuration": _existing_asset(101, "script", "build.sh"),
                "coverage_adapter": _existing_asset(102, "adapter", "adapter.cc"),
                "coverage_configuration": _existing_asset(103, "script", "coverage.sh"),
            },
            probe_invocations=(
                ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed"), b"seed"),
            ),
        )


def test_failed_luna_asset_gets_only_one_terra_repair() -> None:
    invalid = _Probe(probe_evidence(input_evidence(project_lines=0)))
    valid = _Probe(healthy_evidence())

    class ProbeSequence:
        def __init__(self):
            self.calls = 0

        async def run(self, prepared):
            self.calls += 1
            return invalid.evidence if self.calls == 1 else valid.evidence

    repairer = _Repairer()
    service = preparation(probe=ProbeSequence(), repairer=repairer)

    prepared = run(service.prepare(project(), proposal()))

    assert prepared.agent_attempts == ("gpt-5.6-luna", "gpt-5.6-terra")
    assert [call[2] for call in repairer.calls] == ["gpt-5.6-terra"]


def test_second_deterministic_failure_retains_last_validated_target() -> None:
    service = preparation()
    first = run(service.prepare(project(), proposal()))
    failing_probe = _Probe(probe_evidence(input_evidence(project_lines=0)))
    service._probe = failing_probe
    service._repairer = _Repairer()

    with pytest.raises(TargetPreparationFailed) as captured:
        run(service.prepare(project(), proposal()))

    assert captured.value.agent_attempts == ("gpt-5.6-luna", "gpt-5.6-terra")
    assert captured.value.retained_target.target_manifest.tag == first.target_manifest.tag


@pytest.mark.parametrize("change", [
    {"byte_path": "bytes -> repaired_parse_message"},
    {"build_command": "cmake --build build --target parser_fuzz_repaired"},
    {"run_command": "/opt/bigeye/parser_fuzz_repaired"},
])
def test_mutable_repair_fields_retain_the_last_accepted_target(change) -> None:
    service = preparation()
    accepted = run(service.prepare(project(), proposal()))
    service._probe = _Probe(probe_evidence(input_evidence(project_lines=0)))
    changed = proposal().model_copy(update=change)

    with pytest.raises(TargetPreparationFailed) as captured:
        run(service.prepare(project(), changed))

    assert captured.value.retained_target is accepted


def test_repair_identity_digest_uses_only_project_type_name_and_configuration() -> None:
    base = proposal()
    mutable_change = base.model_copy(update={
        "byte_path": "bytes -> another function",
        "build_command": "ninja -C another-build parser_fuzz",
        "run_command": "/opt/bigeye/another-parser-fuzz",
    })
    different_configuration = base.model_copy(update={"configuration": "feature-enabled"})

    assert TargetPreparationService._target_identity_digest(7, base) == (
        TargetPreparationService._target_identity_digest(7, mutable_change)
    )
    assert TargetPreparationService._target_identity_digest(7, base) != (
        TargetPreparationService._target_identity_digest(8, base)
    )
    assert TargetPreparationService._target_identity_digest(7, base) != (
        TargetPreparationService._target_identity_digest(7, different_configuration)
    )


def test_crashing_probe_is_not_repaired_and_returns_both_executions_for_triage() -> None:
    crash = probe_evidence(input_evidence(immediate_crash=True, replayed_immediate_crash=True))
    repairer = _Repairer()
    service = preparation(probe=_Probe(crash), repairer=repairer)

    with pytest.raises(TargetPreparationFailed) as captured:
        run(service.prepare(project(), proposal()))

    assert repairer.calls == []
    assert captured.value.probe_evidence is crash
    assert len(captured.value.probe_evidence.inputs[0].executions) == 2


def test_transport_failure_is_not_sent_to_terra() -> None:
    class TransportFailureProbe:
        async def run(self, prepared):
            raise ConnectionError("Docker daemon disconnected")

    repairer = _Repairer()
    service = preparation(probe=TransportFailureProbe(), repairer=repairer)

    with pytest.raises(ConnectionError, match="Docker daemon"):
        run(service.prepare(project(), proposal()))

    assert repairer.calls == []


def test_only_typed_compilation_failure_gets_one_terra_repair() -> None:
    class CompilationThenSuccess(_TargetLayers):
        def prepare(self, *arguments, cancellation_signal=None):
            self.calls.append(arguments)
            if len(self.calls) == 1:
                raise ImageCompilationFailed("compiler returned an error")
            return _manifest("target", "bigeye-target:repaired")

    repairer = _Repairer()
    prepared = run(preparation(target_layers=CompilationThenSuccess(), repairer=repairer).prepare(project(), proposal()))

    assert prepared.agent_attempts == ("gpt-5.6-luna", "gpt-5.6-terra")
    assert len(repairer.calls) == 1


def test_concurrent_initial_and_terra_repair_share_one_identity_lock() -> None:
    class Activity:
        def __init__(self):
            self.active = 0
            self.max_active = 0
            self.guard = threading.Lock()

        def enter(self):
            with self.guard:
                self.active += 1
                self.max_active = max(self.max_active, self.active)

        def leave(self):
            with self.guard:
                self.active -= 1

    activity = Activity()

    class FirstCompilationFails(_TargetLayers):
        def __init__(self):
            super().__init__()
            self.count = 0
            self.guard = threading.Lock()

        def prepare(self, *arguments, cancellation_signal=None):
            activity.enter()
            try:
                time.sleep(0.02)
                with self.guard:
                    self.count += 1
                    call = self.count
            finally:
                activity.leave()
            if call == 1:
                raise ImageCompilationFailed("generated target did not compile")
            return _manifest("target", f"bigeye-target:{call}")

    class SlowRepair:
        async def repair(self, selected_project, selected_proposal, failure, model):
            activity.enter()
            try:
                await asyncio.sleep(0.04)
            finally:
                activity.leave()
            return TargetRepair(
                selected_proposal.model_copy(update={"uncertainty": "repaired"}),
                "gpt-5.6-terra",
            )

    service = preparation(target_layers=FirstCompilationFails(), repairer=SlowRepair())

    async def scenario():
        return await asyncio.gather(
            service.prepare(project(), proposal()),
            service.prepare(project(), proposal()),
        )

    first, second = run(scenario())

    assert activity.max_active == 1
    assert first.agent_attempts == ("gpt-5.6-luna", "gpt-5.6-terra")
    assert second.agent_attempts == ("gpt-5.6-luna",)


def test_daemon_build_failure_is_fatal_and_never_sent_to_repair() -> None:
    class DaemonFailure(_TargetLayers):
        def prepare(self, *arguments, cancellation_signal=None):
            raise ImageBuildFailed("Docker build stream disconnected") from ConnectionError("daemon unavailable")

    repairer = _Repairer()
    with pytest.raises(ImageBuildFailed, match="disconnected"):
        run(preparation(target_layers=DaemonFailure(), repairer=repairer).prepare(project(), proposal()))

    assert repairer.calls == []


def test_repair_result_must_be_typed_and_exactly_terra() -> None:
    class LunaRepair:
        async def repair(self, selected_project, selected_proposal, failure, model):
            return TargetRepair(selected_proposal, "gpt-5.6-luna")

    service = preparation(
        probe=_Probe(probe_evidence(input_evidence(project_lines=0))), repairer=LunaRepair(),
    )

    with pytest.raises(TargetPreparationFailed, match="Terra") as captured:
        run(service.prepare(project(), proposal()))

    assert captured.value.agent_attempts == ("gpt-5.6-luna", "gpt-5.6-luna")


def test_repair_cannot_silently_change_target_identity() -> None:
    class IdentityChangingRepairer:
        async def repair(self, selected_project, selected_proposal, failure, model):
            return TargetRepair(proposal("different-target"), "gpt-5.6-terra")

    service = preparation(
        probe=_Probe(probe_evidence(input_evidence(project_lines=0))),
        repairer=IdentityChangingRepairer(),
    )

    with pytest.raises(TargetPreparationFailed, match="identity") as captured:
        run(service.prepare(project(), proposal()))

    assert captured.value.agent_attempts == ("gpt-5.6-luna", "gpt-5.6-terra")


class _ExistingAssetPlanner:
    def __init__(self):
        self.assets = {
            "target": _existing_asset(100, "harness", "harness.cc"),
            "configuration": _existing_asset(101, "script", "build.sh"),
            "coverage_adapter": _existing_asset(102, "adapter", "adapter.cc"),
            "coverage_configuration": _existing_asset(103, "script", "coverage.sh"),
        }

    def plan(self, selected_project, selected_proposal):
        return PreparationPlan(
            asset_versions=(),
            existing_assets=self.assets,
            probe_invocations=(
                ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty"), b""),
                ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum"), b"\x00"),
                ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed"), b"seed"),
            ),
        )


class _ConcurrentTargetLayers(_TargetLayers):
    def __init__(self):
        super().__init__()
        self.active = 0
        self.max_active = 0
        self._guard = threading.Lock()

    def prepare(self, *arguments, cancellation_signal=None):
        with self._guard:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(0.03)
        with self._guard:
            self.active -= 1
        return _manifest("target", "bigeye-target:existing")


def _existing_proposal(target_name="parser", instance_type="component-level"):
    return proposal(target_name).model_copy(update={
        "instance_type": instance_type,
        "generated_asset_intents": [],
    })


def test_identical_proposals_serialize_before_publishing_distinct_asset_versions() -> None:
    assets = _AssetStore()
    target_layers = _ConcurrentTargetLayers()
    service = preparation(asset_store=assets, target_layers=target_layers)

    async def same_target():
        await asyncio.gather(
            service.prepare(project(), proposal()),
            service.prepare(project(), proposal()),
        )

    run(same_target())

    assert len({asset.id for asset in assets.created}) == 2
    assert assets.max_active == 1
    assert target_layers.max_active == 1


def test_distinct_target_configurations_with_distinct_assets_prepare_in_parallel() -> None:
    class DistinctAssetPlanner(_ExistingAssetPlanner):
        def plan(self, selected_project, selected_proposal):
            offset = 100 if selected_proposal.configuration == "first-config" else 200
            self.assets = {
                "target": _existing_asset(offset, "harness", "harness.cc"),
                "configuration": _existing_asset(offset + 1, "script", "build.sh"),
                "coverage_adapter": _existing_asset(offset + 2, "adapter", "adapter.cc"),
                "coverage_configuration": _existing_asset(offset + 3, "script", "coverage.sh"),
            }
            return super().plan(selected_project, selected_proposal)

    target_layers = _ConcurrentTargetLayers()
    service = preparation(planner=DistinctAssetPlanner(), target_layers=target_layers)

    async def distinct_target_identity():
        await asyncio.gather(
            service.prepare(
                project(), _existing_proposal().model_copy(update={"configuration": "first-config"}),
            ),
            service.prepare(
                project(), _existing_proposal().model_copy(update={"configuration": "second-config"}),
            ),
        )

    run(distinct_target_identity())
    assert target_layers.max_active > 1


def test_cancelled_build_is_stopped_and_joined_before_releasing_its_target_lock() -> None:
    class CancellableTargetLayers(_TargetLayers):
        def __init__(self):
            super().__init__()
            self.started = threading.Event()
            self.cleaned = threading.Event()
            self.second_saw_cleanup = False
            self.call_count = 0
            self._guard = threading.Lock()

        def prepare(self, *arguments, cancellation_signal=None):
            with self._guard:
                self.call_count += 1
                call = self.call_count
            assert cancellation_signal is not None
            if call == 1:
                self.started.set()
                while not cancellation_signal.wait(0.005):
                    pass
                self.cleaned.set()
                raise ImageBuildCancelled("cancelled test build")
            self.second_saw_cleanup = self.cleaned.is_set()
            return _manifest("target", "bigeye-target:after-cancel")

    async def scenario():
        layers = CancellableTargetLayers()
        service = preparation(planner=_ExistingAssetPlanner(), target_layers=layers)
        selected = _existing_proposal()
        first = asyncio.create_task(service.prepare(project(), selected))
        assert await asyncio.to_thread(layers.started.wait, 1.0)
        second = asyncio.create_task(service.prepare(project(), selected))
        await asyncio.sleep(0.01)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        prepared = await asyncio.wait_for(second, 1.0)
        return layers, prepared

    layers, prepared = run(scenario())

    assert layers.cleaned.is_set()
    assert layers.second_saw_cleanup is True
    assert prepared.target_manifest.tag == "bigeye-target:after-cancel"


def test_retained_target_identity_includes_instance_type() -> None:
    service = preparation()
    run(service.prepare(project(), proposal()))
    service._probe = _Probe(probe_evidence(input_evidence(project_lines=0)))

    system_proposal = proposal().model_copy(update={"instance_type": "system-level"})
    with pytest.raises(TargetPreparationFailed) as captured:
        run(service.prepare(project(), system_proposal))

    assert captured.value.retained_target is None


def _record(result_id: str = "target_known") -> TargetProposalRecord:
    return TargetProposalRecord(
        result_id=result_id,
        specialist="prepare_component_target",
        tool_call_id="call-1",
        attempt=1,
        model="gpt-5.6-luna",
        proposal=proposal(),
    )


def _review(*, selected=("target_known",), decision_actions=("target_known",)) -> CampaignReviewResult:
    record = _record()
    return CampaignReviewResult(
        decision=CampaignDecision(
            decision="prepare parser",
            motivation="the parser has repository evidence",
            evidence_ids=["source:parser"],
            bounded_actions=list(decision_actions),
            next_review_delay_seconds=900,
            next_review_reason="Recheck after the probe",
            uncertainty="runtime behavior is not known yet",
        ),
        known_action_ids=(record.result_id,),
        selected_action_ids=selected,
        known_target_proposals=(record,),
        selected_target_proposals=(record,) if record.result_id in selected else (),
        known_triage_results=(),
        selected_triage_results=(),
        known_operation_requests=(),
        selected_operation_requests=(),
        quarantined_operation_requests=(),
    )


def test_decision_executor_accepts_only_manager_selected_known_ids_and_returns_typed_results() -> None:
    prepared = SimpleNamespace(target_name="parser")

    class Preparation:
        async def prepare(self, selected_project, selected_proposal):
            assert selected_proposal.proposal.target_name == "parser"
            return prepared

    results = run(DecisionExecutor(Preparation()).execute(project(), _review()))

    assert results == [ActionResult("target_known", prepared)]


def test_decision_executor_waits_for_siblings_and_returns_typed_failures() -> None:
    failed = _record("target_failed").model_copy(update={"proposal": proposal("failed")})
    succeeded = _record("target_succeeded").model_copy(update={"proposal": proposal("succeeded")})
    review = CampaignReviewResult(
        decision=CampaignDecision(
            decision="prepare independent targets",
            motivation="both targets have repository evidence",
            evidence_ids=["source:parser"],
            bounded_actions=[failed.result_id, succeeded.result_id],
            next_review_delay_seconds=900,
            next_review_reason="Recheck after both preparations settle",
            uncertainty="runtime behavior is not known yet",
        ),
        known_action_ids=(failed.result_id, succeeded.result_id),
        selected_action_ids=(failed.result_id, succeeded.result_id),
        known_target_proposals=(failed, succeeded),
        selected_target_proposals=(failed, succeeded),
        known_triage_results=(),
        selected_triage_results=(),
        known_operation_requests=(),
        selected_operation_requests=(),
        quarantined_operation_requests=(),
    )

    class Preparation:
        def __init__(self):
            self.succeeded = False

        async def prepare(self, selected_project, record):
            if record.result_id == "target_failed":
                await asyncio.sleep(0.01)
                raise DeterministicPreparationError("target did not compile")
            await asyncio.sleep(0.03)
            self.succeeded = True
            return SimpleNamespace(target_name="succeeded")

    preparation_service = Preparation()
    results = run(DecisionExecutor(preparation_service).execute(project(), review))

    assert preparation_service.succeeded is True
    assert results[0] == ActionResult(
        "target_failed", None,
        ActionError("DeterministicPreparationError", "target did not compile"),
    )
    assert results[1].succeeded is True
    assert results[1].output.target_name == "succeeded"


@pytest.mark.parametrize(
    "review",
    [
        _review(selected=("unknown",), decision_actions=("unknown",)),
        _review(selected=(), decision_actions=("target_known",)),
    ],
)
def test_decision_executor_rejects_unknown_or_unvalidated_action_selection(review) -> None:
    with pytest.raises(ValueError, match="manager-validated"):
        run(DecisionExecutor(SimpleNamespace()).execute(project(), review))


def test_decision_executor_rejects_selected_record_that_differs_from_known_record() -> None:
    review = _review()
    replacement = _record().model_copy(update={"proposal": proposal("different")})
    changed = review.model_copy(update={"selected_target_proposals": (replacement,)})

    with pytest.raises(ValueError, match="manager-validated"):
        run(DecisionExecutor(SimpleNamespace()).execute(project(), changed))


def test_decision_executor_rejects_duplicate_known_action_ids() -> None:
    review = _review().model_copy(update={"known_action_ids": ("target_known", "target_known")})

    with pytest.raises(ValueError, match="manager-validated"):
        run(DecisionExecutor(SimpleNamespace()).execute(project(), review))


class _CleanCoverage:
    def __init__(self, observations):
        self.observations = list(observations)
        self.calls = []

    async def collect(self, prepared, invocation, process):
        self.calls.append((prepared.coverage_image_id, invocation.name, process.exit_code))
        return self.observations.pop(0)


def _attested(project_lines=frozenset({"src/parser.cc:12"}), *, input_digest="d" * 64):
    return AttestedCoverage(
        project_lines=project_lines,
        harness_lines=frozenset({"adapter.cc:4"}),
        startup_lines=frozenset({"src/main.cc:8"}),
        contract_valid=True,
        provenance=CleanCoverageProvenance(
            project_id=7,
            commit_sha="a" * 40,
            clean_image_id="sha256:" + "c" * 64,
            testcase_sha256=input_digest,
        ),
    )


def _probe_target():
    return SimpleNamespace(
        project_id=7,
        commit_sha="a" * 40,
        image="sha256:" + "b" * 64,
        coverage_image_id="sha256:" + "c" * 64,
        replay_environment=BASELINE_SANITIZER_ENVIRONMENT,
        probe_invocations=(
            ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty"), b""),
            ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum"), b"\x00"),
            ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed"), b"seed"),
        ),
    )


def _attestations_for(target, project_lines=frozenset({"src/parser.cc:12"})):
    return [
        _attested(project_lines, input_digest=invocation.testcase_sha256)
        for invocation in target.probe_invocations
        for _execution in range(2)
    ]


def test_probe_invocation_derives_exact_empty_minimum_and_seed_digests() -> None:
    invocations = _probe_target().probe_invocations

    assert [item.testcase_sha256 for item in invocations] == [
        sha256(b"").hexdigest(),
        sha256(b"\x00").hexdigest(),
        sha256(b"seed").hexdigest(),
    ]


@pytest.mark.parametrize("invocation_index", [0, 1, 2])
def test_probe_rejects_swapped_or_stale_testcase_attestation(invocation_index: int) -> None:
    target = _probe_target()
    coverage = _attestations_for(target)
    wrong_invocation = target.probe_invocations[(invocation_index + 1) % 3]
    coverage[invocation_index * 2 + 1] = _attested(
        input_digest=wrong_invocation.testcase_sha256,
    )
    runner = _ProbeRunner([ContainerResult(0, "healthy\n") for _ in range(6)])

    with pytest.raises(ProbeEvidenceMismatch, match="exact testcase"):
        run(ProbeService(
            ProbeRunner(runner), _CleanCoverage(coverage), timeout_seconds=1.0,
        ).run(target))


def test_forged_target_probe_json_cannot_replace_clean_coverage_attestation() -> None:
    forged = ContainerResult(
        0,
        'BIGEYE_PROBE_RESULT={"alive":true,"accepted_input":true,"project_lines":999,'
        '"harness_lines":0,"startup_lines":0,"immediate_crash":false,'
        '"invalid_api_use":false,"sanitizer_output":""}\n',
    )
    runner = ProbeRunner(_ProbeRunner([forged for _ in range(6)]))
    target = _probe_target()
    coverage = _CleanCoverage(_attestations_for(target, frozenset()))

    evidence = run(ProbeService(runner, coverage, timeout_seconds=1.0).run(target))

    assert evidence.project_lines == frozenset()
    assert "project code" in ProbePolicy.accept(evidence).reason


def test_replay_only_crash_is_preserved_and_rejects_target() -> None:
    healthy = ContainerResult(0, "target output\n")
    replay_crash = ContainerResult(139, "ERROR: AddressSanitizer: heap-buffer-overflow\n")
    bounded = _ProbeRunner([healthy, healthy, healthy, healthy, healthy, replay_crash])
    target = _probe_target()
    coverage = _CleanCoverage(_attestations_for(target))

    evidence = run(ProbeService(ProbeRunner(bounded), coverage, timeout_seconds=1.0).run(target))

    seed = next(item for item in evidence.inputs if item.role == "seed")
    assert seed.first.immediate_crash is False
    assert seed.replay.immediate_crash is True
    assert "AddressSanitizer" in seed.replay.sanitizer_output
    assert ProbePolicy.accept(evidence).accepted is False
