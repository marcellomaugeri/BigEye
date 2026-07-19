"""Deterministic contracts for target preparation and supervised startup probes."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.campaign_review import CampaignReviewResult, TargetProposalRecord
from backend.agents.outputs.target_proposal import TargetProposal
from backend.fuzzing.campaigns.probe import (
    ProbeEvidence,
    ProbeInputEvidence,
    ProbeInvocation,
    ProbePolicy,
    ProbeService,
)
from backend.fuzzing.campaigns.target_preparation import (
    AssetVersionRequest,
    DeterministicPreparationError,
    PreparationPlan,
    PreparedTarget,
    TargetPreparationFailed,
    TargetPreparationService,
)
from backend.fuzzing.docker.container_runner import ContainerResult, ContainerTimedOut
from backend.fuzzing.layers.manifest import LayerManifest
from backend.services.campaigns.decision_executor import ActionResult, DecisionExecutor


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
    return ProbeInputEvidence(
        name=name,
        role=role,
        exit_code=exit_code,
        alive=alive,
        accepts_input=accepts_input,
        deterministic=deterministic,
        project_lines=project_lines,
        harness_lines=harness_lines,
        startup_lines=startup_lines,
        immediate_crash=immediate_crash,
        timed_out=timed_out,
        sanitizer_output=sanitizer_output,
        invalid_api_use=invalid_api_use,
        replayed_immediate_crash=replayed_immediate_crash,
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
    evidence = probe_evidence(replace(input_evidence(), **change))

    result = ProbePolicy.accept(evidence)

    assert result.accepted is False
    assert reason in result.reason


def test_probe_requires_immediate_crash_replay_and_rejects_seed_independent_crashes() -> None:
    unreplayed = probe_evidence(input_evidence(immediate_crash=True))
    seed_independent = probe_evidence(
        input_evidence(
            "empty", role="empty", immediate_crash=True, replayed_immediate_crash=True,
            accepts_input=False, project_lines=0,
        ),
        input_evidence(immediate_crash=True, replayed_immediate_crash=True),
    )

    assert "replayed" in ProbePolicy.accept(unreplayed).reason
    assert "seed-independent" in ProbePolicy.accept(seed_independent).reason


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
    result = ProbePolicy.accept(probe_evidence(replace(input_evidence(), **change)))

    assert result.accepted is False
    assert reason in result.reason


class _ProbeRunner:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    async def run(self, image, command, timeout, sink):
        self.calls.append((image, tuple(command), timeout))
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
            ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty")),
            ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum")),
            ProbeInvocation("seed:message.bin", "seed", ("/opt/bigeye/probe", "tests/data/message.bin")),
        ),
    )

    evidence = run(ProbeService(runner, timeout_seconds=2.0).run(target))

    assert [call[1][-1] for call in runner.calls] == [
        "empty", "empty", "minimum", "minimum", "tests/data/message.bin", "tests/data/message.bin",
    ]
    assert evidence.exit_codes == (0, 0, 0)
    assert evidence.alive and evidence.accepts_input and evidence.deterministic
    assert evidence.project_lines == 5 and evidence.harness_lines == 2 and evidence.startup_lines == 1
    assert ProbePolicy.accept(evidence).accepted is True


def test_probe_timeout_is_retained_as_evidence_instead_of_retried_as_transport() -> None:
    runner = _ProbeRunner([
        _probe_output(), _probe_output(), _probe_output(), _probe_output(),
        ContainerTimedOut("bounded probe timed out"), ContainerTimedOut("bounded probe timed out"),
    ])
    target = SimpleNamespace(
        image="sha256:" + "b" * 64,
        probe_invocations=(
            ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty")),
            ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum")),
            ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed")),
        ),
    )

    evidence = run(ProbeService(runner, timeout_seconds=1.0).run(target))

    assert evidence.timed_out is True
    assert evidence.exit_codes == (0, 0, None)
    assert "timed out" in ProbePolicy.accept(evidence).reason


def test_probe_preserves_sanitizer_report_emitted_outside_the_result_record() -> None:
    seed = _probe_output()
    seed = ContainerResult(seed.exit_code, "runtime error: invalid shift\n" + seed.output)
    runner = _ProbeRunner([_probe_output() for _ in range(4)] + [seed, seed])
    target = SimpleNamespace(
        image="sha256:" + "b" * 64,
        probe_invocations=(
            ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty")),
            ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum")),
            ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed")),
        ),
    )

    evidence = run(ProbeService(runner, timeout_seconds=1.0).run(target))

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
    def __init__(self, shared_key="parser-target"):
        self.shared_key = shared_key

    def plan(self, selected_project, selected_proposal):
        name = selected_proposal.target_name
        requests = (
            AssetVersionRequest(
                "target", "harness", "harness.cc", {"harness.cc": f"draft:{name}"},
                self.shared_key, (f"component/{name}/harness.cc",),
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
                ProbeInvocation("empty", "empty", ("/opt/bigeye/probe", "empty")),
                ProbeInvocation("minimum", "minimum", ("/opt/bigeye/probe", "minimum")),
                ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed")),
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

    def prepare(self, selected_project, project_manifest, target, configuration, sink, fuzz_patch_asset=None):
        self.calls.append((selected_project.id, target.id, configuration.id, fuzz_patch_asset))
        if self.fail:
            raise DeterministicPreparationError("target compilation failed")
        return _manifest("target", f"bigeye-target:{target.id}")


class _CoverageLayers:
    def __init__(self):
        self.calls = []

    def prepare(self, selected_project, project_manifest, adapter, configuration, sink):
        self.calls.append((selected_project.id, adapter.id, configuration.id))
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
        return selected_proposal.model_copy(update={"uncertainty": "repaired target requires a fresh probe"})


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
    assert prepared.agent_attempts == ("gpt-5.6-luna",)
    assert prepared.probe.accepted is True


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
            probe_invocations=(ProbeInvocation("seed", "seed", ("/opt/bigeye/probe", "seed")),),
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


def test_transport_failure_is_not_sent_to_terra() -> None:
    class TransportFailureProbe:
        async def run(self, prepared):
            raise ConnectionError("Docker daemon disconnected")

    repairer = _Repairer()
    service = preparation(probe=TransportFailureProbe(), repairer=repairer)

    with pytest.raises(ConnectionError, match="Docker daemon"):
        run(service.prepare(project(), proposal()))

    assert repairer.calls == []


def test_repair_cannot_silently_change_target_identity() -> None:
    class IdentityChangingRepairer:
        async def repair(self, selected_project, selected_proposal, failure, model):
            return proposal("different-target")

    service = preparation(
        probe=_Probe(probe_evidence(input_evidence(project_lines=0))),
        repairer=IdentityChangingRepairer(),
    )

    with pytest.raises(TargetPreparationFailed, match="identity") as captured:
        run(service.prepare(project(), proposal()))

    assert captured.value.agent_attempts == ("gpt-5.6-luna", "gpt-5.6-terra")


def test_same_project_asset_is_serialized_but_distinct_targets_prepare_in_parallel() -> None:
    shared_store = _AssetStore()
    shared_service = preparation(asset_store=shared_store, planner=_Planner(shared_key="shared"))

    async def same_asset():
        await asyncio.gather(
            shared_service.prepare(project(), proposal("first")),
            shared_service.prepare(project(), proposal("second")),
        )

    run(same_asset())
    assert shared_store.max_active == 1

    distinct_store = _AssetStore()

    class DistinctPlanner(_Planner):
        def plan(self, selected_project, selected_proposal):
            self.shared_key = selected_proposal.target_name
            return super().plan(selected_project, selected_proposal)

    distinct_service = preparation(asset_store=distinct_store, planner=DistinctPlanner())

    async def distinct_assets():
        await asyncio.gather(
            distinct_service.prepare(project(), proposal("first")),
            distinct_service.prepare(project(), proposal("second")),
        )

    run(distinct_assets())
    assert distinct_store.max_active > 1


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
            next_review_condition="after the probe",
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
