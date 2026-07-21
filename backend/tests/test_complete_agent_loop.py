"""Opt-in acceptance for the complete agent-discovered fuzzing loop."""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "backend/tests/fixtures/whole_loop_project"


def test_whole_loop_fixture_is_a_plain_api_and_cli_project() -> None:
    expected = {
        "CMakeLists.txt",
        "include/decoder.h",
        "src/decoder.c",
        "src/decoder_cli.c",
        "seeds/plain.input",
        "seeds/framed.input",
    }
    files = {
        path.relative_to(FIXTURE).as_posix()
        for path in FIXTURE.rglob("*")
        if path.is_file()
    }

    assert files == expected
    combined = "\n".join(
        (FIXTURE / relative).read_text(encoding="utf-8", errors="replace")
        for relative in sorted(files)
    ).casefold()
    for forbidden in (
        "llvmfuzzertestoneinput",
        "afl-fuzz",
        "libfuzzer",
        "dockerfile",
        "dictionary",
        "expected target",
    ):
        assert forbidden not in combined

    header = (FIXTURE / "include/decoder.h").read_text(encoding="utf-8")
    cmake = (FIXTURE / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "decoder_decode" in header
    assert "add_library(" in cmake
    assert "add_executable(" in cmake
    assert "decoder_cli" in cmake


def test_initial_manager_review_uses_parallel_independent_discovery() -> None:
    from backend.agents.prompts.manager import MANAGER_PROMPT

    prompt = MANAGER_PROMPT.casefold()
    assert "at least two" in prompt
    assert "parallel" in prompt
    assert "independent repository entry paths" in prompt


def test_worker_prompt_keeps_engine_orchestration_out_of_target_argv() -> None:
    from backend.agents.prompts.fuzzing_worker import FUZZING_WORKER_PROMPT

    prompt = FUZZING_WORKER_PROMPT.casefold()
    assert "application argv only" in prompt
    assert "start with an executable under /opt/bigeye" in prompt
    assert "must never include\nafl-fuzz" in prompt
    assert "/opt/bigeye/generated-assets/<relative path>" in prompt
    assert "every declared seed must be compatible" in prompt


def test_real_worker_proposal_and_probe_request_promote_after_output_validation() -> None:
    from backend.agents.outputs.campaign_review import CampaignReviewCollection, WorkerInvocation
    from backend.agents.outputs.target_proposal import TargetProposal

    invocation = WorkerInvocation(
        "prepare decoder component", "call-real-shape", 1, "gpt-5.6-luna",
    )
    collection = CampaignReviewCollection()
    content = b"int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);\n"
    request = collection.record_operation(
        invocation,
        {
            "operation": "probe",
            "asset_paths": ["decoder_fuzz.c"],
            "assertions": ["Run bounded deterministic probes with the repository seeds."],
            "executed": False,
            "provenance": "agent_request",
            "trusted_instructions": False,
        },
        project_id=7,
        project_commit_sha="a" * 40,
        draft_sha256s=(("decoder_fuzz.c", sha256(content).hexdigest()),),
        evidence_ids=("repository-inventory:7:exact",),
    )
    proposal = TargetProposal(
        target_name="decoder_component",
        instance_type="component-level",
        byte_path="input bytes reach decoder_decode through a generated entrypoint",
        expected_project_reach="decoder_decode and decode_payload",
        build_command="clang /src/src/decoder.c /opt/bigeye/generated-assets/decoder_fuzz.c",
        run_command="/opt/bigeye/decoder_component",
        seeds=[{"path": "seeds/plain.input", "provenance": "repository"}],
        configuration="component decoder API",
        sanitizer_plan="ASan and UBSan",
        generated_asset_intents=[{
            "relative_path": "decoder_fuzz.c", "purpose": "component entrypoint",
        }],
        probe_assertions=["The valid seed reaches decoder_decode."],
        evidence_ids=["repository-inventory:7:exact"],
        uncertainty="The deterministic probe has not run.",
    )

    proposal_record = collection.record_worker_outcome(invocation, proposal)
    collection.complete_attempt(invocation, accepted=True)
    action = collection.pipeline_operation(request.request_id)

    assert action.target_proposal == proposal_record
    assert action.asset_paths == ("decoder_fuzz.c",)
    assert action.draft_sha256s == (("decoder_fuzz.c", sha256(content).hexdigest()),)


def test_duplicate_real_worker_requests_receive_one_bounded_correction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    from agents import Runner
    from agents.run import RunConfig
    from agents.tool_context import ToolContext

    from backend.agents.context import AgentContext
    from backend.agents.outputs.campaign_review import CampaignReviewCollection
    from backend.agents.outputs.fuzzing_worker_result import FuzzingWorkerResult
    from backend.agents.outputs.target_proposal import TargetProposal
    from backend.agents.tools.agent_dispatch import dispatch_tools
    from backend.agents.tools.generated_assets import write_asset_file
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "decoder.c").write_text("int decoder_decode(void) { return 0; }\n")
    generated = tmp_path / "generated"
    context = AgentContext(7, "a" * 40, repository, generated, EvidenceRetriever(repository))
    write_asset_file(
        context, "decoder_fuzz.c",
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n",
        None,
    )
    collection = CampaignReviewCollection()
    calls: list[str] = []
    request_ids: dict[str, list[str]] = {}

    def proposal() -> TargetProposal:
        return TargetProposal(
            target_name="decoder_component", instance_type="component-level",
            byte_path="bytes reach decoder_decode", expected_project_reach="decoder.c",
            build_command="clang /src/decoder.c /opt/bigeye/generated-assets/decoder_fuzz.c",
            run_command="/opt/bigeye/decoder_component",
            seeds=[], configuration="decoder API", sanitizer_plan="ASan and UBSan",
            generated_asset_intents=[{
                "relative_path": "decoder_fuzz.c", "purpose": "component entrypoint",
            }],
            probe_assertions=["The bounded seed reaches decoder_decode."],
            evidence_ids=["known"], uncertainty="The probe has not run.",
        )

    class Result:
        interruptions = []
        new_items = []
        raw_responses = []
        input = "nested"

        def __init__(self, agent, outer_context):
            self.final_output = FuzzingWorkerResult(
                summary="Prepared the decoder component proposal.",
                evidence_ids=["known"], target_proposals=[proposal()], triage_results=[],
                operation_request_ids=request_ids[agent.model], recommendations=[],
                uncertainty="The retained operation has not run.",
            )
            self.agent_tool_invocation = SimpleNamespace(
                tool_name=outer_context.tool_name,
                tool_call_id=outer_context.tool_call_id,
                tool_arguments=outer_context.tool_arguments,
            )

        def to_input_list(self):
            return []

    async def runner(starting_agent=None, context=None, **_kwargs):
        calls.append(starting_agent.model)
        operation_tool = next(
            item for item in starting_agent.tools if item.name == "request_contained_operation"
        )
        operations = ("build", "probe") if starting_agent.model == "gpt-5.6-luna" else ("probe",)
        ids = []
        for index, operation in enumerate(operations):
            arguments = (
                '{"operation":"' + operation + '","asset_paths":["decoder_fuzz.c"],'
                '"assertions":["Run the bounded decoder preparation."]}'
            )
            record = await operation_tool.on_invoke_tool(ToolContext(
                context.context,
                tool_name=operation_tool.name,
                tool_call_id=f"operation-{starting_agent.model}-{index}",
                tool_arguments=arguments,
                tool_input=context.tool_input,
                run_config=RunConfig(),
                agent=starting_agent,
            ), arguments)
            ids.append(record["request_id"])
        request_ids[starting_agent.model] = ids
        return Result(starting_agent, context)

    monkeypatch.setattr(Runner, "run", runner)
    tool = dispatch_tools(
        context, evidence_ids={"known"},
        evidence_records={"known": {"evidence_id": "known"}},
        collection=collection,
    )[0]
    arguments = '{"assignment":"prepare decoder","evidence_ids":["known"]}'

    output = asyncio.run(tool.on_invoke_tool(ToolContext(
        context, tool_name=tool.name, tool_call_id="call-real-shape",
        tool_arguments=arguments, run_config=RunConfig(),
    ), arguments))

    assert calls == ["gpt-5.6-luna", "gpt-5.6-terra"]
    assert output["target_result_ids"] == []
    assert len(output["pipeline_action_ids"]) == 1
    assert {record.model for record in collection.result.__self__._operations.values()} == {
        "gpt-5.6-terra"
    }
    assert {record.model for record in collection.result.__self__._quarantined_operations.values()} == {
        "gpt-5.6-luna"
    }


def test_run9_state_requires_distinct_system_repair_without_repeat_triage() -> None:
    from backend.agents.manager import _validate_supervision_priority
    from backend.agents.tools.agent_dispatch import WorkerValidationError

    failure_id = "action-failure:7:bad-cli"
    evidence = {
        failure_id: {
            "evidence_id": failure_id,
            "kind": "action_execution_failure",
            "action_ids": ["pipeline_bad_cli"],
            "failures": [{
                "action_id": "pipeline_bad_cli",
                "phase": "probe",
                "command": ["/opt/bigeye/decoder_cli"],
                "message": "bad fixed argv",
            }],
        },
        "campaign-strategy-inventory:7:current": {
            "evidence_id": "campaign-strategy-inventory:7:current",
            "kind": "campaign_strategy_inventory",
            "strategies": [{
                "campaign_id": 1,
                "instance_type": "component-level",
                "engine": "libfuzzer",
                "activity": "working",
            }],
            "system_surface": True,
            "system_gap": True,
            "required_next_instance_type": "system-level",
        },
        "finding:stable": {
            "evidence_id": "finding:stable",
            "kind": "finalized_finding",
            "classification": "true vulnerability",
            "reproducible": True,
            "retained_replay_evidence_id": "finding-replay:stable:exact",
        },
        "finding-replay:stable:exact": {
            "evidence_id": "finding-replay:stable:exact",
            "kind": "finding_replay_evidence",
            "replay": {"attempts": 3, "matching": 3},
            "minimisation": {"accepted": True, "minimal_size": 11},
        },
    }
    replay_only = SimpleNamespace(
        selected_action_ids=("triage_again",),
        selected_target_proposals=(), selected_pipeline_operations=(),
        selected_triage_results=(SimpleNamespace(result_id="triage_again"),),
    )

    with pytest.raises(WorkerValidationError, match="finalized finding"):
        _validate_supervision_priority(replay_only, evidence)

    proposal = SimpleNamespace(
        result_id="target_corrected_cli",
        proposal=SimpleNamespace(instance_type="system-level"),
    )
    corrected = SimpleNamespace(
        selected_action_ids=("pipeline_corrected_cli",),
        selected_target_proposals=(),
        selected_pipeline_operations=(SimpleNamespace(
            action_id="pipeline_corrected_cli", operation="probe", target_proposal=proposal,
        ),),
        selected_triage_results=(),
    )

    _validate_supervision_priority(corrected, evidence)

    assert corrected.selected_action_ids != ("pipeline_bad_cli",)
    assert evidence["campaign-strategy-inventory:7:current"]["strategies"][0]["activity"] == "working"


@pytest.mark.skipif(
    os.environ.get("BIGEYE_LIVE_ACCEPTANCE") != "1",
    reason="complete Agents SDK and Docker acceptance is opt-in",
)
def test_live_complete_agent_loop_through_the_real_product() -> None:
    """Run the browser-driven production loop; it supplies no target commands or runtime doubles."""
    subprocess.run(
        [
            ROOT / "frontend/node_modules/.bin/playwright",
            "test",
            "--config",
            ROOT / "playwright.config.ts",
            ROOT / "tests/e2e/bigeye.spec.ts",
        ],
        cwd=ROOT,
        env={**os.environ, "BIGEYE_LIVE_ACCEPTANCE": "1"},
        check=True,
    )
