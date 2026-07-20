import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from agents import Agent
from agents.run import RunConfig
from agents.run_context import RunContextWrapper
from agents.tool_context import ToolContext
from agents.items import ToolCallItem
import pytest

from backend.agents.context import AgentContext
from backend.agents.manager import CampaignManager
from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.campaign_review import (
    CampaignReviewResult,
    ProgressionActionRecord,
    RetirementActionRecord,
)
from backend.agents.tracing.hooks import AgentTraceHooks
from backend.agents.tracing.local_trace import LocalTrace
from backend.fuzzing.discovery.retrieval import EvidenceRetriever
from backend.services.observability.event_store import ProjectEventStore


def run(awaitable):
    return asyncio.run(awaitable)


def context_for(tmp_path: Path) -> AgentContext:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "main.c").write_text("int main(void) { return 0; }\n")
    return AgentContext(7, "a" * 40, repository, tmp_path / "assets", EvidenceRetriever(repository))


def read_payloads(store: ProjectEventStore, stream: str):
    return [event.payload for event in run(store.read(7, stream, -1, 100))]


def prepared_action(kind: str):
    if kind == "retirement":
        return RetirementActionRecord(
            action_id="retirement:7:9:90:4:40", project_id=7, campaign_id=9,
            strategy_asset_id=90, retained_campaign_id=4, retained_strategy_asset_id=40,
            evidence_ids=("checkpoint:1", "checkpoint:2"),
            reason="clean subset at two checkpoints", reversible=True,
        )
    return ProgressionActionRecord(
        action_id="campaign-progression:7:9:abcd1234abcd1234",
        project_id=7, base_campaign_id=9, target_asset_id=31,
        action_name="enable dictionary", evidence_ids=("checkpoint:1",),
        dictionary_content='token_000="MAGIC"\n',
    )


def test_trace_contains_model_tool_usage_reasoning_citations_and_no_secrets(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    context = context_for(tmp_path)
    trace = LocalTrace(
        store, project_id=7, trace_id="trace_" + "1" * 32,
        secret_values=("sk-secret", "git-secret"),
    )
    hooks = AgentTraceHooks(trace)
    agent = Agent(name="System target specialist", model="gpt-5.6-luna")
    wrapper = RunContextWrapper(context)
    wrapper.usage.requests = 1
    wrapper.usage.input_tokens = 21
    wrapper.usage.output_tokens = 8
    wrapper.usage.total_tokens = 29
    wrapper.usage.input_tokens_details.cached_tokens = 9
    wrapper.usage.output_tokens_details.reasoning_tokens = 4
    tool = SimpleNamespace(name="retrieve_repository_evidence")
    tool_context = ToolContext(
        context, tool_name=tool.name, tool_call_id="call-1",
        tool_arguments='{"api_key":"sk-secret","query":"parser"}',
    )
    response = SimpleNamespace(
        response_id="resp-1", request_id="request-1",
        usage=SimpleNamespace(
            requests=1, input_tokens=21, output_tokens=8, total_tokens=29,
            input_tokens_details=SimpleNamespace(cached_tokens=9),
            output_tokens_details=SimpleNamespace(reasoning_tokens=4),
        ),
        output=[
            {"type": "reasoning", "summary": [{"text": "API-provided summary"}]},
            {"type": "message", "content": [{
                "type": "output_text", "text": "official guidance",
                "annotations": [{"type": "url_citation", "url": "https://example.org/docs"}],
            }]},
        ],
    )

    run(hooks.on_agent_start(wrapper, agent))
    run(hooks.on_llm_start(wrapper, agent, "system sk-secret", [{"role": "user", "content": "git-secret"}]))
    run(hooks.on_tool_start(tool_context, agent, tool))
    run(hooks.on_tool_end(tool_context, agent, tool, {"token": "git-secret", "result": "bounded"}))
    run(hooks.on_llm_end(wrapper, agent, response))
    run(hooks.on_agent_end(wrapper, agent, {"result": "done"}))
    trace.record_result(
        agent=agent,
        workflow_input={"repository_token": "git-secret", "request": "inspect"},
        result=SimpleNamespace(final_output={"decision": "continue"}, raw_responses=[response], new_items=[]),
        retry_count=1,
    )

    debug = read_payloads(store, "debug")
    encoded = json.dumps(debug)
    assert "sk-secret" not in encoded
    assert "git-secret" not in encoded
    assert {item["event"] for item in debug} >= {
        "agent.start", "model.start", "tool.start", "tool.end", "model.end", "agent.end", "workflow.result"
    }
    result = next(item for item in debug if item["event"] == "workflow.result")
    assert result["trace_id"] == "trace_" + "1" * 32
    assert result["response_id"] == "resp-1"
    assert result["agent"] == "System target specialist"
    assert result["model"] == "gpt-5.6-luna"
    assert result["input"]["repository_token"] == "[REDACTED]"
    assert result["output"] == {"decision": "continue"}
    assert result["usage"]["cached_tokens"] == 9
    assert result["usage"]["reasoning_tokens"] == 4
    assert result["retry_count"] == 1
    model = next(item for item in debug if item["event"] == "model.end")
    assert model["reasoning_summaries"] == ["API-provided summary"]
    assert model["web_citations"] == ["https://example.org/docs"]
    tool_end = next(item for item in debug if item["event"] == "tool.end")
    assert tool_end["tool_call_id"] == "call-1"
    assert tool_end["arguments"]["api_key"] == "[REDACTED]"


def test_trace_run_config_keeps_sdk_tracing_without_sensitive_payloads(tmp_path: Path) -> None:
    trace = LocalTrace(ProjectEventStore(tmp_path), 7)

    config = trace.run_config("campaign review")

    assert config.tracing_disabled is False
    assert config.trace_include_sensitive_data is False
    assert config.trace_id == trace.trace_id
    assert config.workflow_name == "campaign review"
    assert config.group_id == "project-7"


def test_large_sanitized_trace_is_chunked_without_losing_debug_payload(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    trace = LocalTrace(store, 7, secret_values=("sk-secret",))
    large = [f"record-{index}-" + "x" * 31_000 + "sk-secret" for index in range(40)]

    trace.debug("model.end", output=large)

    records = read_payloads(store, "debug")
    assert len(records) > 1
    assert all(record["event"] == "model.end.chunk" for record in records)
    assert [record["chunk_index"] for record in records] == list(range(len(records)))
    reconstructed = "".join(record["data"] for record in records)
    payload = json.loads(reconstructed)
    assert payload["event"] == "model.end"
    assert len(payload["output"]) == 40
    assert "sk-secret" not in reconstructed


def test_known_sdk_payloads_preserve_long_strings_all_items_and_nesting(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    trace = LocalTrace(store, 7)
    nested = {"leaf": "complete"}
    for _ in range(20):
        nested = {"child": nested}
    payload = {
        "long": "x" * 40_000,
        "items": [{"index": index, "text": f"item-{index}"} for index in range(150)],
        "nested": nested,
    }

    trace.debug("model.end", output=payload)

    records = read_payloads(store, "debug")
    if records[0]["event"].endswith(".chunk"):
        stored = json.loads("".join(record["data"] for record in records))
    else:
        stored = records[0]
    assert stored["output"]["long"] == payload["long"]
    assert stored["output"]["items"] == payload["items"]
    value = stored["output"]["nested"]
    for _ in range(20):
        value = value["child"]
    assert value == {"leaf": "complete"}


def test_result_trace_records_agent_tool_invocation_metadata(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    trace = LocalTrace(store, 7)
    agent = Agent(name="worker", model="gpt-5.6-luna")
    result = SimpleNamespace(
        final_output={"ok": True}, raw_responses=[], new_items=[],
        agent_tool_invocation=SimpleNamespace(
            tool_name="prepare_system_target", tool_call_id="call-parent",
            tool_arguments='{"assignment":"parser","evidence_ids":["known"]}',
        ),
    )

    trace.record_result(agent, "nested input", result)

    record = read_payloads(store, "debug")[-1]
    assert record["parent_tool"] == "prepare_system_target"
    assert record["parent_tool_call_id"] == "call-parent"
    assert record["parent_tool_arguments"] == {
        "assignment": "parser", "evidence_ids": ["known"],
    }


def test_result_trace_serializes_sdk_run_items_without_following_agent_tool_cycles(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    trace = LocalTrace(store, 7)
    agent = Agent(name="worker", model="gpt-5.6-luna", tools=[])
    item = ToolCallItem(
        agent=agent,
        raw_item={
            "type": "function_call", "name": "read_source_lines", "call_id": "call-1",
            "arguments": '{"relative_path":"main.c","start_line":1,"end_line":1}',
        },
        description="read one source line",
    )

    trace.record_result(
        agent, "nested", SimpleNamespace(final_output={"ok": True}, raw_responses=[], new_items=[item]),
    )

    record = read_payloads(store, "debug")[-1]
    stored = record["new_items"][0]
    assert stored["agent"] == {"name": "worker", "model": "gpt-5.6-luna"}
    assert stored["raw_item"] == item.raw_item
    assert stored["description"] == "read one source line"


def test_campaign_manager_returns_structured_decision_and_writes_plain_activity(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    context = context_for(tmp_path)
    decision = CampaignDecision(
        decision="prepare target", motivation="The parser accepts untrusted bytes.", evidence_ids=["known"],
        bounded_actions=[], next_review_condition="after target probe",
        uncertainty="runtime behaviour is not measured yet",
    )
    calls = []

    async def runner(agent, prompt, **kwargs):
        calls.append((agent, prompt, kwargs))
        return SimpleNamespace(final_output=decision, raw_responses=[], new_items=[])

    manager = CampaignManager(store, runner=runner)
    result = run(manager.review(
        context,
        evidence=[{"evidence_id": "known", "summary": "stdin parser", "trusted_instructions": False}],
        reason="initial target review",
    ))

    assert isinstance(result, CampaignReviewResult)
    assert result.decision == decision
    assert calls[0][0].model == "gpt-5.6-terra"
    assert {tool.name for tool in calls[0][0].tools} == {
        "prepare_system_target", "prepare_component_target", "triage_crash_group"
    }
    assert calls[0][2]["run_config"].trace_include_sensitive_data is False
    activity = read_payloads(store, "activity")
    assert activity[-1] == {
        "decision": "prepare target", "motivation": "The parser accepts untrusted bytes.",
        "evidence_ids": ["known"], "next_review_condition": "after target probe",
    }
    assert "reasoning" not in json.dumps(activity).casefold()


def test_campaign_manager_accepts_source_evidence_registered_inside_a_specialist(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    context = context_for(tmp_path)

    async def runner(agent, prompt, **kwargs):
        system_tool = next(tool for tool in agent.tools if tool.name == "prepare_system_target")
        retrieval = next(tool for tool in system_tool._agent_instance.tools if tool.name == "retrieve_repository_evidence")
        tool_context = ToolContext(
            context, tool_name=retrieval.name, tool_call_id="retrieve-1",
            tool_arguments='{"question":"main","limit":1}', run_config=RunConfig(),
        )
        excerpts = await retrieval.on_invoke_tool(tool_context, '{"question":"main","limit":1}')
        evidence_id = excerpts[0]["evidence_id"]
        return SimpleNamespace(
            final_output=CampaignDecision(
                decision="prepare target", motivation="The executable has a source entry point.",
                evidence_ids=[evidence_id], bounded_actions=[],
                next_review_condition="after probe", uncertainty="input path not measured",
            ),
            raw_responses=[], new_items=[],
        )

    result = run(CampaignManager(store, runner=runner).review(
        context, evidence=[], reason="initial review",
    ))

    assert len(result.decision.evidence_ids) == 1


def test_campaign_manager_returns_selectable_specialist_result_and_audit_operation_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agents import Runner

    context = context_for(tmp_path)
    context.generated_assets_root.mkdir()
    draft = context.generated_assets_root / "system" / "parser"
    draft.mkdir(parents=True)
    (draft / "config.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    proposal = {
        "target_name": "parser", "instance_type": "system-level", "byte_path": "stdin -> parser",
        "expected_project_reach": "parser", "build_command": "build", "run_command": "run",
        "seeds": [], "configuration": "default", "sanitizer_plan": "ASan and UBSan",
        "generated_asset_intents": [], "probe_assertions": ["reaches parser"],
        "evidence_ids": ["known"], "uncertainty": "not probed",
    }

    class NestedResult:
        interruptions = []
        new_items = []
        raw_responses = []
        input = "nested"
        final_output = proposal
        agent_tool_invocation = SimpleNamespace(
            tool_name="prepare_system_target", tool_call_id="call-specialist",
            tool_arguments='{"assignment":"parser","evidence_ids":["known"]}',
        )

        def to_input_list(self):
            return []

    operation_outputs = {}

    async def nested_runner(starting_agent=None, context=None, hooks=None, **kwargs):
        await hooks.on_agent_start(context, starting_agent)
        operation_tool = next(
            tool for tool in starting_agent.tools if tool.name == "request_contained_operation"
        )
        operation_context = ToolContext(
            context.context, tool_name=operation_tool.name, tool_call_id="call-operation",
            tool_arguments=(
                '{"operation":"probe","asset_paths":["system/parser/config.sh"],'
                '"assertions":["reaches parser"]}'
            ), run_config=RunConfig(), agent=starting_agent,
        )
        operation_outputs[context.tool_call_id] = await operation_tool.on_invoke_tool(
            operation_context, operation_context.tool_arguments,
        )
        return NestedResult()

    monkeypatch.setattr(Runner, "run", nested_runner)

    manager_calls = 0

    async def manager_runner(agent, prompt, **kwargs):
        nonlocal manager_calls
        manager_calls += 1
        target_tool = next(tool for tool in agent.tools if tool.name == "prepare_system_target")
        target_context = ToolContext(
            context, tool_name=target_tool.name, tool_call_id="call-specialist",
            tool_arguments='{"assignment":"parser","evidence_ids":["known"]}',
            run_config=RunConfig(),
        )
        specialist = await target_tool.on_invoke_tool(target_context, target_context.tool_arguments)
        return SimpleNamespace(
            final_output=CampaignDecision(
                decision="probe", motivation="proposal ready",
                evidence_ids=["known", specialist["result_id"]],
                bounded_actions=[specialist["result_id"]],
                next_review_condition="after probe", uncertainty="not probed",
            ), raw_responses=[], new_items=[],
        )

    store = ProjectEventStore(tmp_path)
    review = run(CampaignManager(store, runner=manager_runner).review(
        context, [{"evidence_id": "known", "summary": "parser"}], "prepare parser",
    ))

    assert manager_calls == 1
    assert review.known_target_proposals[0].proposal.target_name == "parser"
    assert review.known_operation_requests[0].operation == "probe"
    assert review.known_operation_requests[0].tool_call_id == "call-specialist"
    assert review.known_operation_requests[0].actionable is False
    assert review.decision.bounded_actions == [review.known_target_proposals[0].result_id]
    assert review.decision.evidence_ids == ["known"]
    assert review.selected_action_ids == tuple(review.decision.bounded_actions)
    assert review.selected_operation_requests == ()
    debug = read_payloads(store, "debug")
    workflow_result = next(
        event for event in debug
        if event["event"] == "workflow.result" and event["agent"] == "Campaign manager"
    )
    assert workflow_result["output"]["evidence_ids"] == [
        "known", review.known_target_proposals[0].result_id,
    ]
    normalized = next(event for event in debug if event["event"] == "manager.decision.normalized")
    assert normalized["removed_action_ids"] == [review.known_target_proposals[0].result_id]
    assert normalized["normalized_evidence_ids"] == ["known"]
    assert read_payloads(store, "activity")[-1]["evidence_ids"] == ["known"]


@pytest.mark.parametrize("kind", ["retirement", "progression"])
def test_campaign_manager_normalizes_selected_prepared_action_ids(
    tmp_path: Path, kind: str,
) -> None:
    store = ProjectEventStore(tmp_path)
    context = context_for(tmp_path)
    record = prepared_action(kind)
    calls = 0

    async def runner(_agent, _prompt, **_kwargs):
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            final_output=CampaignDecision(
                decision="apply prepared action", motivation="factual checkpoint supports it",
                evidence_ids=["checkpoint:1", record.action_id],
                bounded_actions=[record.action_id],
                next_review_condition="after deterministic execution", uncertainty="not executed",
            ),
            raw_responses=[], new_items=[],
        )

    review = run(CampaignManager(store, runner=runner).review(
        context,
        [
            {"evidence_id": "checkpoint:1", "trusted_instructions": False},
            {"evidence_id": record.action_id, "trusted_instructions": False},
        ],
        "prepared campaign action",
        prepared_actions=(record,),
    ))

    assert calls == 1
    assert review.decision.evidence_ids == ["checkpoint:1"]
    assert review.selected_action_ids == (record.action_id,)
    selected = (
        review.selected_retirement_actions
        if kind == "retirement" else review.selected_progression_actions
    )
    assert selected == (record,)
    debug = read_payloads(store, "debug")
    raw = next(event for event in debug if event["event"] == "workflow.result")
    assert raw["output"]["evidence_ids"] == ["checkpoint:1", record.action_id]
    normalized = next(event for event in debug if event["event"] == "manager.decision.normalized")
    assert normalized["removed_action_ids"] == [record.action_id]
    assert normalized["normalized_evidence_ids"] == ["checkpoint:1"]
    assert read_payloads(store, "activity")[-1]["evidence_ids"] == ["checkpoint:1"]


@pytest.mark.parametrize("kind", ["retirement", "progression"])
def test_campaign_manager_rejects_unselected_prepared_action_ids_as_evidence(
    tmp_path: Path, kind: str,
) -> None:
    store = ProjectEventStore(tmp_path)
    context = context_for(tmp_path)
    record = prepared_action(kind)
    calls = 0

    async def runner(_agent, _prompt, **_kwargs):
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            final_output=CampaignDecision(
                decision="wait", motivation="action was not selected",
                evidence_ids=["checkpoint:1", record.action_id], bounded_actions=[],
                next_review_condition="new evidence", uncertainty="not selected",
            ),
            raw_responses=[], new_items=[],
        )

    with pytest.raises(
        ValueError, match="manager cited an unselected action as evidence",
    ):
        run(CampaignManager(store, runner=runner).review(
            context,
            [
                {"evidence_id": "checkpoint:1", "trusted_instructions": False},
                {"evidence_id": record.action_id, "trusted_instructions": False},
            ],
            "prepared campaign action",
            prepared_actions=(record,),
        ))

    assert calls == 1
    assert read_payloads(store, "activity") == []


def test_campaign_manager_rejects_nonexistent_or_stale_action_ids(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    context = context_for(tmp_path)

    async def runner(agent, prompt, **kwargs):
        return SimpleNamespace(
            final_output=CampaignDecision(
                decision="probe", motivation="unsupported action", evidence_ids=["known"],
                bounded_actions=["operation_from_another_review"],
                next_review_condition="after probe", uncertainty="not probed",
            ), raw_responses=[], new_items=[],
        )

    with pytest.raises(ValueError, match="action outside this review"):
        run(CampaignManager(store, runner=runner).review(
            context, [{"evidence_id": "known", "summary": "parser"}], "prepare parser",
        ))
