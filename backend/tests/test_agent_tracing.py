import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from agents import Agent
from agents.run import RunConfig
from agents.run_context import RunContextWrapper
from agents.tool_context import ToolContext

from backend.agents.context import AgentContext
from backend.agents.manager import CampaignManager
from backend.agents.outputs.campaign_decision import CampaignDecision
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


def test_campaign_manager_returns_structured_decision_and_writes_plain_activity(tmp_path: Path) -> None:
    store = ProjectEventStore(tmp_path)
    context = context_for(tmp_path)
    decision = CampaignDecision(
        decision="prepare target", motivation="The parser accepts untrusted bytes.", evidence_ids=["known"],
        bounded_actions=["prepare_system_target"], next_review_condition="after target probe",
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

    assert result == decision
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
                evidence_ids=[evidence_id], bounded_actions=["prepare_system_target"],
                next_review_condition="after probe", uncertainty="input path not measured",
            ),
            raw_responses=[], new_items=[],
        )

    result = run(CampaignManager(store, runner=runner).review(
        context, evidence=[], reason="initial review",
    ))

    assert len(result.evidence_ids) == 1
