"""Agents SDK lifecycle hooks that mirror calls into the local sanitized trace."""

from __future__ import annotations

import json

from agents import RunHooks

from backend.agents.tracing.local_trace import _usage, reasoning_summaries, web_citations


def _parent_id(context) -> str | None:
    return getattr(context, "tool_call_id", None)


def _arguments(context):
    value = getattr(context, "tool_arguments", None)
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


class AgentTraceHooks(RunHooks):
    """Capture observable lifecycle data, not hidden model chain of thought."""

    def __init__(self, trace):
        self._trace = trace

    async def on_agent_start(self, context, agent) -> None:
        self._trace.debug(
            "agent.start", agent=agent.name, model=agent.model, parent_id=_parent_id(context),
            usage=_usage(getattr(context, "usage", None)),
        )

    async def on_agent_end(self, context, agent, output) -> None:
        self._trace.debug(
            "agent.end", agent=agent.name, model=agent.model, parent_id=_parent_id(context), output=output,
            usage=_usage(getattr(context, "usage", None)),
        )

    async def on_llm_start(self, context, agent, system_prompt, input_items) -> None:
        self._trace.debug(
            "model.start", agent=agent.name, model=agent.model, parent_id=_parent_id(context),
            input={"system_prompt": system_prompt, "items": input_items},
            usage=_usage(getattr(context, "usage", None)),
        )

    async def on_llm_end(self, context, agent, response) -> None:
        self._trace.debug(
            "model.end", response_id=getattr(response, "response_id", None),
            request_id=getattr(response, "request_id", None), agent=agent.name, model=agent.model,
            parent_id=_parent_id(context), output=getattr(response, "output", None),
            usage=_usage(getattr(response, "usage", None)),
            reasoning_summaries=reasoning_summaries(getattr(response, "output", None)),
            web_citations=web_citations(getattr(response, "output", None)),
        )

    async def on_tool_start(self, context, agent, tool) -> None:
        self._trace.debug(
            "tool.start", agent=agent.name, model=agent.model, parent_id=_parent_id(context),
            tool=getattr(tool, "name", type(tool).__name__), tool_call_id=getattr(context, "tool_call_id", None),
            arguments=_arguments(context),
        )

    async def on_tool_end(self, context, agent, tool, result) -> None:
        self._trace.debug(
            "tool.end", agent=agent.name, model=agent.model, parent_id=_parent_id(context),
            tool=getattr(tool, "name", type(tool).__name__), tool_call_id=getattr(context, "tool_call_id", None),
            arguments=_arguments(context), result=result,
        )

    async def on_handoff(self, context, from_agent, to_agent) -> None:
        self._trace.debug(
            "agent.handoff", agent=from_agent.name, model=from_agent.model, parent_id=_parent_id(context),
            destination=to_agent.name,
        )
