"""Crash-group triage specialist."""

from agents import Agent, ModelSettings, WebSearchTool

from backend.agents.outputs.triage_result import TriageResult
from backend.agents.prompts.crash_triage import CRASH_TRIAGE_PROMPT
from backend.agents.tools.code_navigation import code_navigation_tools
from backend.agents.tools.contained_operations import contained_operation_tools
from backend.agents.tools.evidence_retrieval import evidence_retrieval_tools
from backend.agents.tools.generated_assets import generated_asset_tools


def build_crash_triage_agent(model: str = "gpt-5.6-luna") -> Agent:
    """Return a worker that interprets one deterministically processed crash group."""
    return Agent(
        name="Crash triage specialist", instructions=CRASH_TRIAGE_PROMPT, model=model,
        model_settings=ModelSettings(parallel_tool_calls=True), output_type=TriageResult,
        tools=[
            *code_navigation_tools(), *evidence_retrieval_tools(), WebSearchTool(search_context_size="low"),
            *generated_asset_tools(), *contained_operation_tools(),
        ],
    )
