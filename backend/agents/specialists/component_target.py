"""Component-level target specialist."""

from agents import Agent, ModelSettings, WebSearchTool

from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.prompts.component_target import COMPONENT_TARGET_PROMPT
from backend.agents.tools.code_navigation import code_navigation_tools
from backend.agents.tools.contained_operations import contained_operation_tools
from backend.agents.tools.evidence_retrieval import evidence_retrieval_tools
from backend.agents.tools.generated_assets import generated_asset_tools


def build_component_target_agent(model: str = "gpt-5.6-luna") -> Agent:
    """Return a worker that prepares one in-process component target."""
    return Agent(
        name="Component target specialist", instructions=COMPONENT_TARGET_PROMPT, model=model,
        model_settings=ModelSettings(parallel_tool_calls=True), output_type=TargetProposal,
        tools=[
            *code_navigation_tools(), *evidence_retrieval_tools(), WebSearchTool(search_context_size="low"),
            *generated_asset_tools(), *contained_operation_tools(),
        ],
    )
