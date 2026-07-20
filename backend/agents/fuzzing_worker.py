"""One normal Agents SDK worker with a dynamically supplied fuzzing assignment."""

from agents import Agent, ModelSettings

from backend.agents.context import AgentContext
from backend.agents.outputs.fuzzing_worker_result import FuzzingWorkerResult
from backend.agents.prompts.fuzzing_worker import FUZZING_WORKER_PROMPT
from backend.agents.tools.code_navigation import code_navigation_tools
from backend.agents.tools.contained_operations import contained_operation_tools
from backend.agents.tools.evidence_retrieval import evidence_retrieval_tools
from backend.agents.tools.generated_assets import generated_asset_tools
from backend.agents.tools.web_research import official_web_search_tool


def build_fuzzing_worker(
    model: str = "gpt-5.6-luna",
    web_domains: frozenset[str] = frozenset({"aflplus.plus", "llvm.org"}),
) -> Agent[AgentContext]:
    """Build the non-recursive worker used for every bounded fuzzing assignment."""
    return Agent(
        name="Fuzzing worker",
        instructions=FUZZING_WORKER_PROMPT,
        model=model,
        model_settings=ModelSettings(parallel_tool_calls=True),
        output_type=FuzzingWorkerResult,
        tools=[
            *code_navigation_tools(),
            *evidence_retrieval_tools(),
            official_web_search_tool(web_domains),
            *generated_asset_tools(),
            *contained_operation_tools(),
        ],
    )
