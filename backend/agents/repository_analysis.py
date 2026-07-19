"""The short-lived worker that can inspect one repository."""

from agents import Agent

from backend.agents.prompts.repository_analysis import REPOSITORY_ANALYSIS_PROMPT
from backend.agents.tools.code_navigation import code_navigation_tools
from backend.agents.tools.evidence_retrieval import evidence_retrieval_tools


def build_repository_analysis_agent(model: str = "gpt-5.6-luna") -> Agent:
    """Construct a worker with only deterministic code-navigation tools."""
    return Agent(
        name="Repository analysis worker",
        instructions=REPOSITORY_ANALYSIS_PROMPT,
        model=model,
        tools=[*code_navigation_tools(), *evidence_retrieval_tools()],
    )
