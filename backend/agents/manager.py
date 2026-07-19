"""The manager delegates repository inspection to exactly one worker tool."""

from agents import Agent

from backend.agents.prompts.manager import MANAGER_PROMPT


def build_manager_agent(repository_analysis_worker_tool) -> Agent:
    """Construct the Terra manager without direct repository access."""
    return Agent(
        name="Repository analysis manager",
        instructions=MANAGER_PROMPT,
        model="gpt-5.6-terra",
        tools=[repository_analysis_worker_tool],
    )
