"""Expose the repository-analysis worker to the manager as one agent tool."""

from agents import Agent


def repository_analysis_tool(worker: Agent):
    """Return the worker strictly through the SDK's Agent.as_tool boundary."""
    return worker.as_tool(
        tool_name="analyse_repository",
        tool_description="Inspect the selected repository and return a cited, evidence-based analysis.",
    )
