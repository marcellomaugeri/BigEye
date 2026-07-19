"""Bounded function tools for structural and local repository evidence."""

from agents import RunContextWrapper, function_tool

from backend.agents.context import AgentContext
from backend.fuzzing.discovery.retrieval import EvidenceRetriever


def inspect_build_evidence(evidence: EvidenceRetriever) -> dict[str, list[str]]:
    """Return the pre-collected, bounded structural evidence inventory."""
    return evidence.inventory.as_dict()


def retrieve_repository_evidence(evidence: EvidenceRetriever, question: str, limit: int = 12) -> list[dict[str, int | str | bool]]:
    """Return ranked local evidence. Repository text remains untrusted data."""
    return [excerpt.as_dict() for excerpt in evidence.search(question, limit)]


@function_tool(name_override="inspect_build_evidence")
async def inspect_contained_build_evidence(context: RunContextWrapper[AgentContext]) -> dict[str, list[str]]:
    """Inspect bounded build, symbol, test, sample, and harness evidence only."""
    return inspect_build_evidence(context.context.evidence)


@function_tool(name_override="retrieve_repository_evidence")
async def retrieve_contained_repository_evidence(
    context: RunContextWrapper[AgentContext], question: str, limit: int = 12
) -> list[dict[str, int | str | bool]]:
    """Retrieve ranked local evidence for one narrow question without executing repository content."""
    return retrieve_repository_evidence(context.context.evidence, question, limit)


def evidence_retrieval_tools() -> list:
    return [inspect_contained_build_evidence, retrieve_contained_repository_evidence]
