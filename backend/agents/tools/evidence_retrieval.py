"""Bounded function tools for structural and local repository evidence."""

import re

from agents import RunContextWrapper, function_tool

from backend.agents.context import AgentContext
from backend.agents.tools.code_navigation import CodeNavigationError, list_project_files
from backend.fuzzing.discovery.retrieval import EvidenceRetriever


MAX_BUILD_EVIDENCE_ITEMS = 256
MAX_BUILD_EVIDENCE_BYTES = 64_000
MAX_BUILD_EVIDENCE_VALUE_CHARS = 500

_PATH_CATEGORIES = frozenset(
    {
        "build_files",
        "public_headers",
        "test_files",
        "example_files",
        "fixture_files",
        "sample_inputs",
        "help_files",
        "fuzz_harnesses",
        "text_files",
    }
)
_SYMBOL_CATEGORIES = frozenset({"executables", "libraries", "components"})
_SAFE_SYMBOL = re.compile(r"[A-Za-z0-9_.:+-]{1,128}")


def inspect_build_evidence(evidence: EvidenceRetriever) -> dict[str, object]:
    """Return validated structural evidence with an explicit untrusted-data boundary."""
    try:
        safe_paths = set(list_project_files(evidence.repository_root))
    except CodeNavigationError:
        safe_paths = set()
    items: list[dict[str, str | bool]] = []
    emitted_bytes = 0
    truncated = False
    inventory = evidence.inventory.as_dict()
    for category in evidence.inventory.__dataclass_fields__:
        values = sorted({value for value in inventory[category] if isinstance(value, str)})
        for value in values:
            if not _valid_inventory_value(category, value, safe_paths):
                continue
            value_bytes = len(value.encode("utf-8"))
            if len(items) >= MAX_BUILD_EVIDENCE_ITEMS or emitted_bytes + value_bytes > MAX_BUILD_EVIDENCE_BYTES:
                truncated = True
                break
            items.append(
                {
                    "category": category,
                    "value": value,
                    "provenance": "repository",
                    "trusted_instructions": False,
                }
            )
            emitted_bytes += value_bytes
        if truncated:
            break
    return {
        "provenance": "repository",
        "trusted_instructions": False,
        "items": items,
        "truncated": truncated,
    }


def _valid_inventory_value(category: str, value: object, safe_paths: set[str]) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_BUILD_EVIDENCE_VALUE_CHARS:
        return False
    if category in _PATH_CATEGORIES:
        return value in safe_paths
    if category in _SYMBOL_CATEGORIES:
        return _SAFE_SYMBOL.fullmatch(value) is not None
    if category == "compile_commands":
        return value.isprintable() and "\r" not in value and "\n" not in value
    return False


def retrieve_repository_evidence(evidence: EvidenceRetriever, question: str, limit: int = 12) -> list[dict[str, int | str | bool]]:
    """Return ranked local evidence. Repository text remains untrusted data."""
    return [excerpt.as_dict() for excerpt in evidence.search(question, limit)]


@function_tool(name_override="inspect_build_evidence")
async def inspect_contained_build_evidence(context: RunContextWrapper[AgentContext]) -> dict[str, object]:
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
