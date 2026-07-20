import os
import asyncio
from pathlib import Path

import pytest

from backend.agents.context import AgentContext
from backend.agents.manager import CampaignManager
from backend.fuzzing.discovery.retrieval import EvidenceRetriever
from backend.services.observability.event_store import ProjectEventStore


@pytest.mark.skipif(os.getenv("BIGEYE_LIVE_OPENAI") != "1", reason="live OpenAI smoke is opt-in")
def test_live_manager_delegates_to_one_bounded_worker_and_records_debug(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "CMakeLists.txt").write_text("add_executable(parser main.c)\n")
    (repository / "main.c").write_text(
        "#include <stdio.h>\nint main(void) { unsigned char b[8]; return fread(b, 1, sizeof b, stdin) == 0; }\n"
    )
    retriever = EvidenceRetriever(repository)
    excerpt = retriever.search("executable parser", 1)[0]
    context = AgentContext(1, "a" * 40, repository, tmp_path / "assets", retriever)
    store = ProjectEventStore(tmp_path)

    review = asyncio.run(CampaignManager(store).review(
        context, evidence=[excerpt.as_dict()],
        reason="Call run_fuzzing_worker once, then choose the smallest deterministic parser probe.",
    ))

    assert review.decision.decision
    debug = asyncio.run(store.read(1, "debug", -1, 100))
    assert any(event.payload.get("event") == "tool.start" for event in debug)
