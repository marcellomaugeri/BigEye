"""Campaign workflow entry points and the temporary backbone compatibility adapter."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from agents import Runner

from backend.agents.context import AgentContext
from backend.agents.manager import CampaignManager
from backend.fuzzing.discovery.retrieval import EvidenceRetriever


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class CampaignWorkflow(CampaignManager):
    """Named application boundary for ongoing campaign reviews."""


def _publish_initial_decision(workspace: Path, context: AgentContext, content: str) -> Path:
    workspace_root = Path(os.path.abspath(workspace)).resolve(strict=True)
    project_root = context.repository_root.parent
    try:
        relative = project_root.relative_to(workspace_root)
    except ValueError as error:
        raise ValueError("project workspace escaped the configured workspace") from error
    if relative.parts != ("projects", str(context.project_id)):
        raise ValueError("project workspace does not match the agent context")
    project_descriptor = os.open(project_root, _DIRECTORY_FLAGS)
    temporary_name = f".initial-campaign-{uuid4().hex}.tmp"
    temporary_created = False
    try:
        try:
            os.mkdir("analysis", mode=0o700, dir_fd=project_descriptor)
        except FileExistsError:
            pass
        analysis_descriptor = os.open("analysis", _DIRECTORY_FLAGS, dir_fd=project_descriptor)
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=analysis_descriptor,
            )
            temporary_created = True
            try:
                encoded = content.encode("utf-8")
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("initial campaign decision could not be written")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary_name, "repository.md", src_dir_fd=analysis_descriptor, dst_dir_fd=analysis_descriptor)
            temporary_created = False
            os.fsync(analysis_descriptor)
        finally:
            if temporary_created:
                try:
                    os.unlink(temporary_name, dir_fd=analysis_descriptor)
                except OSError:
                    pass
            os.close(analysis_descriptor)
    finally:
        os.close(project_descriptor)
    return project_root / "analysis" / "repository.md"


class RepositoryAnalysisWorkflow:
    """Keep the current backbone API while producing an initial campaign decision, not a generic scan."""

    def __init__(self, workspace: Path, runner=Runner.run, event_store=None):
        self._workspace = Path(workspace)
        self._manager = CampaignWorkflow(event_store, runner=runner)

    async def analyse(
        self, project_id: int, commit_sha: str, repository_root: Path, generated_assets_root: Path,
    ) -> Path:
        retriever = EvidenceRetriever(repository_root)
        context = AgentContext(project_id, commit_sha, repository_root, generated_assets_root, retriever)
        excerpts = retriever.search("build executable library input parser test example", 12)
        decision = await self._manager.review(
            context, [excerpt.as_dict() for excerpt in excerpts],
            "Choose the smallest evidence-backed initial fuzzing target and its deterministic probe.",
        )
        body = "# Initial campaign decision\n\n```json\n" + json.dumps(
            decision.model_dump(mode="json"), ensure_ascii=False, indent=2,
        ) + "\n```\n"
        return _publish_initial_decision(self._workspace, context, body)
