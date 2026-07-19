"""Read the repository analysis artifact when later work has produced it."""

from pathlib import Path

from backend.services.clone_repository import contained_path
from backend.services.run_project_backbone import AnalysisNotReady


class AnalysisReader:
    def __init__(self, workspace: Path):
        self._workspace = workspace

    async def get(self, project_id: int) -> str:
        path = contained_path(self._workspace, "projects", str(project_id), "analysis", "repository.md")
        if path.is_symlink() or not path.is_file():
            raise AnalysisNotReady()
        return path.read_text(encoding="utf-8")
