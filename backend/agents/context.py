"""Application-owned context supplied to bounded repository tools."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever


@dataclass(frozen=True)
class AgentContext:
    project_id: int
    commit_sha: str
    repository_root: Path
    generated_assets_root: Path
    evidence: "EvidenceRetriever"

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, int) or isinstance(self.project_id, bool) or self.project_id < 1:
            raise ValueError("project ID must be a positive integer")
        if not isinstance(self.commit_sha, str) or re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", self.commit_sha) is None:
            raise ValueError("commit SHA must be an exact resolved Git object ID")
        repository_path = Path(os.path.abspath(os.fspath(self.repository_root)))
        if repository_path.is_symlink():
            raise ValueError("repository root must not be a symlink")
        repository_root = repository_path.resolve(strict=True)
        if not repository_root.is_dir():
            raise ValueError("repository root must be a directory")
        project_root = repository_root.parent
        assets_path = Path(os.path.abspath(os.fspath(self.generated_assets_root)))
        try:
            lexical_relative = assets_path.relative_to(project_root)
        except ValueError as error:
            raise ValueError("generated assets root must stay inside the project root") from error
        if not lexical_relative.parts or self._has_symlink_component(project_root, lexical_relative):
            raise ValueError("generated assets root must not use symlink ancestors")
        assets_root = assets_path.resolve(strict=False)
        try:
            resolved_relative = assets_root.relative_to(project_root)
        except ValueError as error:
            raise ValueError("generated assets root must stay inside the project root") from error
        if not resolved_relative.parts or assets_root == repository_root or repository_root in assets_root.parents:
            raise ValueError("generated assets root must be outside the immutable repository")
        if assets_root.exists() and not assets_root.is_dir():
            raise ValueError("generated assets root must be a directory")
        from backend.fuzzing.discovery.retrieval import EvidenceRetriever

        if not isinstance(self.evidence, EvidenceRetriever) or self.evidence.repository_root != repository_root:
            raise ValueError("evidence must belong to the selected repository")
        object.__setattr__(self, "repository_root", repository_root)
        object.__setattr__(self, "generated_assets_root", assets_root)

    @staticmethod
    def _has_symlink_component(project_root: Path, relative_path: Path) -> bool:
        current = project_root
        for part in relative_path.parts:
            current /= part
            if current.is_symlink():
                return True
        return False
