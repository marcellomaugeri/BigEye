"""Application-owned context supplied to bounded repository tools."""

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever


@dataclass(frozen=True)
class AgentContext:
    project_id: int
    commit_sha: str = "unresolved"
    repository_root: Path = Path(".")
    generated_assets_root: Path | None = None
    evidence: "EvidenceRetriever | None" = None

    def __post_init__(self) -> None:
        repository_root = Path(self.repository_root)
        if repository_root.is_symlink():
            raise ValueError("repository root must not be a symlink")
        repository_root = repository_root.resolve(strict=True)
        if not repository_root.is_dir():
            raise ValueError("repository root must be a directory")
        if not isinstance(self.commit_sha, str) or not self.commit_sha:
            raise ValueError("commit SHA is required")
        assets_root = self.generated_assets_root
        if assets_root is None:
            assets_root = repository_root.parent / "generated-assets"
        assets_root = Path(assets_root)
        if assets_root.is_symlink():
            raise ValueError("generated assets root must not be a symlink")
        from backend.fuzzing.discovery.retrieval import EvidenceRetriever

        evidence = self.evidence or EvidenceRetriever(repository_root)
        if evidence.repository_root != repository_root:
            raise ValueError("evidence must belong to the selected repository")
        object.__setattr__(self, "repository_root", repository_root)
        object.__setattr__(self, "generated_assets_root", assets_root.resolve())
        object.__setattr__(self, "evidence", evidence)
