"""Application-owned context supplied to repository-analysis tools."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentContext:
    project_id: int
    repository_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "repository_root", self.repository_root.resolve(strict=True))
