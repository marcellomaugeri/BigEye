"""Durable identity for one processed campaign artifact."""

from dataclasses import dataclass
import re


_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ProcessedCampaignArtifact:
    project_id: int
    campaign_id: int
    kind: str
    content_sha256: str
    accepted: bool
    evidence_id: str
    reason: str
    durable_relative_path: str | None

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not int or self.project_id <= 0
            or type(self.campaign_id) is not int or self.campaign_id <= 0
            or self.kind not in {"corpus", "crash", "corpus-minimisation"}
            or not isinstance(self.content_sha256, str)
            or _SHA256.fullmatch(self.content_sha256) is None
            or type(self.accepted) is not bool
            or not _bounded(self.evidence_id, 256)
            or not _bounded(self.reason, 2_000)
            or self.durable_relative_path is not None
            and not _bounded(self.durable_relative_path, 2_000)
        ):
            raise ValueError("processed campaign artifact is invalid")


def _bounded(value, limit: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit and "\x00" not in value
