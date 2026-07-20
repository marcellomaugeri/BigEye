"""Conservative clean-coverage overlap analysis for manager review."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath


_COMMIT = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_MAX_CAMPAIGNS = 256
_MAX_CHECKPOINTS = 64
_MAX_LINES = 100_000
_MAX_FUNCTIONS = 20_000
_MAX_CRASH_GROUPS = 10_000


@dataclass(frozen=True)
class CleanCoverageCheckpoint:
    evidence_id: str
    reached_lines: frozenset[tuple[str, int]]
    reached_functions: frozenset[tuple[str, str]]
    recent_marginal_lines: frozenset[tuple[str, int]] = frozenset()

    def __post_init__(self) -> None:
        if not _bounded_text(self.evidence_id, 256):
            raise ValueError("coverage checkpoint evidence ID is invalid")
        object.__setattr__(self, "reached_lines", _lines(self.reached_lines, _MAX_LINES))
        object.__setattr__(self, "recent_marginal_lines", _lines(self.recent_marginal_lines, _MAX_LINES))
        if len(self.reached_functions) > _MAX_FUNCTIONS:
            raise ValueError("coverage checkpoint functions exceed their bound")
        functions: set[tuple[str, str]] = set()
        for item in self.reached_functions:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError("coverage checkpoint function is invalid")
            path, name = item
            if not _bounded_text(name, 1_024):
                raise ValueError("coverage checkpoint function is invalid")
            functions.add((_path(path), name))
        object.__setattr__(self, "reached_functions", frozenset(functions))


@dataclass(frozen=True)
class CampaignCoverageHistory:
    project_id: int
    campaign_id: int
    strategy_asset_id: int
    commit_sha: str
    checkpoints: tuple[CleanCoverageCheckpoint, ...]
    crash_group_ids: frozenset[str] = frozenset()
    configuration_purpose: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not int
            or self.project_id <= 0
            or type(self.campaign_id) is not int
            or self.campaign_id <= 0
            or type(self.strategy_asset_id) is not int
            or self.strategy_asset_id <= 0
            or not isinstance(self.commit_sha, str)
            or _COMMIT.fullmatch(self.commit_sha) is None
            or not isinstance(self.checkpoints, tuple)
            or len(self.checkpoints) > _MAX_CHECKPOINTS
            or any(not isinstance(item, CleanCoverageCheckpoint) for item in self.checkpoints)
        ):
            raise ValueError("campaign history is invalid")
        object.__setattr__(self, "commit_sha", self.commit_sha.lower())
        if len(self.crash_group_ids) > _MAX_CRASH_GROUPS or any(
            not _bounded_text(identifier, 256) for identifier in self.crash_group_ids
        ):
            raise ValueError("campaign history crash groups are invalid")
        if self.configuration_purpose is not None and not _bounded_text(self.configuration_purpose, 1_024):
            raise ValueError("campaign history configuration purpose is invalid")
        if self.configuration_purpose is not None:
            object.__setattr__(self, "configuration_purpose", self.configuration_purpose.strip())


@dataclass(frozen=True)
class RetirementCandidate:
    project_id: int
    campaign_id: int
    strategy_asset_id: int
    retained_campaign_id: int
    retained_strategy_asset_id: int
    evidence_ids: tuple[str, ...]
    reason: str
    reversible: bool = True

    def __post_init__(self) -> None:
        identifiers = (
            self.project_id, self.campaign_id, self.strategy_asset_id,
            self.retained_campaign_id, self.retained_strategy_asset_id,
        )
        if (
            any(type(identifier) is not int or identifier <= 0 for identifier in identifiers)
            or self.campaign_id == self.retained_campaign_id
            or self.strategy_asset_id == self.retained_strategy_asset_id
            or not isinstance(self.evidence_ids, tuple)
            or not 1 <= len(self.evidence_ids) <= 8
            or len(self.evidence_ids) != len(set(self.evidence_ids))
            or any(not _bounded_text(identifier, 256) for identifier in self.evidence_ids)
            or not _bounded_text(self.reason, 1_024)
            or self.reversible is not True
        ):
            raise ValueError("retirement candidate is invalid")


class OverlapAnalyzer:
    """Return evidence for redundant workers; it never stops or deletes anything."""

    @staticmethod
    def compare(campaigns) -> list[RetirementCandidate]:
        if not isinstance(campaigns, (tuple, list)) or len(campaigns) > _MAX_CAMPAIGNS or any(
            not isinstance(campaign, CampaignCoverageHistory) for campaign in campaigns
        ):
            raise ValueError("campaign histories are invalid or exceed their bound")
        ordered = sorted(campaigns, key=lambda item: item.campaign_id)
        if len({item.campaign_id for item in ordered}) != len(ordered):
            raise ValueError("campaign histories contain duplicate campaign IDs")

        result: list[RetirementCandidate] = []
        already_retired: set[int] = set()
        for candidate in reversed(ordered):
            retained = next((
                other for other in ordered
                if other.campaign_id not in already_retired
                and _can_retain(candidate, other)
            ), None)
            if retained is None:
                continue
            candidate_checkpoints = candidate.checkpoints[-2:]
            retained_checkpoints = retained.checkpoints[-2:]
            result.append(RetirementCandidate(
                project_id=candidate.project_id,
                campaign_id=candidate.campaign_id,
                strategy_asset_id=candidate.strategy_asset_id,
                retained_campaign_id=retained.campaign_id,
                retained_strategy_asset_id=retained.strategy_asset_id,
                evidence_ids=tuple(
                    identifier
                    for pair in zip(candidate_checkpoints, retained_checkpoints, strict=True)
                    for identifier in (pair[0].evidence_id, pair[1].evidence_id)
                ),
                reason="clean coverage remained a subset for two consecutive checkpoints",
            ))
            already_retired.add(candidate.campaign_id)
        return sorted(result, key=lambda item: item.campaign_id)


def _can_retain(candidate: CampaignCoverageHistory, retained: CampaignCoverageHistory) -> bool:
    if (
        candidate.campaign_id == retained.campaign_id
        or candidate.project_id != retained.project_id
        or candidate.commit_sha != retained.commit_sha
    ):
        return False
    if len(candidate.checkpoints) < 2 or len(retained.checkpoints) < 2:
        return False
    if candidate.crash_group_ids - retained.crash_group_ids:
        return False
    if candidate.configuration_purpose is not None and candidate.configuration_purpose != retained.configuration_purpose:
        return False
    candidate_recent = candidate.checkpoints[-2:]
    retained_recent = retained.checkpoints[-2:]
    if any(checkpoint.recent_marginal_lines for checkpoint in candidate_recent):
        return False
    for candidate_checkpoint, retained_checkpoint in zip(candidate_recent, retained_recent, strict=True):
        if not candidate_checkpoint.reached_lines <= retained_checkpoint.reached_lines:
            return False
        if not candidate_checkpoint.reached_functions <= retained_checkpoint.reached_functions:
            return False
    if all(
        candidate_checkpoint.reached_lines == retained_checkpoint.reached_lines
        and candidate_checkpoint.reached_functions == retained_checkpoint.reached_functions
        for candidate_checkpoint, retained_checkpoint in zip(candidate_recent, retained_recent, strict=True)
    ):
        return candidate.campaign_id > retained.campaign_id
    return True


def _lines(values, limit: int) -> frozenset[tuple[str, int]]:
    if not isinstance(values, frozenset) or len(values) > limit:
        raise ValueError("coverage checkpoint lines are invalid or exceed their bound")
    lines: set[tuple[str, int]] = set()
    for item in values:
        if not isinstance(item, tuple) or len(item) != 2 or type(item[1]) is not int or item[1] <= 0:
            raise ValueError("coverage checkpoint line is invalid")
        lines.add((_path(item[0]), item[1]))
    return frozenset(lines)


def _path(value) -> str:
    if not _bounded_text(value, 4_096):
        raise ValueError("coverage source path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", "..", ".git"} for part in path.parts):
        raise ValueError("coverage source path must be repository-relative")
    return path.as_posix()


def _bounded_text(value, limit: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit
