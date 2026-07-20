"""Deterministic facts that justify one bounded manager review."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ReviewTrigger:
    """One plain-language reason to ask the project manager for a decision."""

    reason: str
    evidence_ids: tuple[str, ...]
    stop_campaign: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("review trigger reason must be non-blank text")
        _validate_evidence(self.evidence_ids)
        if type(self.stop_campaign) is not bool:
            raise ValueError("review trigger stop decision must be boolean")


@dataclass(frozen=True)
class CampaignSnapshot:
    """Application-owned campaign facts; no scheduling decision is stored here."""

    evidence_ids: tuple[str, ...] = ()
    coverage_path_counts: tuple[int, ...] = ()
    active_workers: int = 0
    initial_supervision_complete: bool = False
    review_due: bool = False
    next_review_after: datetime | None = None
    manager_wake_at: datetime | None = None
    irrelevant_project_coverage: bool = False
    corpus_opportunity: bool = False
    replayed_crash: bool = False
    unhealthy_worker: bool = False
    documented_configuration: bool = False
    system_gap: bool = False
    overlap_candidate: bool = False
    free_slots: int = 0
    material_change: bool = False

    def __post_init__(self) -> None:
        _validate_evidence(self.evidence_ids)
        if (
            not isinstance(self.coverage_path_counts, tuple)
            or any(type(value) is not int or value < 0 for value in self.coverage_path_counts)
        ):
            raise ValueError("coverage path counts must be non-negative integers")
        if type(self.active_workers) is not int or self.active_workers < 0:
            raise ValueError("active worker count must be a non-negative integer")
        if type(self.free_slots) is not int or self.free_slots < 0:
            raise ValueError("free slot count must be a non-negative integer")
        for name in (
            "initial_supervision_complete", "review_due", "irrelevant_project_coverage",
            "corpus_opportunity", "replayed_crash", "unhealthy_worker",
            "documented_configuration", "system_gap", "overlap_candidate", "material_change",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name.replace('_', ' ')} must be boolean")
        for deadline in (self.next_review_after, self.manager_wake_at):
            if deadline is not None and deadline.tzinfo is None:
                raise ValueError("next review deadline must include a timezone")


def _validate_evidence(evidence_ids: tuple[str, ...]) -> None:
    if (
        not isinstance(evidence_ids, tuple)
        or len(evidence_ids) != len(set(evidence_ids))
        or any(not isinstance(value, str) or not value.strip() for value in evidence_ids)
    ):
        raise ValueError("review evidence identifiers must be unique non-blank text")


class WakeEvaluator:
    """Choose the highest-priority new condition without invoking a model."""

    _CONDITIONS = (
        ("unhealthy_worker", "campaign worker is unhealthy", True),
        ("replayed_crash", "replayed crash ready for triage", False),
        ("irrelevant_project_coverage", "coverage does not reach relevant project code", True),
        ("initial_supervision_complete", "initial supervision completed", False),
        ("corpus_opportunity", "validated corpus opportunity", False),
        ("documented_configuration", "documented configuration hypothesis", False),
        ("system_gap", "system campaign coverage gap", False),
        ("overlap_candidate", "overlap retirement candidate", False),
        ("material_change", "material asset or build change", False),
    )

    def evaluate(
        self,
        previous: CampaignSnapshot | None,
        current: CampaignSnapshot,
        now: datetime,
    ) -> ReviewTrigger | None:
        if previous is not None and not isinstance(previous, CampaignSnapshot):
            raise TypeError("previous campaign observation must be a CampaignSnapshot")
        if not isinstance(current, CampaignSnapshot):
            raise TypeError("current campaign observation must be a CampaignSnapshot")
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("wake evaluation time must include a timezone")

        for attribute, reason, stop_campaign in self._CONDITIONS:
            if getattr(current, attribute) and not bool(getattr(previous, attribute, False)):
                return ReviewTrigger(reason, current.evidence_ids, stop_campaign)

        deadline_due = current.review_due or any(
            deadline is not None and deadline <= now
            for deadline in (current.next_review_after, current.manager_wake_at)
        )
        previous_due = bool(getattr(previous, "review_due", False))
        if deadline_due and not previous_due:
            return ReviewTrigger("review window expired", current.evidence_ids)

        history = current.coverage_path_counts
        plateau = len(history) >= 3 and len(set(history[-3:])) == 1
        previous_history = previous.coverage_path_counts if previous is not None else ()
        previous_plateau = len(previous_history) >= 3 and len(set(previous_history[-3:])) == 1
        if plateau and not previous_plateau:
            return ReviewTrigger("coverage plateau across three snapshots", current.evidence_ids)

        previous_slots = previous.free_slots if previous is not None else 0
        if current.free_slots > 0 and previous_slots == 0:
            return ReviewTrigger("project has a free worker slot", current.evidence_ids)
        return None
