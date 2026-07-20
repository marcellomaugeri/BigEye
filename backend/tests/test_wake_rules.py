from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


NOW = datetime(2026, 7, 20, 9, tzinfo=UTC)


def snapshot(**changes):
    from backend.services.campaigns.wake_rules import CampaignSnapshot

    values = {
        "evidence_ids": ("campaign:3",),
        "coverage_path_counts": (10, 11, 12),
    }
    values.update(changes)
    return CampaignSnapshot(**values)


def test_time_slot_wakes_manager_without_stopping_campaign() -> None:
    from backend.services.campaigns.wake_rules import WakeEvaluator

    trigger = WakeEvaluator().evaluate(
        snapshot(), snapshot(review_due=True, next_review_after=NOW), NOW,
    )

    assert trigger is not None
    assert trigger.reason == "review window expired"
    assert trigger.stop_campaign is False
    assert trigger.evidence_ids == ("campaign:3",)


def test_plateau_requires_three_consecutive_equal_snapshots() -> None:
    from backend.services.campaigns.wake_rules import WakeEvaluator

    evaluator = WakeEvaluator()

    assert evaluator.evaluate(snapshot(), snapshot(coverage_path_counts=(10, 10)), NOW) is None
    trigger = evaluator.evaluate(snapshot(), snapshot(coverage_path_counts=(10, 10, 10)), NOW)

    assert trigger is not None
    assert trigger.reason == "coverage plateau across three snapshots"
    assert trigger.stop_campaign is False


@pytest.mark.parametrize(
    ("changes", "reason", "stop_campaign"),
    [
        ({"initial_supervision_complete": True}, "initial supervision completed", False),
        ({"irrelevant_project_coverage": True}, "coverage does not reach relevant project code", True),
        ({"corpus_opportunity": True}, "validated corpus opportunity", False),
        ({"replayed_crash": True}, "replayed crash ready for triage", False),
        ({"unhealthy_worker": True}, "campaign worker is unhealthy", True),
        ({"documented_configuration": True}, "documented configuration hypothesis", False),
        ({"system_gap": True}, "system campaign coverage gap", False),
        ({"overlap_candidate": True}, "overlap retirement candidate", False),
        ({"free_slots": 1}, "project has a free worker slot", False),
        ({"material_change": True}, "material asset or build change", False),
    ],
)
def test_each_material_condition_has_one_plain_text_trigger(changes, reason, stop_campaign) -> None:
    from backend.services.campaigns.wake_rules import WakeEvaluator

    trigger = WakeEvaluator().evaluate(snapshot(), snapshot(**changes), NOW)

    assert trigger is not None
    assert trigger.reason == reason
    assert trigger.stop_campaign is stop_campaign


def test_initial_supervision_and_material_change_only_wake_on_transition() -> None:
    from backend.services.campaigns.wake_rules import WakeEvaluator

    evaluator = WakeEvaluator()

    assert evaluator.evaluate(
        snapshot(initial_supervision_complete=True),
        snapshot(initial_supervision_complete=True),
        NOW,
    ) is None
    assert evaluator.evaluate(
        snapshot(material_change=True), snapshot(material_change=True), NOW,
    ) is None


def test_deadline_is_derived_from_aware_time_without_a_polling_flag() -> None:
    from backend.services.campaigns.wake_rules import WakeEvaluator

    evaluator = WakeEvaluator()

    assert evaluator.evaluate(
        snapshot(), snapshot(next_review_after=NOW + timedelta(seconds=1)), NOW,
    ) is None
    trigger = evaluator.evaluate(
        snapshot(), snapshot(next_review_after=NOW - timedelta(seconds=1)), NOW,
    )
    assert trigger is not None and trigger.reason == "review window expired"


def test_unchanged_deadline_wakes_when_time_crosses_it() -> None:
    from backend.services.campaigns.wake_rules import WakeEvaluator

    deadline = NOW - timedelta(seconds=1)
    trigger = WakeEvaluator().evaluate(
        snapshot(next_review_after=deadline),
        snapshot(next_review_after=deadline),
        NOW,
    )

    assert trigger is not None and trigger.reason == "review window expired"


def test_healthy_growing_campaign_has_no_trigger() -> None:
    from backend.services.campaigns.wake_rules import WakeEvaluator

    assert WakeEvaluator().evaluate(snapshot(), snapshot(coverage_path_counts=(12, 13, 14)), NOW) is None


def test_snapshot_rejects_blank_or_duplicate_evidence_and_naive_deadlines() -> None:
    from backend.services.campaigns.wake_rules import CampaignSnapshot

    with pytest.raises(ValueError, match="evidence"):
        CampaignSnapshot(evidence_ids=("",))
    with pytest.raises(ValueError, match="evidence"):
        CampaignSnapshot(evidence_ids=("same", "same"))
    with pytest.raises(ValueError, match="timezone"):
        CampaignSnapshot(next_review_after=datetime(2026, 7, 20))
