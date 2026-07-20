from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


def run(awaitable):
    return asyncio.run(awaitable)


def checkpoint(identity: str, lines, functions=(("a.c", "parse"),), marginal_lines=()):
    from backend.fuzzing.coverage.overlap import CleanCoverageCheckpoint

    return CleanCoverageCheckpoint(
        evidence_id=identity,
        reached_lines=frozenset(lines),
        reached_functions=frozenset(functions),
        recent_marginal_lines=frozenset(marginal_lines),
    )


def history(
    campaign_id: int,
    strategy_asset_id: int,
    checkpoints,
    *,
    crashes=(),
    purpose=None,
    commit="a" * 40,
    project_id=7,
    compatibility_group_id="c" * 64,
):
    from backend.fuzzing.coverage.overlap import CampaignCoverageHistory

    return CampaignCoverageHistory(
        campaign_id=campaign_id,
        project_id=project_id,
        strategy_asset_id=strategy_asset_id,
        commit_sha=commit,
        compatibility_group_id=compatibility_group_id,
        checkpoints=tuple(checkpoints),
        crash_group_ids=frozenset(crashes),
        configuration_purpose=purpose,
    )


def redundant_for_two_checkpoints(*, unique_crashes=0, purpose=None, marginal_lines=()):
    candidate = history(
        9,
        90,
        (
            checkpoint("candidate:1", {("a.c", 10)}),
            checkpoint("candidate:2", {("a.c", 10)}, marginal_lines=marginal_lines),
        ),
        crashes=tuple(f"crash:{number}" for number in range(unique_crashes)),
        purpose=purpose,
    )
    retained = history(
        4,
        40,
        (
            checkpoint("retained:1", {("a.c", 10), ("a.c", 11)}),
            checkpoint("retained:2", {("a.c", 10), ("a.c", 11)}),
        ),
    )
    return (candidate, retained)


def test_subset_requires_two_checkpoints_and_no_unique_crash() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    analyzer = OverlapAnalyzer()
    candidate = analyzer.compare(redundant_for_two_checkpoints(unique_crashes=0))

    assert candidate[0].reversible is True
    assert candidate[0].campaign_id == 9
    assert candidate[0].retained_campaign_id == 4
    assert analyzer.compare(redundant_for_two_checkpoints(unique_crashes=1)) == []


@pytest.mark.parametrize("crash_groups", [["crash:known"], frozenset({"crash:known"})])
def test_crash_group_collections_are_normalized_before_comparison(crash_groups) -> None:
    from backend.fuzzing.coverage.overlap import CampaignCoverageHistory, OverlapAnalyzer

    candidate_checkpoints = (
        checkpoint("candidate:1", {("a.c", 10)}),
        checkpoint("candidate:2", {("a.c", 10)}),
    )
    candidate = CampaignCoverageHistory(
        campaign_id=9,
        project_id=7,
        strategy_asset_id=90,
        commit_sha="a" * 40,
        compatibility_group_id="c" * 64,
        checkpoints=candidate_checkpoints,
        crash_group_ids=crash_groups,
    )
    retained = history(
        4,
        40,
        (
            checkpoint("retained:1", {("a.c", 10), ("a.c", 11)}),
            checkpoint("retained:2", {("a.c", 10), ("a.c", 11)}),
        ),
        crashes=("crash:known",),
    )

    assert candidate.crash_group_ids == frozenset({"crash:known"})
    assert OverlapAnalyzer().compare((candidate, retained))[0].campaign_id == 9


def test_one_subset_checkpoint_is_not_enough() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    candidate, retained = redundant_for_two_checkpoints()
    one_checkpoint = history(
        candidate.campaign_id,
        candidate.strategy_asset_id,
        candidate.checkpoints[-1:],
    )

    assert OverlapAnalyzer().compare((one_checkpoint, retained)) == []


@pytest.mark.parametrize(
    "changes",
    [
        {"purpose": "encrypted protocol"},
        {"marginal_lines": (("a.c", 12),)},
    ],
)
def test_unique_configuration_purpose_or_recent_marginal_line_blocks_retirement(changes) -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    assert OverlapAnalyzer().compare(redundant_for_two_checkpoints(**changes)) == []


def test_different_commit_is_never_compared() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    candidate, retained = redundant_for_two_checkpoints()
    other_commit = history(
        retained.campaign_id,
        retained.strategy_asset_id,
        retained.checkpoints,
        commit="b" * 40,
    )

    assert OverlapAnalyzer().compare((candidate, other_commit)) == []


def test_different_project_is_never_compared_even_at_the_same_commit() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    candidate, retained = redundant_for_two_checkpoints()
    other_project = history(
        retained.campaign_id,
        retained.strategy_asset_id,
        retained.checkpoints,
        project_id=8,
    )

    assert OverlapAnalyzer().compare((candidate, other_project)) == []


def test_unrelated_target_contract_is_never_compared() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    candidate, retained = redundant_for_two_checkpoints()
    unrelated_target = history(
        retained.campaign_id,
        retained.strategy_asset_id,
        retained.checkpoints,
        compatibility_group_id="d" * 64,
    )

    assert OverlapAnalyzer().compare((candidate, unrelated_target)) == []


def test_equal_coverage_retains_lower_campaign_id_once() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    first = history(4, 40, (
        checkpoint("first:1", {("a.c", 10)}),
        checkpoint("first:2", {("a.c", 10)}),
    ))
    second = history(9, 90, (
        checkpoint("second:1", {("a.c", 10)}),
        checkpoint("second:2", {("a.c", 10)}),
    ))

    candidates = OverlapAnalyzer().compare((second, first))

    assert [(item.campaign_id, item.retained_campaign_id) for item in candidates] == [(9, 4)]


def test_candidate_contains_reviewable_evidence_and_preserves_strategy_identity() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    candidate = OverlapAnalyzer().compare(redundant_for_two_checkpoints())[0]

    assert candidate.strategy_asset_id == 90
    assert candidate.retained_strategy_asset_id == 40
    assert candidate.evidence_ids == (
        "candidate:1", "retained:1", "candidate:2", "retained:2",
    )
    assert candidate.reason == "clean coverage remained a subset for two consecutive checkpoints"


def test_functions_must_also_remain_a_subset() -> None:
    from backend.fuzzing.coverage.overlap import OverlapAnalyzer

    candidate, retained = redundant_for_two_checkpoints()
    candidate_with_unique_function = history(9, 90, (
        checkpoint("candidate:1", {("a.c", 10)}, functions=(("a.c", "parse"), ("a.c", "decode"))),
        checkpoint("candidate:2", {("a.c", 10)}, functions=(("a.c", "parse"), ("a.c", "decode"))),
    ))

    assert OverlapAnalyzer().compare((candidate_with_unique_function, retained)) == []


def test_invalid_or_unbounded_history_is_rejected() -> None:
    from backend.fuzzing.coverage.overlap import CampaignCoverageHistory, OverlapAnalyzer

    with pytest.raises(ValueError, match="campaign history"):
        CampaignCoverageHistory(
            campaign_id=0,
            project_id=7,
            strategy_asset_id=1,
            commit_sha="a" * 40,
            compatibility_group_id="c" * 64,
            checkpoints=(),
        )

    histories = tuple(
        history(number, number, (
            checkpoint(f"{number}:1", {("a.c", number)}),
            checkpoint(f"{number}:2", {("a.c", number)}),
        ))
        for number in range(1, 258)
    )
    with pytest.raises(ValueError, match="campaign histories"):
        OverlapAnalyzer().compare(histories)


def test_retirement_candidate_must_be_reversible_and_project_bound() -> None:
    from backend.fuzzing.coverage.overlap import RetirementCandidate

    with pytest.raises(ValueError, match="retirement candidate"):
        RetirementCandidate(
            project_id=7,
            campaign_id=9,
            strategy_asset_id=90,
            retained_campaign_id=4,
            retained_strategy_asset_id=40,
            evidence_ids=("candidate:1", "retained:1", "candidate:2", "retained:2"),
            reason="clean coverage remained a subset for two consecutive checkpoints",
            reversible=False,
        )


def test_target_lifecycle_requires_complete_never_functional_absence_evidence() -> None:
    from backend.services.campaigns.target_lifecycle import TargetLifecycleService

    assets = SimpleNamespace(deletion_evidence=AsyncMock(return_value={
        "complete": True,
        "asset_kind": "harness", "asset_content_hash": "a" * 64,
        "probe_attempts": 2, "failed_probe_attempts": 2, "attempt_revision": 12,
        "successful_probe": False,
        "accepted_campaign": False,
        "useful_clean_coverage": False,
        "finding_dependencies": (),
        "evidence_ids": ("asset:90", "campaign-absence:90", "coverage-absence:90"),
    }))
    service = TargetLifecycleService(assets=assets, campaigns=SimpleNamespace())

    action = run(service.never_functional_deletion(7, 90))

    assert action is not None
    assert action.kind == "delete-never-functional"
    assert action.asset_ids == (90,)
    for missing in (
        {"complete": False}, {"successful_probe": True}, {"accepted_campaign": True},
        {"useful_clean_coverage": True}, {"finding_dependencies": (11,)},
        {"probe_attempts": 0, "failed_probe_attempts": 0},
        {"asset_kind": "configuration"},
    ):
        assets.deletion_evidence.return_value = {
            "complete": True,
            "asset_kind": "harness", "asset_content_hash": "a" * 64,
            "probe_attempts": 2, "failed_probe_attempts": 2, "attempt_revision": 12,
            "successful_probe": False,
            "accepted_campaign": False,
            "useful_clean_coverage": False,
            "finding_dependencies": (),
            "evidence_ids": ("complete:90",),
        } | missing
        assert run(service.never_functional_deletion(7, 90)) is None


def test_healthy_unhelpful_target_is_unscheduled_and_preserved() -> None:
    from backend.services.campaigns.target_lifecycle import TargetLifecycleService

    campaigns = SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(
        id=9, project_id=7, target_asset_id=90, stopped_at=None, error=None,
    )))
    assets = SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(
        id=90, project_id=7, kind="configuration", content_hash="a" * 64,
        validated_at=object(), error=None,
    )))
    service = TargetLifecycleService(assets=assets, campaigns=campaigns)

    action = run(service.unschedule(7, 9, "healthy but no recent marginal coverage"))

    assert action.kind == "unschedule"
    assert action.campaign_id == 9
    assert action.asset_ids == ()
    assert action.reversible is True


def test_overlap_deletion_requires_two_clean_checkpoints_and_healthy_retained_strategy() -> None:
    from backend.services.campaigns.target_lifecycle import TargetLifecycleService

    campaigns = SimpleNamespace(overlap_deletion_evidence=AsyncMock(return_value={
        "complete": True,
        "project_id": 7,
        "campaign_id": 9,
        "strategy_asset_id": 90,
        "retained_campaign_id": 4,
        "retained_strategy_asset_id": 40,
        "comparable_clean_checkpoints": 2,
        "fully_subsumed": True,
        "unique_crash_groups": (),
        "retained_healthy": True,
        "finding_bundle_requests": (),
        "evidence_ids": ("candidate:1", "retained:1", "candidate:2", "retained:2"),
    }))
    assets = SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(
        id=90, project_id=7, kind="configuration", content_hash="a" * 64,
        validated_at=object(), error=None,
    )))
    service = TargetLifecycleService(assets=assets, campaigns=campaigns)

    assert run(service.overlapping_deletion(7, 9)).kind == "delete-overlapping"
    for unsafe in (
        {"comparable_clean_checkpoints": 1}, {"fully_subsumed": False},
        {"unique_crash_groups": ("crash:unique",)}, {"retained_healthy": False},
        {"complete": False},
    ):
        campaigns.overlap_deletion_evidence.return_value = {
            **campaigns.overlap_deletion_evidence.return_value,
            **unsafe,
        }
        assert run(service.overlapping_deletion(7, 9)) is None
