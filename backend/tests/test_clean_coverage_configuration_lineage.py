"""Clean-build provenance for base and progressed campaign configurations."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.models.asset import CampaignAsset


NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


def _asset(asset_id: int, kind: str, parent_id: int | None = None) -> CampaignAsset:
    return CampaignAsset(
        id=asset_id,
        project_id=7,
        kind=kind,
        name=f"asset-{asset_id}",
        content_hash=f"{asset_id:064x}",
        parent_id=parent_id,
        created_at=NOW,
        validated_at=NOW,
        error=None,
    )


class _Assets:
    def __init__(self, *assets: CampaignAsset):
        self._assets = {asset.id: asset for asset in assets}

    async def get(self, asset_id: int):
        return self._assets.get(asset_id)


class _Checkouts:
    def __init__(self, root: Path):
        self._root = root

    async def resolve(self, project_id: int, commit_sha: str):
        return SimpleNamespace(project_id=project_id, commit_sha=commit_sha, root=self._root)


def _request(configuration_asset_id: int):
    return SimpleNamespace(
        project_id=7,
        commit_sha="a" * 40,
        campaign_id=9,
        strategy_asset_id=33,
        target_asset_id=31,
        configuration_asset_id=configuration_asset_id,
        coverage_asset_id=34,
        clean_image_id="sha256:" + "c" * 64,
        clean_content_hash="d" * 64,
        clean_parent_image_id="sha256:" + "e" * 64,
        replay_command=("/target", "{input}"),
        replay_environment=(),
    )


def _resolver(tmp_path: Path, configuration_asset_id: int, *lineage: CampaignAsset):
    from backend.fuzzing.coverage.replay_verifier import CleanCoverageTargetResolver

    repository = tmp_path / "repository"
    repository.mkdir(exist_ok=True)
    campaign = SimpleNamespace(
        id=9,
        project_id=7,
        target_asset_id=31,
        configuration_asset_id=configuration_asset_id,
    )
    campaigns = SimpleNamespace(get=lambda _campaign_id: _async_value(campaign))
    assets = _Assets(
        _asset(31, "target"),
        _asset(33, "strategy"),
        _asset(34, "coverage"),
        *lineage,
    )
    return CleanCoverageTargetResolver(_Checkouts(repository), campaigns, assets)


async def _async_value(value):
    return value


def test_progressed_configuration_resolves_reusable_base_clean_build(tmp_path: Path) -> None:
    resolver = _resolver(
        tmp_path,
        41,
        _asset(32, "configuration", 31),
        _asset(41, "configuration", 32),
    )

    target = run(resolver.resolve(_request(41)))

    assert target.configuration_asset_id == 41
    assert target.strategy_asset_id == 33
    assert target.clean_build_configuration_asset_id == 32


def test_base_configuration_remains_its_own_clean_build_identity(tmp_path: Path) -> None:
    resolver = _resolver(tmp_path, 32, _asset(32, "configuration", 31))

    target = run(resolver.resolve(_request(32)))

    assert target.configuration_asset_id == 32
    assert target.clean_build_configuration_asset_id == 32


@pytest.mark.parametrize(
    "configuration_asset_id,lineage",
    [
        (41, (_asset(41, "configuration", 42), _asset(42, "configuration", 41))),
        (41, (_asset(41, "configuration", 35), _asset(35, "coverage"))),
        (31, ()),
    ],
    ids=("cycle", "wrong-terminal-type", "target-used-as-configuration"),
)
def test_clean_build_configuration_rejects_invalid_lineage(
    tmp_path: Path,
    configuration_asset_id: int,
    lineage: tuple[CampaignAsset, ...],
) -> None:
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError

    resolver = _resolver(tmp_path, configuration_asset_id, *lineage)

    with pytest.raises(CoverageIntegrityError, match="configuration"):
        run(resolver.resolve(_request(configuration_asset_id)))
