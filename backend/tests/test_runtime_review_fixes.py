"""Regression contracts for production campaign runtime review findings."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from backend.models.asset import CampaignAsset


NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


class _ReusableAssetStore:
    """Small content-addressed fake retaining the publisher's observable contract."""

    def __init__(self):
        self.assets: dict[tuple, CampaignAsset] = {}

    async def create_reusable(self, project_id, kind, name, files, parent_id):
        content = tuple(
            (file_name, Path(source).read_bytes())
            for file_name, source in sorted(files.items())
        )
        content_hash = sha256(b"\0".join(
            file_name.encode() + b"\0" + value for file_name, value in content
        )).hexdigest()
        key = (project_id, kind, name, content_hash, parent_id)
        asset = self.assets.get(key)
        if asset is None:
            asset = CampaignAsset(
                id=len(self.assets) + 100,
                project_id=project_id,
                kind=kind,
                name=name,
                content_hash=content_hash,
                parent_id=parent_id,
                created_at=NOW,
                validated_at=NOW,
                error=None,
            )
            self.assets[key] = asset
        return asset


def _record(*, suffix: str, action: str, arguments=(), environment=(), detail=None, dictionary=None):
    from backend.agents.outputs.campaign_review import ProgressionActionRecord

    return ProgressionActionRecord(
        action_id=f"campaign-progression:7:9:{suffix}",
        project_id=7,
        base_campaign_id=9,
        target_asset_id=31,
        action_name=action,
        evidence_ids=("evidence:source",),
        arguments=arguments,
        environment=environment,
        detail=detail,
        dictionary_content=dictionary,
    )


def test_progression_variants_publish_distinct_reusable_validated_assets(tmp_path: Path) -> None:
    from backend.services.campaigns.production_progression import ProgressionAssetPublisher

    repository = tmp_path / "workspace/projects/7/repository"
    repository.mkdir(parents=True)
    context = SimpleNamespace(
        project_id=7,
        repository_root=repository,
        generated_assets_root=repository.parent / "assets",
    )
    store = _ReusableAssetStore()
    publisher = ProgressionAssetPublisher(store)
    base_with_configuration = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
    )
    base_without_configuration = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=None,
    )
    records = (
        _record(
            suffix="dictionary", action="enable dictionary",
            dictionary='token_000="MAGIC"\n',
        ),
        _record(
            suffix="grammar", action="enable grammar mutator",
            environment=((
                "AFL_CUSTOM_MUTATOR_LIBRARY",
                "/usr/local/lib/afl/libgrammarmutator-json.so",
            ),),
        ),
        _record(
            suffix="argument", action="try configuration",
            arguments=("--encrypt",), detail="--encrypt",
        ),
        _record(
            suffix="environment", action="try configuration",
            arguments=("--protocol",), environment=(("PROTOCOL", "aux"),),
            detail="auxiliary protocol",
        ),
    )

    assets = [run(publisher.publish(context, base_with_configuration, item)) for item in records]
    reused = run(publisher.publish(context, base_with_configuration, records[0]))
    target_parented = run(publisher.publish(context, base_without_configuration, records[0]))

    assert len({asset.id for asset in assets}) == 4
    assert len({asset.content_hash for asset in assets}) == 4
    assert all(asset.kind == "configuration" for asset in assets)
    assert all(asset.parent_id == 32 and asset.validated_at is not None for asset in assets)
    assert reused.id == assets[0].id
    assert target_parented.parent_id == 31
    assert target_parented.id != reused.id


def test_progression_asset_publisher_rejects_secret_environment_without_writes(
    tmp_path: Path,
) -> None:
    from backend.agents.outputs.campaign_review import ProgressionActionRecord
    from backend.services.campaigns.production_progression import ProgressionAssetPublisher

    repository = tmp_path / "workspace/projects/7/repository"
    repository.mkdir(parents=True)
    generated_assets_root = repository.parent / "assets"
    context = SimpleNamespace(
        project_id=7,
        repository_root=repository,
        generated_assets_root=generated_assets_root,
    )
    store = _ReusableAssetStore()
    publisher = ProgressionAssetPublisher(store)
    base = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
    )
    record = ProgressionActionRecord.model_construct(
        action_id="campaign-progression:7:9:secret",
        project_id=7,
        base_campaign_id=9,
        target_asset_id=31,
        action_name="try configuration",
        evidence_ids=("evidence:source",),
        arguments=("--protocol",),
        environment=(("OPENAI_API_KEY", "must-not-be-persisted"),),
        detail="auxiliary protocol",
        dictionary_content=None,
    )

    with pytest.raises(ValueError, match="replay environment"):
        run(publisher.publish(context, base, record))

    assert store.assets == {}
    assert not generated_assets_root.exists()


def test_progression_retry_reuses_bound_campaign_and_strategy_after_partial_publication() -> None:
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=2)
    base = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", stopped_at=None, error=None,
    )
    sibling = SimpleNamespace(
        id=12, project_id=7, target_asset_id=31, configuration_asset_id=41,
        engine="afl", stopped_at=None, error=None,
    )
    invocation = ContainerInvocation(
        engine="afl", image_id="sha256:" + "b" * 64,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--",
            "/opt/bigeye/parser", "@@",
        ],
        environment={"AFL_NO_UI": "1"}, campaign_labels={},
        network_disabled=True, read_only_source=True,
        timeout_ms=1_000, memory_limit_mb=1_024,
    )
    campaigns = AsyncMock()
    campaigns.get.return_value = base
    campaigns.get_progression.side_effect = [None, sibling, sibling]
    campaigns.create_progression.return_value = sibling
    campaigns.record_progression_error.return_value = True
    campaigns.clear_progression_error.return_value = True
    progression_assets = AsyncMock()
    progression_assets.publish.return_value = SimpleNamespace(
        id=41, project_id=7, parent_id=32, validated_at=NOW, error=None,
    )
    invocations = SimpleNamespace(
        load=lambda *_args: invocation,
        clone_variant=AsyncMock(side_effect=[RuntimeError("interrupted"), None, None]),
    )
    containers = AsyncMock()
    runtime = RepositoryCampaignRuntime(
        tasks=AsyncMock(), assets=AsyncMock(), campaigns=campaigns,
        discovery=SimpleNamespace(context=lambda _project_id: SimpleNamespace(project_id=7)),
        containers=containers, invocations=invocations,
        progression_assets=progression_assets,
    )
    action = _record(
        suffix="dictionary", action="enable dictionary",
        dictionary='token_000="MAGIC"\n',
    )

    with pytest.raises(RuntimeError, match="interrupted"):
        run(runtime.progress(project, action))
    campaigns.record_progression_error.assert_awaited_once()
    result = run(runtime.progress(project, action))
    from backend.services.campaigns.production_runtime import ContainerObservation
    runtime._observations[7] = ContainerObservation(active_campaign_ids=(9, 12))
    repeated = run(runtime.progress(project, action))

    assert result is sibling
    assert repeated is sibling
    assert campaigns.create_progression.await_count == 3
    assert all(
        call.kwargs["action_id"] == action.action_id
        and call.kwargs["configuration_asset_id"] == 41
        for call in campaigns.create_progression.await_args_list
    )
    assert invocations.clone_variant.await_count == 3
    assert all(
        call.kwargs["configuration_asset_id"] == 41
        for call in invocations.clone_variant.await_args_list
    )
    campaigns.record_error.assert_not_awaited()
    assert campaigns.clear_progression_error.await_count == 2
    assert containers.start_exact.await_count == 2
    containers.start_exact.assert_awaited_with(project, sibling)


@pytest.mark.parametrize("environment", [
    (("OPENAI_API_KEY", "must-not-be-persisted"),),
    (("DATABASE_URL", "postgresql://db/bigeye?user=admin&password=secret"),),
])
def test_progression_rejects_secret_environment_before_asset_or_campaign_persistence(
    environment,
) -> None:
    from backend.agents.outputs.campaign_review import ProgressionActionRecord
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=2)
    base = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", stopped_at=None, error=None,
    )
    invocation = ContainerInvocation(
        engine="afl", image_id="sha256:" + "b" * 64,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--",
            "/opt/bigeye/parser", "@@",
        ],
        environment={"AFL_NO_UI": "1"}, campaign_labels={},
        network_disabled=True, read_only_source=True,
        timeout_ms=1_000, memory_limit_mb=1_024,
    )
    campaigns = AsyncMock()
    campaigns.get.return_value = base
    progression_assets = AsyncMock()
    runtime = RepositoryCampaignRuntime(
        tasks=AsyncMock(), assets=AsyncMock(), campaigns=campaigns,
        discovery=SimpleNamespace(context=lambda _project_id: SimpleNamespace(project_id=7)),
        containers=AsyncMock(),
        invocations=SimpleNamespace(load=lambda *_args: invocation, clone_variant=AsyncMock()),
        progression_assets=progression_assets,
    )
    record_fields = dict(
        action_id="campaign-progression:7:9:secret",
        project_id=7,
        base_campaign_id=9,
        target_asset_id=31,
        action_name="try configuration",
        evidence_ids=("evidence:source",),
        arguments=("--protocol",),
        environment=environment,
        detail="auxiliary protocol",
        dictionary_content=None,
    )

    with pytest.raises(ValueError, match="replay environment"):
        ProgressionActionRecord(**record_fields)

    record = ProgressionActionRecord.model_construct(**record_fields)

    with pytest.raises(ValueError, match="replay environment"):
        run(runtime.progress(project, record))

    campaigns.get.assert_not_awaited()
    campaigns.create_progression.assert_not_awaited()
    progression_assets.publish.assert_not_awaited()


def test_reconciliation_skips_an_incomplete_errored_progression_invocation(
    tmp_path: Path,
) -> None:
    from backend.services.campaigns.production_runtime import DeferredCampaignContainers

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=2)
    incomplete = SimpleNamespace(
        id=12, project_id=7, target_asset_id=31, configuration_asset_id=41,
        engine="afl", stopped_at=None, error="variant publication interrupted",
        next_review_after=NOW, next_review_reason="initial campaign supervision",
    )
    docker = Mock()
    docker.connect.side_effect = AssertionError("errored progression must not reach Docker")
    invocations = Mock()
    invocations.load.side_effect = AssertionError("incomplete invocation must not be loaded")
    containers = DeferredCampaignContainers(
        tmp_path, docker_client=docker, invocation_store=invocations,
    )

    snapshot = run(containers.reconcile(project, (incomplete,), ()))

    assert snapshot.active_campaign_ids == ()
    docker.connect.assert_not_called()
    invocations.load.assert_not_called()


def test_campaign_repository_binds_one_progression_action_to_one_campaign_transactionally() -> None:
    from backend.repositories.campaign_repository import CampaignRepository

    row = {
        "id": 12, "project_id": 7, "target_asset_id": 31,
        "configuration_asset_id": 41, "engine": "afl", "started_at": NOW,
        "stopped_at": None, "last_heartbeat_at": None, "cpu_seconds": 0.0,
        "next_review_after": NOW, "next_review_reason": "initial campaign supervision",
        "error": None,
    }
    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=_AsyncContext())
    connection.fetchrow.side_effect = [None, row]
    pool = SimpleNamespace(acquire=lambda: _AsyncConnection(connection))
    repository = CampaignRepository(pool)

    result = run(repository.create_progression(
        action_id="campaign-progression:7:9:dictionary",
        project_id=7,
        base_campaign_id=9,
        target_asset_id=31,
        configuration_asset_id=41,
        engine="afl",
        next_review_after=NOW,
        next_review_reason="initial campaign supervision",
        configuration_purpose="enable dictionary",
    ))

    assert result.id == 12
    assert "pg_advisory_xact_lock" in connection.execute.await_args_list[0].args[0]
    assert "campaign_progression_actions" in connection.fetchrow.await_args_list[0].args[0]
    creation = connection.fetchrow.await_args_list[1].args[0]
    assert "INSERT INTO campaigns" in creation
    assert "INSERT INTO campaign_progression_actions" in creation
    assert "INSERT INTO campaign_contexts" in creation


def test_campaign_repository_reads_an_existing_progression_result() -> None:
    from backend.repositories.campaign_repository import CampaignRepository

    row = {
        "id": 12, "project_id": 7, "target_asset_id": 31,
        "configuration_asset_id": 41, "engine": "afl", "started_at": NOW,
        "stopped_at": None, "last_heartbeat_at": None, "cpu_seconds": 0.0,
        "next_review_after": NOW, "next_review_reason": "initial campaign supervision",
        "error": None,
    }
    pool = AsyncMock()
    pool.fetchrow.return_value = row

    result = run(CampaignRepository(pool).get_progression(
        "campaign-progression:7:9:dictionary",
    ))

    assert result.id == 12
    assert "campaign_progression_actions" in pool.fetchrow.await_args.args[0]


class _AsyncContext:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _AsyncConnection:
    def __init__(self, connection):
        self._connection = connection

    async def __aenter__(self):
        return self._connection

    async def __aexit__(self, *_args):
        return False


def test_review_schedule_preserves_an_existing_earlier_campaign_deadline() -> None:
    from backend.repositories.campaign_repository import CampaignRepository

    pool = AsyncMock()
    pool.fetchval.return_value = 1

    assert run(CampaignRepository(pool).schedule_next_reviews(
        7, NOW, "periodic campaign supervision",
    )) is True

    query = pool.fetchval.await_args.args[0]
    assert "LEAST" in query
    assert "next_review_after IS NULL OR $2 < next_review_after" in query
    assert "ELSE next_review_reason" in query


def test_variant_clean_coverage_keeps_build_provenance_without_rebuilding(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.coverage_contract import CampaignCoverageContract
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage
    from backend.fuzzing.coverage.replay_verifier import ResolvedCoverageTarget
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    base = tmp_path / "projects/7/campaigns/9"
    for name in ("config", "corpus", "output", "logs"):
        (base / name).mkdir(parents=True)
    (base / "corpus/seed").write_bytes(b"seed")
    contract = CampaignCoverageContract(
        project_id=7,
        commit_sha="a" * 40,
        clean_image_id="sha256:" + "c" * 64,
        clean_content_hash="d" * 64,
        clean_parent_image_id="sha256:" + "e" * 64,
        target_asset_id=31,
        configuration_asset_id=32,
        clean_build_configuration_asset_id=32,
        coverage_asset_id=34,
        binary_path="/opt/bigeye/parser",
        replay_command=("/opt/bigeye/parser", "{input}"),
        replay_environment=(),
    )
    (base / "config/coverage.json").write_text(json.dumps(asdict(contract)))
    invocation = ContainerInvocation(
        engine="afl", image_id="sha256:" + "b" * 64,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--",
            "/opt/bigeye/parser", "@@",
        ],
        environment={"AFL_NO_UI": "1"}, campaign_labels={},
        network_disabled=True, read_only_source=True,
        timeout_ms=1_000, memory_limit_mb=1_024,
    )
    store = CampaignInvocationStore(tmp_path)

    run(store.clone_variant(
        7, 9, 12, invocation, configuration_asset_id=41,
    ))

    cloned = store.load_coverage(7, 12)
    assert cloned.configuration_asset_id == 41
    assert cloned.clean_build_configuration_asset_id == 32
    target = ResolvedCoverageTarget(
        id=12,
        project_id=7,
        commit_sha="a" * 40,
        clean_image=cloned.clean_image_id,
        clean_image_id=cloned.clean_image_id,
        clean_content_hash=cloned.clean_content_hash,
        clean_parent_image_id=cloned.clean_parent_image_id,
        binary_path=cloned.binary_path,
        replay_command=cloned.replay_command,
        target_asset_id=31,
        configuration_asset_id=41,
        clean_build_configuration_asset_id=32,
        strategy_asset_id=41,
        coverage_asset_id=34,
        cpu_exposure_seconds=0.0,
        repository_root=tmp_path,
        replay_environment=cloned.replay_environment,
    )
    client = SimpleNamespace(api=SimpleNamespace(inspect_image=lambda _image: {
        "Id": cloned.clean_image_id,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"Labels": {
            "bigeye.project": "7",
            "bigeye.commit": "a" * 40,
            "bigeye.layer": "coverage",
            "bigeye.content-hash": "d" * 64,
            "bigeye.parent-image": "sha256:" + "e" * 64,
            "bigeye.target-asset-id": "31",
            "bigeye.configuration-asset-id": "32",
            "bigeye.coverage-asset-id": "34",
        }},
    }))

    verified = LlvmCoverage(client, SimpleNamespace(), tmp_path)._verify_clean_image(target)

    assert verified["id"] == cloned.clean_image_id
