"""Project campaign read contracts for the Overview workspace."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient


NOW = datetime(2026, 7, 20, 9, 0, tzinfo=UTC)


class _Pool:
    def __init__(self):
        self.calls = []

    async def fetch(self, query, project_id, *arguments):
        self.calls.append((query, project_id, *arguments))
        if "FROM campaigns" in query:
            return [{
                "id": 4, "project_id": 7, "target_asset_id": 31,
                "configuration_asset_id": 32, "engine": "system-engine",
                "started_at": NOW, "stopped_at": None, "last_heartbeat_at": NOW,
                "cpu_seconds": 5_400.0, "next_review_after": NOW,
                "next_review_reason": "Coverage is still increasing in the parser.", "error": None,
            }]
        return [
            {
                "id": 31, "project_id": 7, "kind": "target", "name": "Parser input path",
                "content_hash": "a" * 64, "parent_id": None, "created_at": NOW,
                "validated_at": NOW, "error": None,
            },
            {
                "id": 32, "project_id": 7, "kind": "configuration", "name": "Encrypted mode",
                "content_hash": "b" * 64, "parent_id": None, "created_at": NOW,
                "validated_at": NOW, "error": None,
            },
            {
                "id": 33, "project_id": 7, "kind": "strategy", "name": "Parser strategy",
                "content_hash": "c" * 64, "parent_id": 31, "created_at": NOW,
                "validated_at": NOW, "error": None,
            },
        ]


def test_campaign_repository_reads_campaigns_with_project_assets():
    from backend.repositories.campaign_repository import CampaignRepository

    pool = _Pool()
    campaigns, assets = asyncio.run(CampaignRepository(pool).list_with_assets_for_project(7))

    assert campaigns[0].target_asset_id == 31
    assert [asset.name for asset in assets] == ["Parser input path", "Encrypted mode", "Parser strategy"]
    assert len(pool.calls) == 2
    assert all(call[1] == 7 for call in pool.calls)
    assert "id = ANY($2::bigint[])" in pool.calls[1][0]
    assert pool.calls[1][2] == [31, 32]
    assert pool.calls[1][3] == 1_001


def test_campaign_repository_does_not_read_unrelated_accumulated_assets():
    from backend.repositories.campaign_repository import CampaignRepository

    class AccumulatedAssets(_Pool):
        async def fetch(self, query, project_id, *arguments):
            if "FROM campaigns" in query:
                return await super().fetch(query, project_id, *arguments)
            assert "id = ANY($2::bigint[])" in query
            assert arguments[0] == [31, 32]
            return await super().fetch(query, project_id, *arguments)

    campaigns, assets = asyncio.run(
        CampaignRepository(AccumulatedAssets()).list_with_assets_for_project(7)
    )

    assert [campaign.id for campaign in campaigns] == [4]
    assert [asset.id for asset in assets] == [31, 32, 33]


def test_campaign_repository_rejects_a_referenced_asset_set_larger_than_its_read_bound():
    from backend.repositories.campaign_repository import CampaignRepository

    class TooManyReferencedAssets(_Pool):
        async def fetch(self, query, project_id, *arguments):
            if "FROM campaigns" in query:
                return await super().fetch(query, project_id, *arguments)
            row = {
                "project_id": 7, "kind": "strategy", "name": "Strategy",
                "content_hash": "a" * 64, "parent_id": 31, "created_at": NOW,
                "validated_at": NOW, "error": None,
            }
            return [{**row, "id": index + 100} for index in range(1_001)]

    with __import__('pytest').raises(OverflowError, match="campaign asset read limit"):
        asyncio.run(CampaignRepository(TooManyReferencedAssets()).list_with_assets_for_project(7))


class _Campaigns:
    async def list_with_assets_for_project(self, project_id):
        pool = _Pool()
        from backend.repositories.campaign_repository import CampaignRepository
        return await CampaignRepository(pool).list_with_assets_for_project(project_id)

    async def list_contexts_for_project(self, project_id):
        return {
            4: {
                "configuration_purpose": "Exercise the encrypted parser path.",
                "retirement_reason": None,
            },
        }


class _Checkpoints:
    async def histories(self, project_id):
        return ()


class _Projects:
    async def get(self, project_id):
        return SimpleNamespace(id=project_id, paused_at=None)


def _client():
    from backend.api.app import create_app
    from backend.services.campaigns.read_campaigns import CampaignReadService

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None), campaigns=_Campaigns(), projects=_Projects(),
        campaign_reader=CampaignReadService(_Campaigns(), _Checkpoints()), close=lambda: None,
    )
    app = create_app(services=services)

    @asynccontextmanager
    async def lifespan(_app):
        _app.state.services = services
        yield

    app.router.lifespan_context = lifespan
    return TestClient(app)


def test_campaign_route_exposes_user_names_and_keeps_engine_as_metadata():
    with _client() as client:
        response = client.get("/api/projects/7/campaigns")

    assert response.status_code == 200
    assert response.json() == {
        "project_id": 7,
        "project_paused": False,
        "campaigns": [{
            "id": 4, "target_asset_id": 31, "target_name": "Parser input path",
            "configuration_asset_id": 32, "configuration_name": "Encrypted mode",
            "engine": "system-engine", "started_at": "2026-07-20T09:00:00Z",
            "stopped_at": None, "last_heartbeat_at": "2026-07-20T09:00:00Z",
            "cpu_exposure_seconds": 5400.0,
            "next_review_after": "2026-07-20T09:00:00Z",
            "next_review_reason": "Coverage is still increasing in the parser.", "error": None,
            "configuration_purpose": "Exercise the encrypted parser path.",
            "retirement_reason": None,
            "reached_line_count": None, "unique_line_count": None, "overlapping_line_count": None,
        }],
        "assets": [
            {"id": 31, "kind": "target", "name": "Parser input path", "parent_id": None},
            {"id": 32, "kind": "configuration", "name": "Encrypted mode", "parent_id": None},
            {"id": 33, "kind": "strategy", "name": "Parser strategy", "parent_id": 31},
        ],
    }


def test_campaign_route_returns_an_intentional_empty_collection():
    class EmptyCampaigns:
        async def list_with_assets_for_project(self, project_id):
            return [], []

        async def list_contexts_for_project(self, project_id):
            return {}

    from backend.api.app import create_app
    from backend.services.campaigns.read_campaigns import CampaignReadService

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None), campaigns=EmptyCampaigns(), projects=_Projects(),
        campaign_reader=CampaignReadService(EmptyCampaigns(), _Checkpoints()), close=lambda: None,
    )
    app = create_app(services=services)

    @asynccontextmanager
    async def lifespan(_app):
        _app.state.services = services
        yield

    app.router.lifespan_context = lifespan
    with TestClient(app) as client:
        response = client.get("/api/projects/7/campaigns")

    assert response.status_code == 200
    assert response.json() == {"project_id": 7, "project_paused": False, "campaigns": [], "assets": []}


def test_campaign_route_returns_not_found_for_a_nonexistent_project():
    class MissingProjects:
        async def get(self, project_id):
            return None

    from backend.api.app import create_app

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None), campaigns=_Campaigns(),
        projects=MissingProjects(), campaign_reader=SimpleNamespace(), close=lambda: None,
    )
    app = create_app(services=services)

    @asynccontextmanager
    async def lifespan(_app):
        _app.state.services = services
        yield

    app.router.lifespan_context = lifespan
    with TestClient(app) as client:
        response = client.get("/api/projects/404/campaigns")

    assert response.status_code == 404
    assert response.json() == {"detail": "project not found"}


def test_production_services_expose_the_campaign_read_repository(tmp_path):
    from backend.api.dependencies import build_services
    from backend.repositories.campaign_repository import CampaignRepository
    from backend.services.campaigns.read_campaigns import CampaignReadService

    services = build_services(AsyncMock(), tmp_path)

    assert isinstance(services.campaigns, CampaignRepository)
    assert isinstance(services.campaign_reader, CampaignReadService)


def test_campaign_read_service_reports_only_persisted_compatible_overlap_and_unique_reach():
    from backend.fuzzing.coverage.overlap import CampaignCoverageHistory, CleanCoverageCheckpoint
    from backend.services.campaigns.read_campaigns import CampaignReadService

    def history(campaign_id, lines, purpose="Exercise parser mode."):
        checkpoint = CleanCoverageCheckpoint(
            f"checkpoint:{campaign_id}", frozenset(("src/parser.c", line) for line in lines), frozenset(),
        )
        return CampaignCoverageHistory(
            7, campaign_id, 30 + campaign_id, "a" * 40, "b" * 64, (checkpoint,),
            configuration_purpose=purpose,
        )

    campaign_rows = [SimpleNamespace(id=4), SimpleNamespace(id=5), SimpleNamespace(id=6)]
    assets = [SimpleNamespace(id=31, project_id=7)]

    class Campaigns:
        async def list_with_assets_for_project(self, project_id):
            return campaign_rows, assets

        async def list_contexts_for_project(self, project_id):
            return {
                4: {"configuration_purpose": "Exercise parser mode.", "retirement_reason": None},
                5: {"configuration_purpose": "Exercise parser mode.", "retirement_reason": None},
                6: {"configuration_purpose": "Different purpose.", "retirement_reason": "Redundant."},
            }

    class Checkpoints:
        async def histories(self, project_id):
            return (
                history(4, {1, 2, 3}), history(5, {2, 3, 4}),
                history(6, {1, 2, 3}, "Different purpose."),
            )

    result = asyncio.run(CampaignReadService(Campaigns(), Checkpoints()).read(7))

    assert result.summaries[4] == {
        "configuration_purpose": "Exercise parser mode.",
        "retirement_reason": None,
        "reached_line_count": 3,
        "unique_line_count": 1,
        "overlapping_line_count": 2,
    }
    assert result.summaries[6]["unique_line_count"] == 3
    assert result.summaries[6]["overlapping_line_count"] == 0
    assert result.summaries[6]["retirement_reason"] == "Redundant."
