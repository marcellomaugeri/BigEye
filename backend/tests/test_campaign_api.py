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
    assert "LIMIT $2" in pool.calls[1][0]
    assert pool.calls[1][2] == 1_001


def test_campaign_repository_rejects_an_asset_set_larger_than_its_read_bound():
    from backend.repositories.campaign_repository import CampaignRepository

    class TooManyAssets(_Pool):
        async def fetch(self, query, project_id, *arguments):
            if "FROM campaigns" in query:
                return []
            row = {
                "project_id": 7, "kind": "strategy", "name": "Strategy",
                "content_hash": "a" * 64, "parent_id": None, "created_at": NOW,
                "validated_at": NOW, "error": None,
            }
            return [{**row, "id": index + 1} for index in range(1_001)]

    with __import__('pytest').raises(OverflowError, match="campaign asset read limit"):
        asyncio.run(CampaignRepository(TooManyAssets()).list_with_assets_for_project(7))


class _Campaigns:
    async def list_with_assets_for_project(self, project_id):
        pool = _Pool()
        from backend.repositories.campaign_repository import CampaignRepository
        return await CampaignRepository(pool).list_with_assets_for_project(project_id)


class _Projects:
    async def get(self, project_id):
        return SimpleNamespace(id=project_id)


def _client():
    from backend.api.app import create_app

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None), campaigns=_Campaigns(), projects=_Projects(), close=lambda: None,
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
        "campaigns": [{
            "id": 4, "target_asset_id": 31, "target_name": "Parser input path",
            "configuration_asset_id": 32, "configuration_name": "Encrypted mode",
            "engine": "system-engine", "started_at": "2026-07-20T09:00:00Z",
            "stopped_at": None, "last_heartbeat_at": "2026-07-20T09:00:00Z",
            "cpu_exposure_seconds": 5400.0,
            "next_review_after": "2026-07-20T09:00:00Z",
            "next_review_reason": "Coverage is still increasing in the parser.", "error": None,
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

    from backend.api.app import create_app

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None), campaigns=EmptyCampaigns(), projects=_Projects(), close=lambda: None,
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
    assert response.json() == {"project_id": 7, "campaigns": [], "assets": []}


def test_campaign_route_returns_not_found_for_a_nonexistent_project():
    class MissingProjects:
        async def get(self, project_id):
            return None

    from backend.api.app import create_app

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None), campaigns=_Campaigns(),
        projects=MissingProjects(), close=lambda: None,
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

    services = build_services(AsyncMock(), tmp_path)

    assert isinstance(services.campaigns, CampaignRepository)
