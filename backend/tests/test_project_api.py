"""Project creation and control HTTP contracts."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
import warnings

import pytest

warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")

from starlette.testclient import TestClient


NOW = datetime(2026, 7, 19, tzinfo=UTC)


def project(*, revision: str = "stable", token_present: bool = True, paused_at=None):
    from backend.models.project import Project

    return Project(
        7,
        "https://github.com/acme/demo.git",
        revision,
        2,
        None,
        token_present,
        NOW,
        paused_at,
        None,
    )


@pytest.fixture
def services():
    return SimpleNamespace(
        project_creator=AsyncMock(),
        project_settings=AsyncMock(),
        projects=AsyncMock(),
        tasks=AsyncMock(),
        logs=AsyncMock(),
        events=AsyncMock(),
        settings=AsyncMock(),
        recovery=AsyncMock(),
    )


@pytest.fixture
def client(services):
    from backend.api.app import create_app

    with TestClient(create_app(services=services)) as test_client:
        yield test_client


def test_create_accepts_revision_and_token_but_response_redacts_token(client, services):
    services.project_creator.create.return_value = project()

    response = client.post("/api/projects", json={
        "repository_url": "https://github.com/acme/demo.git",
        "revision": "stable",
        "worker_count": 2,
        "repository_token": "secret-read-token",
    })

    assert response.status_code == 202
    assert response.json()["requested_revision"] == "stable"
    assert response.json()["token_present"] is True
    assert "repository_token" not in response.json()
    services.project_creator.create.assert_awaited_once_with(
        "https://github.com/acme/demo.git", "stable", 2, "secret-read-token"
    )


def test_revision_cannot_be_changed_by_settings(client):
    response = client.patch("/api/projects/7/settings", json={"revision": "other"})

    assert response.status_code == 422


def test_project_settings_are_read_and_updated_without_returning_token(client, services):
    services.project_settings.get.return_value = project()
    services.project_settings.update.return_value = project(token_present=False)

    read = client.get("/api/projects/7/settings")
    updated = client.patch("/api/projects/7/settings", json={"worker_count": 4, "repository_token": ""})

    assert read.status_code == 200
    assert read.json() == {
        "requested_revision": "stable",
        "commit_sha": None,
        "worker_count": 2,
        "token_present": True,
    }
    assert updated.status_code == 200
    assert updated.json()["token_present"] is False
    assert "repository_token" not in updated.json()
    services.project_settings.update.assert_awaited_once_with(7, 4, "")


def test_pause_and_resume_return_the_project_state(client, services):
    services.project_settings.pause.return_value = project(paused_at=NOW)
    services.project_settings.resume.return_value = project(paused_at=None)

    paused = client.post("/api/projects/7/pause")
    resumed = client.post("/api/projects/7/resume")

    assert paused.status_code == 200
    assert paused.json()["paused_at"] == "2026-07-19T00:00:00Z"
    assert resumed.status_code == 200
    assert resumed.json()["paused_at"] is None
    services.project_settings.pause.assert_awaited_once_with(7)
    services.project_settings.resume.assert_awaited_once_with(7)


def test_project_setting_missing_project_is_not_found(client, services):
    services.project_settings.get.side_effect = KeyError(7)

    response = client.get("/api/projects/7/settings")

    assert response.status_code == 404
