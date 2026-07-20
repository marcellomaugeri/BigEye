"""Release persistence contracts."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


NOW = datetime(2026, 7, 19, tzinfo=UTC)


def run(awaitable):
    return asyncio.run(awaitable)


def project_row(**changes):
    return {
        "id": 7,
        "repository_url": "https://github.com/acme/demo.git",
        "requested_revision": "HEAD",
        "worker_count": 2,
        "commit_sha": None,
        "token_present": False,
        "created_at": NOW,
        "manager_wake_at": None,
        "manager_wake_reason": None,
        "error": None,
    } | changes


def test_project_response_model_never_contains_token():
    from backend.models.project import Project

    assert "repository_token" not in Project.__dataclass_fields__


def test_release_models_expose_only_the_required_fields():
    from backend.models.asset import CampaignAsset
    from backend.models.campaign import Campaign
    from backend.models.coverage import CoverageEvidence
    from backend.models.finding import Finding
    from backend.models.project import Project

    assert tuple(Project.__dataclass_fields__) == (
        "id", "repository_url", "requested_revision", "worker_count", "commit_sha",
        "token_present", "created_at", "manager_wake_at", "manager_wake_reason", "error",
    )
    assert tuple(CampaignAsset.__dataclass_fields__) == (
        "id", "project_id", "kind", "name", "content_hash", "parent_id", "created_at",
        "validated_at", "error",
    )
    assert tuple(Campaign.__dataclass_fields__) == (
        "id", "project_id", "target_asset_id", "configuration_asset_id", "engine", "started_at",
        "stopped_at", "last_heartbeat_at", "cpu_seconds", "next_review_after",
        "next_review_reason", "error",
    )
    assert tuple(CoverageEvidence.__dataclass_fields__) == (
        "id", "project_id", "commit_sha", "source_path", "line_number", "function_name",
        "campaign_id", "asset_id", "first_testcase_sha256", "cpu_exposure_seconds",
    )
    assert tuple(Finding.__dataclass_fields__) == (
        "id", "project_id", "fingerprint", "classification", "priority_rank", "priority_reason",
        "description", "reproducible", "occurrence_count", "created_at", "triaged_at", "error",
    )


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *args):
        return False


class TestProjectRepository:
    def test_create_uses_release_defaults_and_persists_initial_tasks_transactionally(self):
        from backend.repositories.project_repository import ProjectRepository

        connection = AsyncMock()
        connection.transaction = MagicMock(return_value=_Transaction())
        connection.fetchrow.return_value = project_row()
        pool = SimpleNamespace(acquire=lambda: _Acquire(connection))

        created = run(ProjectRepository(pool).create_with_tasks(
            "https://github.com/acme/demo.git", 2, ["repository clone"]
        ))

        assert created.requested_revision == "HEAD"
        assert created.token_present is False
        assert created.manager_wake_at is None
        assert created.manager_wake_reason is None
        connection.transaction.assert_called_once_with()
        query = connection.fetchrow.await_args.args[0]
        assert "INSERT INTO projects (repository_url, worker_count)" in query
        assert "requested_revision" in query
        assert "repository_token IS NOT NULL AS token_present" in query
        connection.execute.assert_awaited_once_with(
            "INSERT INTO tasks (project_id, name) VALUES ($1, $2)", 7, "repository clone"
        )

    def test_settings_preserve_or_clear_token_without_exposing_it(self):
        from backend.repositories.project_repository import ProjectRepository

        pool = AsyncMock()
        pool.fetchrow.return_value = project_row(token_present=True)
        repository = ProjectRepository(pool)

        updated = run(repository.update_settings(7, 4, ""))

        assert updated.token_present is True
        query, project_id, worker_count, token = pool.fetchrow.await_args.args
        assert "CASE WHEN $3::text IS NULL THEN repository_token ELSE NULLIF($3, '') END" in query
        assert (project_id, worker_count, token) == (7, 4, "")
        assert "repository_token" not in updated.__dict__

    def test_manager_review_deadline_is_scheduled_and_cleared_without_a_pause_state(self):
        from backend.repositories.project_repository import ProjectRepository

        pool = AsyncMock()
        repository = ProjectRepository(pool)
        wake_at = datetime(2026, 7, 19, 12, tzinfo=UTC)

        run(repository.schedule_manager_review(7, wake_at, "Recheck clean coverage growth."))
        run(repository.clear_manager_review(7))

        scheduled, cleared = pool.execute.await_args_list
        assert scheduled.args == (
            "UPDATE projects SET manager_wake_at = $2, manager_wake_reason = $3 WHERE id = $1",
            7,
            wake_at,
            "Recheck clean coverage growth.",
        )
        assert cleared.args == (
            "UPDATE projects SET manager_wake_at = NULL, manager_wake_reason = NULL WHERE id = $1",
            7,
        )

    def test_recovery_uses_the_continuous_project_state_without_a_pause_filter(self):
        from backend.repositories.project_repository import ProjectRepository

        pool = AsyncMock()
        pool.fetch.return_value = [project_row()]
        repository = ProjectRepository(pool)

        recovered = run(repository.list_unfinished())

        assert recovered == [repository._project(project_row())]
        recovery_query = pool.fetch.await_args.args[0]
        assert "WHERE error IS NULL" in recovery_query
        assert "finished_at" not in recovery_query

    def test_get_repository_token_returns_secret_only_to_the_clone_boundary(self):
        from backend.repositories.project_repository import ProjectRepository

        pool = AsyncMock()
        pool.fetchval.return_value = "secret-read-token"

        assert run(ProjectRepository(pool).get_repository_token(7)) == "secret-read-token"
        assert pool.fetchval.await_args.args == (
            "SELECT repository_token FROM projects WHERE id = $1", 7
        )

    def test_update_settings_raises_for_missing_project(self):
        from backend.repositories.project_repository import ProjectRepository

        pool = AsyncMock()
        pool.fetchrow.return_value = None

        with pytest.raises(KeyError, match="7"):
            run(ProjectRepository(pool).update_settings(7, 2, None))


@pytest.mark.parametrize(("module", "class_name", "row"), [
    ("asset_repository", "AssetRepository", {
        "id": 1, "project_id": 7, "kind": "source", "name": "main.c", "content_hash": "a" * 64,
        "parent_id": None, "created_at": NOW, "validated_at": None, "error": None,
    }),
    ("campaign_repository", "CampaignRepository", {
        "id": 2, "project_id": 7, "target_asset_id": 1, "configuration_asset_id": None,
        "engine": "libfuzzer", "started_at": NOW, "stopped_at": None, "last_heartbeat_at": None,
        "cpu_seconds": 0.0, "next_review_after": None, "next_review_reason": None, "error": None,
    }),
    ("coverage_repository", "CoverageRepository", {
        "id": 3, "project_id": 7, "commit_sha": "a" * 40, "source_path": "main.c", "line_number": 4,
        "function_name": "main", "campaign_id": 2, "asset_id": 1, "first_testcase_sha256": "b" * 64,
        "cpu_exposure_seconds": 1.5,
    }),
    ("finding_repository", "FindingRepository", {
        "id": 4, "project_id": 7, "fingerprint": "c" * 64, "classification": "crash",
        "priority_rank": None, "priority_reason": None, "description": "signal", "reproducible": True,
        "occurrence_count": 1, "created_at": NOW, "triaged_at": None, "error": None,
    }),
])
def test_release_repositories_lookup_project_rows(module, class_name, row):
    repository_module = __import__(f"backend.repositories.{module}", fromlist=[class_name])
    repository = getattr(repository_module, class_name)(AsyncMock())
    repository._pool.fetchrow.return_value = row
    repository._pool.fetch.return_value = [row]

    found = run(repository.get(7))
    listed = run(repository.list_for_project(7))

    assert found.id == row["id"]
    assert listed == [found]
    assert "$1" in repository._pool.fetchrow.await_args.args[0]
    assert "$1" in repository._pool.fetch.await_args.args[0]
