"""Findings endpoints expose replayed groups and bounded reproducers only."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend.models.finding import Finding


NOW = datetime(2026, 7, 20, tzinfo=UTC)
ROW = Finding(
    id=5, project_id=7, fingerprint="a" * 64,
    classification="true vulnerability", priority_rank=1,
    priority_reason="Reproducible sanitizer failure in a reachable parser.",
    description="Reproduced parser memory failure.", reproducible=True,
    occurrence_count=2, created_at=NOW, triaged_at=NOW, error=None,
)


class FindingRows:
    async def list_for_project(self, project_id):
        return [ROW] if project_id == 7 else []

    async def get(self, finding_id):
        return ROW if finding_id == 5 else None


class FindingArtifacts:
    def detail(self, finding):
        assert finding is ROW
        return {
            "uncertainty": "Reachability outside the fixture remains to be confirmed.",
            "evidence_ids": ["replay:original:1"],
            "reproducer": {"sha256": "b" * 64, "size": 5},
            "replay": {"attempts": 3, "matching": 3},
        }

    def read_reproducer(self, finding, max_bytes):
        assert finding is ROW
        assert max_bytes == 16 * 1024 * 1024
        return b"crash"


def client(rows=None, artifacts=None):
    from backend.api.app import create_app

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None),
        findings=rows or FindingRows(),
        finding_artifacts=artifacts or FindingArtifacts(),
        close=lambda: None,
    )
    app = create_app(services=services)

    @asynccontextmanager
    async def lifespan(_app):
        _app.state.services = services
        yield

    app.router.lifespan_context = lifespan
    return TestClient(app)


def test_list_contains_only_persisted_replayed_groups():
    with client() as api:
        response = api.get("/api/projects/7/findings")

    assert response.status_code == 200
    assert response.json() == [{
        "id": "5", "project_id": "7", "classification": "true vulnerability",
        "priority_rank": 1,
        "priority_reason": "Reproducible sanitizer failure in a reachable parser.",
        "description": "Reproduced parser memory failure.", "reproducible": True,
        "occurrence_count": 2, "created_at": "2026-07-20T00:00:00Z",
        "triaged_at": "2026-07-20T00:00:00Z",
    }]


def test_detail_is_project_scoped_and_exposes_bounded_evidence_not_logs_or_paths():
    with client() as api:
        response = api.get("/api/projects/7/findings/5")
        wrong_project = api.get("/api/projects/8/findings/5")

    assert response.status_code == 200
    body = response.json()
    assert body["uncertainty"].startswith("Reachability")
    assert body["reproducer"]["size"] == 5
    assert "path" not in str(body).casefold()
    assert "log" not in str(body).casefold()
    assert wrong_project.status_code == 404


def test_reproducer_download_has_fixed_safe_headers_and_no_host_path():
    with client() as api:
        response = api.get("/api/projects/7/findings/5/reproducer")

    assert response.status_code == 200
    assert response.content == b"crash"
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == 'attachment; filename="bigeye-finding-5.bin"'
    assert "x-sendfile" not in response.headers


def test_missing_or_unpublished_finding_is_not_found():
    with client() as api:
        response = api.get("/api/projects/7/findings/999")

    assert response.status_code == 404


def test_finding_route_identifiers_must_be_positive():
    with client() as api:
        project = api.get("/api/projects/0/findings")
        finding = api.get("/api/projects/7/findings/0")

    assert project.status_code == 422
    assert finding.status_code == 422


def test_repository_creates_or_atomically_increments_one_project_fingerprint_group():
    class Pool:
        def __init__(self):
            self.call = None

        async def fetchrow(self, query, *arguments):
            self.call = (query, arguments)
            return {
                "id": 5, "project_id": 7, "fingerprint": "a" * 64,
                "classification": "true vulnerability", "priority_rank": 1,
                "priority_reason": "reason", "description": "description",
                "reproducible": True, "occurrence_count": 2,
                "created_at": NOW, "triaged_at": NOW, "error": None,
            }

    from backend.repositories.finding_repository import FindingRepository

    pool = Pool()
    row = __import__("asyncio").run(FindingRepository(pool).create_or_increment(
        project_id=7, fingerprint="a" * 64, classification="true vulnerability",
        priority_rank=1, priority_reason="reason", description="description", reproducible=True,
    ))

    assert row.occurrence_count == 2
    query, arguments = pool.call
    assert "pg_advisory_xact_lock" in query
    assert "$1::bigint" in query
    assert "occurrence_count = findings.occurrence_count + 1" in query
    assert arguments == (7, "a" * 64, "true vulnerability", 1, "reason", "description", True)


def test_reproducer_metadata_accepts_an_empty_crash_input():
    from backend.api.views.finding import ReproducerMetadata

    value = ReproducerMetadata(sha256="b" * 64, size=0)

    assert value.size == 0


def test_repository_rejects_non_text_classification_without_querying():
    class Pool:
        async def fetchrow(self, *_args):
            raise AssertionError("invalid finding must not reach PostgreSQL")

    from backend.repositories.finding_repository import FindingRepository
    import asyncio
    import pytest

    with pytest.raises(ValueError, match="classification"):
        asyncio.run(FindingRepository(Pool()).create_or_increment(
            project_id=7, fingerprint="a" * 64, classification=["unresolved"],
            priority_rank=None, priority_reason=None, description="description", reproducible=False,
        ))
