"""Findings endpoints expose replayed groups and bounded reproducers only."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
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
    def __init__(self, has_more=False):
        self.has_more = has_more
        self.page_calls = []

    async def list_page(self, project_id, limit, before):
        self.page_calls.append((project_id, limit, before))
        return ([ROW] if project_id == 7 else []), self.has_more

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


class Reproductions:
    async def start(self, project_id, finding_id):
        from backend.services.findings.reproduction_registry import ReproductionRun
        from backend.services.findings.reproduce_finding import FindingNotFound

        if (project_id, finding_id) != (7, 5):
            raise FindingNotFound("finding not found")
        return ReproductionRun(
            "c" * 32, 7, 5, "starting", NOW, None,
            "sha256:" + "d" * 64,
            ("/opt/bigeye/reproduce", "/finding/input"),
        )

    async def stream(self, project_id, finding_id, run_id):
        if (project_id, finding_id, run_id) != (7, 5, "c" * 32):
            raise LookupError("not found")
        yield {"event": "reproduction", "data": {"phase": "starting"}}
        yield {"event": "output", "data": {"stream": "stderr", "text": "asan\n"}}
        yield {"event": "reproduction", "data": {"phase": "completed", "exit_code": 1}}


def client(rows=None, artifacts=None, observability=None):
    from backend.api.app import create_app

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None),
        findings=rows or FindingRows(),
        finding_artifacts=artifacts or FindingArtifacts(),
        observability=observability or SimpleNamespace(locate_evidence=AsyncMock(return_value={})),
        reproductions=Reproductions(),
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
    assert response.json() == {"items": [{
        "id": "5", "project_id": "7", "classification": "true vulnerability",
        "priority_rank": 1,
        "priority_reason": "Reproducible sanitizer failure in a reachable parser.",
        "description": "Reproduced parser memory failure.", "reproducible": True,
        "occurrence_count": 2, "created_at": "2026-07-20T00:00:00Z",
        "triaged_at": "2026-07-20T00:00:00Z",
    }], "next_cursor": None}


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


def test_detail_links_only_evidence_resolved_to_an_exact_retained_event():
    from backend.models.event import StoredEvent

    retained = StoredEvent(
        id=812, created_at=NOW, stream="activity",
        payload={"evidence_ids": ["replay:original:1"]},
    )
    observability = SimpleNamespace(locate_evidence=AsyncMock(return_value={
        "replay:original:1": retained,
    }))
    with client(observability=observability) as api:
        response = api.get("/api/projects/7/findings/5")

    assert response.status_code == 200
    assert response.json()["evidence_events"] == [{
        "evidence_id": "replay:original:1", "stream": "activity", "event_id": 812,
    }]
    observability.locate_evidence.assert_awaited_once_with(7, ["replay:original:1"])


def test_reproducer_download_has_fixed_safe_headers_and_no_host_path():
    with client() as api:
        response = api.get("/api/projects/7/findings/5/reproducer")

    assert response.status_code == 200
    assert response.content == b"crash"
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == 'attachment; filename="bigeye-finding-5.bin"'
    assert "x-sendfile" not in response.headers


def test_exact_reproduction_is_accepted_and_streamed_only_as_sse():
    with client() as api:
        started = api.post("/api/projects/7/findings/5/reproductions")
        wrong_project = api.post("/api/projects/8/findings/5/reproductions")
        stream = api.get(
            "/api/projects/7/findings/5/reproductions/" + "c" * 32 + "/events",
        )
        websocket_like = api.get(
            "/api/projects/7/findings/5/reproductions/" + "c" * 32 + "/stdin",
        )

    assert started.status_code == 202
    assert started.json()["command"] == ["/opt/bigeye/reproduce", "/finding/input"]
    assert wrong_project.status_code == 404
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert "event: output\ndata: {\"stream\":\"stderr\",\"text\":\"asan\\n\"}" in stream.text
    assert websocket_like.status_code == 404


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


def test_findings_list_enforces_limit_and_project_scoped_cursor():
    rows = FindingRows(has_more=True)
    with client(rows=rows) as api:
        first = api.get("/api/projects/7/findings", params={"limit": 1})
        cursor = first.json()["next_cursor"]
        continued = api.get("/api/projects/7/findings", params={"limit": 1, "cursor": cursor})
        wrong_project = api.get("/api/projects/8/findings", params={"cursor": cursor})
        too_small = api.get("/api/projects/7/findings", params={"limit": 0})
        too_large = api.get("/api/projects/7/findings", params={"limit": 101})

    assert first.status_code == 200
    assert continued.status_code == 200
    assert rows.page_calls[1][2] == (1, NOW, 5)
    assert wrong_project.status_code == 422
    assert too_small.status_code == 422
    assert too_large.status_code == 422


def test_repository_creates_or_atomically_increments_one_project_fingerprint_group():
    class Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class Connection:
        def __init__(self):
            self.calls = []

        def transaction(self):
            return Transaction()

        async def execute(self, query, *arguments):
            self.calls.append((query, arguments))

        async def fetchrow(self, query, *arguments):
            self.calls.append((query, arguments))
            if "INSERT INTO findings" in query:
                return {"id": 5}
            return {
                "id": 5, "project_id": 7, "fingerprint": "a" * 64,
                "classification": "true vulnerability", "priority_rank": 1,
                "priority_reason": "true vulnerability; reproducible; observed 2 times",
                "description": "description", "reproducible": True,
                "occurrence_count": 2, "created_at": NOW, "triaged_at": NOW, "error": None,
            }

    class Acquire:
        def __init__(self, connection):
            self.connection = connection

        async def __aenter__(self):
            return self.connection

        async def __aexit__(self, *_args):
            return False

    class Pool:
        def __init__(self):
            self.connection = Connection()

        def acquire(self):
            return Acquire(self.connection)

    from backend.repositories.finding_repository import FindingRepository

    pool = Pool()
    row = __import__("asyncio").run(FindingRepository(pool).create_or_increment(
        project_id=7, fingerprint="a" * 64, classification="true vulnerability",
        description="description", reproducible=True, candidate_selected=True,
    ))

    assert row.occurrence_count == 2
    queries = [query for query, _arguments in pool.connection.calls]
    assert "pg_advisory_xact_lock" in queries[0]
    assert "INSERT INTO findings" in queries[1]
    assert "ON CONFLICT (project_id, fingerprint)" in queries[1]
    assert "CASE WHEN $6 THEN EXCLUDED.classification ELSE findings.classification END" in queries[1]
    assert "occurrence_count = findings.occurrence_count + 1" in queries[1]
    assert pool.connection.calls[1][1][-1] is True
    assert "ROW_NUMBER() OVER" in queries[2]
    assert "priority_reason" in queries[2]


def test_reproducer_metadata_accepts_an_empty_crash_input():
    from backend.api.views.finding import ReproducerMetadata

    value = ReproducerMetadata(sha256="b" * 64, size=0)

    assert value.size == 0


def test_production_services_wire_committed_finding_routes(tmp_path):
    from backend.api.app import create_app
    from backend.api.dependencies import build_services
    from backend.fuzzing.crashes.artifacts import FindingArtifactStore
    from backend.repositories.finding_repository import FindingRepository

    class Pool:
        def __init__(self):
            self.fetch_calls = []

        async def fetch(self, query, *arguments):
            self.fetch_calls.append((query, arguments))
            return []

    class Recovery:
        async def recover(self):
            return None

    pool = Pool()
    services = build_services(pool, tmp_path)
    services.recovery = Recovery()

    with TestClient(create_app(services=services)) as api:
        response = api.get("/api/projects/7/findings")

    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}
    assert isinstance(services.findings, FindingRepository)
    assert isinstance(services.finding_artifacts, FindingArtifactStore)
    assert services.reproductions is not None
    assert pool.fetch_calls[0][1] == (7, 51, None, None, None)


def test_repository_pages_by_global_priority_rank_before_creation_time():
    class Pool:
        def __init__(self):
            self.calls = []

        async def fetch(self, query, *arguments):
            self.calls.append((query, arguments))
            return []

    from backend.repositories.finding_repository import FindingRepository
    import asyncio

    pool = Pool()
    rows, has_more = asyncio.run(FindingRepository(pool).list_page(7, 25, (3, NOW, 5)))

    assert rows == [] and has_more is False
    query, arguments = pool.calls[0]
    assert "ORDER BY priority_rank ASC NULLS LAST, created_at DESC, id DESC" in query
    assert "COALESCE(priority_rank" in query
    assert arguments == (7, 26, 3, NOW, 5)


def test_finding_detail_caps_evidence_identifiers_at_specialist_bound():
    from pydantic import ValidationError
    from backend.api.views.finding import FindingDetailResponse

    values = {
        **ROW.__dict__, "id": "5", "project_id": "7", "error": None,
        "uncertainty": "uncertain", "evidence_ids": [f"evidence:{index}" for index in range(65)],
        "reproducer": {"sha256": "b" * 64, "size": 0},
        "replay": {"attempts": 3, "matching": 3},
    }
    values.pop("fingerprint")
    values.pop("error")

    with pytest.raises(ValidationError):
        FindingDetailResponse(**values)


def test_repository_rejects_non_text_classification_without_querying():
    class Pool:
        def acquire(self):
            raise AssertionError("invalid finding must not reach PostgreSQL")

    from backend.repositories.finding_repository import FindingRepository
    import asyncio
    import pytest

    with pytest.raises(ValueError, match="classification"):
        asyncio.run(FindingRepository(Pool()).create_or_increment(
            project_id=7, fingerprint="a" * 64, classification=["unresolved"],
            description="description", reproducible=False, candidate_selected=True,
        ))


def test_release_schema_guarantees_one_finding_group_per_project_fingerprint():
    from pathlib import Path

    schema = (Path(__file__).parents[1] / "database" / "schema.sql").read_text()

    assert "UNIQUE (project_id, fingerprint)" in schema
