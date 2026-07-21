"""Thin source traceability API contracts."""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError


class _Coverage:
    async def project_tree(self, project_id, limit=1_000, offset=0):
        return {"project_id": project_id, "commit_sha": "a" * 40, "files": [
            {"path": "src/a.c", "covered_lines": 2, "total_lines": 3,
             "lines": {"covered": 2, "total": 3, "percent": 66.66666666666667},
             "functions": {"covered": 1, "total": 2, "percent": 50.0},
             "branches": None, "cpu_exposure_seconds": 4.0},
        ], "summary": {
            "lines": {"covered": 2, "total": 3, "percent": 66.66666666666667},
            "functions": {"covered": 1, "total": 2, "percent": 50.0},
            "branches": None,
        }, "history": [{
            "observed_at": "2026-07-20T09:00:00Z", "covered": 2, "total": 3,
            "percent": 66.66666666666667,
        }], "pagination": {"limit": limit, "offset": offset, "total": 1}}

    async def source_file(self, project_id, path, start_line, end_line):
        return {
            "project_id": project_id, "commit_sha": "a" * 40, "path": path,
            "start_line": start_line, "end_line": end_line, "total_lines": 742,
            "lines": [{"number": 12, "text": "return 0;", "covered": True,
                       "branches": [True],
                       "strategy_count": 1, "cpu_exposure_seconds": 2.0}],
        }

    async def function_summaries(self, project_id, path, limit=1_000, offset=0):
        return {
            "functions": [{"name": "parse", "path": path, "covered_lines": 2, "cpu_exposure_seconds": 4.0}],
            "pagination": {"limit": limit, "offset": offset, "total": 1},
        }

    async def line_evidence(self, project_id, path, line_number, limit=500, offset=0):
        return {
            "evidence": [{
                "campaign_id": 4, "strategy_asset_id": 33, "testcase_sha256": "b" * 64,
                "replay_command": ["/target", "{input}"], "target_asset_id": 31,
                "replay_environment": {"BIGEYE_MODE": "encrypted"},
                "configuration_asset_id": None, "clean_image_id": "sha256:clean",
                "cpu_exposure_seconds": 2.0,
            }],
            "pagination": {"limit": limit, "offset": offset, "total": 1},
        }

    async def retained_testcase(self, project_id, path, line_number, strategy_asset_id, testcase_sha256):
        assert (project_id, path, line_number, strategy_asset_id, testcase_sha256) == (
            7, "src/a.c", 12, 33, "b" * 64,
        )
        return b"retained-testcase"


def _client(coverage=None):
    from backend.api.app import create_app

    services = SimpleNamespace(
        recovery=SimpleNamespace(recover=lambda: None), coverage=coverage or _Coverage(), close=lambda: None,
    )
    app = create_app(services=services)

    @asynccontextmanager
    async def lifespan(_app):
        _app.state.services = services
        yield

    app.router.lifespan_context = lifespan
    return TestClient(app)


def test_coverage_routes_expose_tree_source_functions_and_first_hit_evidence():
    with _client() as client:
        tree = client.get("/api/projects/7/coverage/tree")
        source = client.get("/api/projects/7/coverage/source", params={"path": "src/a.c", "start_line": 12, "end_line": 20})
        functions = client.get("/api/projects/7/coverage/functions", params={"path": "src/a.c"})
        evidence = client.get("/api/projects/7/coverage/lines/12", params={"path": "src/a.c"})
        testcase = client.get(
            "/api/projects/7/coverage/lines/12/testcases/33",
            params={"path": "src/a.c", "sha256": "b" * 64},
        )

    assert tree.status_code == 200
    assert tree.json()["files"][0]["path"] == "src/a.c"
    assert tree.json()["summary"]["branches"] is None
    assert tree.json()["summary"]["lines"] == {
        "covered": 2, "total": 3, "percent": 66.66666666666667,
    }
    assert tree.json()["history"] == [{
        "observed_at": "2026-07-20T09:00:00Z", "covered": 2, "total": 3,
        "percent": 66.66666666666667,
    }]
    assert tree.json()["pagination"] == {"limit": 1000, "offset": 0, "total": 1}
    assert source.status_code == 200
    assert source.json()["lines"][0]["covered"] is True
    assert source.json()["lines"][0]["branches"] == [True]
    assert source.json()["total_lines"] == 742
    assert functions.status_code == 200
    assert functions.json()["functions"][0]["name"] == "parse"
    assert functions.json()["pagination"]["total"] == 1
    assert evidence.status_code == 200
    assert evidence.json()["evidence"][0]["strategy_asset_id"] == 33
    assert evidence.json()["evidence"][0]["replay_environment"] == {"BIGEYE_MODE": "encrypted"}
    assert evidence.json()["pagination"]["total"] == 1
    assert testcase.status_code == 200
    assert testcase.content == b"retained-testcase"
    assert testcase.headers["content-type"] == "application/octet-stream"
    assert testcase.headers["content-disposition"].startswith("attachment;")


def test_line_evidence_response_redacts_credential_shaped_environment_defensively():
    class UnsafeCoverage(_Coverage):
        async def line_evidence(self, project_id, path, line_number, limit=500, offset=0):
            result = await super().line_evidence(project_id, path, line_number, limit, offset)
            result["evidence"][0]["replay_environment"] = {
                "BIGEYE_MODE": "encrypted",
                "GITHUB_PAT": "github-secret",
                "DATABASE_URL": "postgresql://user:password@db/bigeye",
                "DATABASE_QUERY_URL": "postgresql://db/bigeye?user=admin&password=secret",
                "ENCODED_AUTH_URL": "https://example.test/?payload=Bearer%20must-not-persist",
                "ENCODED_BASIC_URL": "https://example.test/?payload=Basic%20dXNlcjpwYXNz",
                "authentication": "Bearer bearer-secret",
            }
            return result

    with _client(UnsafeCoverage()) as client:
        response = client.get(
            "/api/projects/7/coverage/lines/12", params={"path": "src/a.c"},
        )

    assert response.status_code == 200
    assert response.json()["evidence"][0]["replay_environment"] == {
        "BIGEYE_MODE": "encrypted",
        "GITHUB_PAT": "[REDACTED]",
        "DATABASE_URL": "[REDACTED]",
        "DATABASE_QUERY_URL": "[REDACTED]",
        "ENCODED_AUTH_URL": "[REDACTED]",
        "ENCODED_BASIC_URL": "[REDACTED]",
        "authentication": "[REDACTED]",
    }


def test_retained_testcase_route_rejects_untrusted_identity_without_leaking_paths():
    class RejectingCoverage(_Coverage):
        async def retained_testcase(self, *_args):
            raise CoverageIntegrityError("/Users/private/secret was replaced")

    with _client(RejectingCoverage()) as client:
        response = client.get(
            "/api/projects/7/coverage/lines/12/testcases/33",
            params={"path": "src/a.c", "sha256": "b" * 64},
        )

    assert response.status_code == 422
    assert response.json() == {"detail": "invalid source path or range"}


def test_source_route_enforces_bounded_ranges_before_service_call():
    coverage = _Coverage()
    with _client(coverage) as client:
        invalid = client.get("/api/projects/7/coverage/source", params={
            "path": "src/a.c", "start_line": 1, "end_line": 502,
        })

    assert invalid.status_code == 422


def test_source_route_pages_to_a_deep_link_beyond_line_five_hundred():
    with _client() as client:
        response = client.get("/api/projects/7/coverage/source", params={
            "path": "src/a.c", "start_line": 501, "end_line": 1_000,
        })

    assert response.status_code == 200
    assert response.json()["start_line"] == 501
    assert response.json()["total_lines"] == 742


def test_tree_route_returns_a_truthful_empty_success_when_no_coverage_exists():
    class EmptyCoverage(_Coverage):
        async def project_tree(self, project_id, limit=1_000, offset=0):
            return {
                "project_id": project_id, "commit_sha": "a" * 40, "files": [],
                "summary": {"lines": None, "functions": None, "branches": None},
                "history": [],
                "pagination": {"limit": limit, "offset": offset, "total": 0},
            }

    with _client(EmptyCoverage()) as client:
        response = client.get("/api/projects/7/coverage/tree")

    assert response.status_code == 200
    assert response.json()["files"] == []
    assert response.json()["pagination"]["total"] == 0


def test_source_route_maps_containment_failure_without_leaking_host_path():
    class RejectingCoverage(_Coverage):
        async def source_file(self, *_args):
            raise ValueError("/Users/private/secret escaped checkout")

    with _client(RejectingCoverage()) as client:
        response = client.get("/api/projects/7/coverage/source", params={"path": "../secret"})

    assert response.status_code == 422
    assert response.json() == {"detail": "invalid source path or range"}


def test_coverage_pagination_is_bounded_at_http_boundary():
    with _client() as client:
        tree = client.get("/api/projects/7/coverage/tree", params={"limit": 1001})
        functions = client.get("/api/projects/7/coverage/functions", params={"path": "src/a.c", "offset": -1})
        evidence = client.get("/api/projects/7/coverage/lines/1", params={"path": "src/a.c", "limit": 501})

    assert (tree.status_code, functions.status_code, evidence.status_code) == (422, 422, 422)
