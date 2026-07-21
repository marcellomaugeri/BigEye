"""Focused contracts for the read-only libaom release acceptance observer."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.run_libaom_acceptance import (
    AcceptanceBlocker,
    AcceptanceRunner,
    DockerCampaignObserver,
    LIBAOM_REPOSITORY,
    LIBAOM_REVISION,
    LIBAOM_TAG,
    PublicProjectApi,
    atomic_write_report,
    project_submission,
    verify_report,
)


ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:" + "a" * 64


def campaign(
    campaign_id: int,
    engine: str,
    *,
    cpu_seconds: float = 10.0,
    stopped_at: str | None = None,
    error: str | None = None,
) -> dict:
    return {
        "id": campaign_id,
        "target_asset_id": 100 + campaign_id,
        "target_name": f"target-{campaign_id}",
        "configuration_asset_id": 200 + campaign_id,
        "configuration_name": f"configuration-{campaign_id}",
        "configuration_purpose": "baseline address and undefined behaviour sanitizers",
        "engine": engine,
        "started_at": "2026-07-21T08:00:00Z",
        "stopped_at": stopped_at,
        "last_heartbeat_at": "2026-07-21T08:01:00Z",
        "cpu_exposure_seconds": cpu_seconds,
        "error": error,
        "activity": "running" if stopped_at is None and error is None else "stopped",
    }


def docker_campaign(campaign_id: int, engine: str, *, running: bool = True) -> dict:
    return {
        "campaign_id": campaign_id,
        "container_id": f"container-{campaign_id}",
        "state": "running" if running else "exited",
        "image_id": IMAGE,
        "command": ["/usr/bin/fuzzer", "/campaign/corpus"],
        "engine": engine,
        "commit_sha": LIBAOM_REVISION,
        "project_id": 7,
        "sanitizers": ["address", "undefined"],
        "corpus": {"file_count": 2, "total_bytes": 8, "sha256": "b" * 64},
        "strategy": {
            "proposal_identity": "e" * 64,
            "instance_type": "system-level" if engine == "afl" else "component-level",
            "engine": engine,
            "argv": ["/opt/bigeye/build/fuzzer", "{input}"],
            "seed_set": ["f" * 64],
            "target": {"asset_id": 100 + campaign_id, "content_sha256": "c" * 64},
            "configuration": {"asset_id": 200 + campaign_id, "content_sha256": "d" * 64},
            "coverage": {
                "asset_id": 300 + campaign_id,
                "content_sha256": "e" * 64,
                "clean_image_id": IMAGE,
                "clean_content_sha256": "f" * 64,
            },
            "commit_sha": LIBAOM_REVISION,
        },
    }


def coverage() -> dict:
    return {
        "commit_sha": LIBAOM_REVISION,
        "summary": {
            "lines": {"covered": 120, "total": 1000, "percent": 12.0},
            "functions": {"covered": 20, "total": 100, "percent": 20.0},
            "branches": {"covered": 40, "total": 500, "percent": 8.0},
        },
        "files": [{"path": "av1/decoder/decodeframe.c", "covered_lines": 120}],
    }


def events() -> list[dict]:
    return [
        {
            "id": 10,
            "created_at": "2026-07-21T08:00:00Z",
            "stream": "debug",
            "payload": {
                "event": "agent.end",
                "agent": "Campaign manager",
                "model": "gpt-5.6-terra",
                "trace_id": "trace-1",
            },
        },
        {
            "id": 11,
            "created_at": "2026-07-21T08:00:01Z",
            "stream": "debug",
            "payload": {
                "event": "target preparation accepted",
                "target_asset_id": 101,
                "configuration_asset_id": 201,
                "retry": 1,
            },
        },
        {
            "id": 12,
            "created_at": "2026-07-21T08:00:02Z",
            "stream": "debug",
            "payload": {
                "event": "workflow.error",
                "agent": "Fuzzing worker",
                "error": {"type": "ValueError", "message": "one corrected attempt"},
            },
        },
    ]


class FakeApi:
    def __init__(self, *, projects: list[dict], snapshots: list[dict]):
        self.projects = projects
        self.snapshots = snapshots
        self.created: list[dict] = []
        self.snapshot_calls = 0

    async def list_projects(self) -> list[dict]:
        return self.projects

    async def create_project(self, payload: dict) -> dict:
        self.created.append(payload)
        project = {
            "id": "7",
            "repository_url": payload["repository_url"],
            "requested_revision": payload["revision"],
            "worker_count": payload["worker_count"],
            "commit_sha": None,
            "error": None,
        }
        self.projects.append(project)
        return project

    async def observe(self, project_id: str) -> dict:
        del project_id
        index = min(self.snapshot_calls, len(self.snapshots) - 1)
        self.snapshot_calls += 1
        return self.snapshots[index]


class FakeDocker:
    def __init__(self, observations: list[list[dict]]):
        self.observations = observations
        self.calls = 0

    async def observe(self, project_id: int, commit_sha: str) -> list[dict]:
        assert project_id == 7
        assert commit_sha == LIBAOM_REVISION
        index = min(self.calls, len(self.observations) - 1)
        self.calls += 1
        return self.observations[index]


class Clock:
    def __init__(self):
        self.value = datetime(2026, 7, 21, 8, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value

    async def sleep(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


def coverage_witness(campaign_id: int) -> dict:
    return {
        "campaign_id": campaign_id,
        "strategy_asset_id": 200 + campaign_id,
        "testcase_sha256": "9" * 64,
        "target_asset_id": 100 + campaign_id,
        "configuration_asset_id": 200 + campaign_id,
        "clean_image_id": IMAGE,
        "cpu_exposure_seconds": 1.0,
        "source_path": "av1/decoder/decodeframe.c",
        "line_number": 42,
    }


def snapshot(
    *,
    campaigns: list[dict],
    coverage_value: dict | None,
    coverage_evidence: list[dict] | None = None,
) -> dict:
    return {
        "project": {
            "id": "7",
            "repository_url": LIBAOM_REPOSITORY,
            "requested_revision": LIBAOM_REVISION,
            "worker_count": 4,
            "commit_sha": LIBAOM_REVISION,
            "error": None,
        },
        "campaigns": {
            "project_id": 7,
            "campaigns": campaigns,
            "assets": [
                {"id": 101, "kind": "harness", "name": "target-1", "parent_id": None},
                {"id": 201, "kind": "configuration", "name": "configuration-1", "parent_id": None},
                {
                    "id": 999, "kind": "harness-source", "name": "child-source.c",
                    "parent_id": 101,
                },
            ],
        },
        "coverage": coverage_value,
        "coverage_evidence": (
            [coverage_witness(value["id"]) for value in campaigns]
            if coverage_evidence is None and coverage_value is not None
            else coverage_evidence or []
        ),
        "findings": {"items": [], "next_cursor": None},
        "activity_events": [],
        "debug_events": events(),
        "failures": [],
    }


def test_source_identity_and_submission_are_exact_and_do_not_inject_fuzzing_inputs() -> None:
    assert LIBAOM_REPOSITORY == "https://aomedia.googlesource.com/aom"
    assert LIBAOM_REVISION == "ad44980d7f3c7a2605c25d51ea96946949000841"
    assert LIBAOM_TAG == "v3.13.2"

    public = project_submission(repository_token=None)
    assert public == {
        "repository_url": LIBAOM_REPOSITORY,
        "revision": LIBAOM_REVISION,
        "worker_count": 4,
    }
    private = project_submission(repository_token="read-only")
    assert private == {**public, "repository_token": "read-only"}
    forbidden = {
        "dockerfile", "build_command", "run_command", "harness", "seed",
        "corpus", "engine", "target", "targets", "configuration",
    }
    assert forbidden.isdisjoint(public)


def test_runner_reuses_the_exact_public_project_instead_of_resubmitting(tmp_path: Path) -> None:
    existing = {
        "id": "7", "repository_url": LIBAOM_REPOSITORY,
        "requested_revision": LIBAOM_REVISION, "worker_count": 4,
        "commit_sha": LIBAOM_REVISION, "error": None,
    }
    api = FakeApi(projects=[existing], snapshots=[])
    runner = AcceptanceRunner(api, FakeDocker([]), tmp_path)

    selected = asyncio.run(runner.ensure_project())

    assert selected == existing
    assert api.created == []


def test_runner_submits_only_the_public_project_request_when_no_exact_project_exists(tmp_path: Path) -> None:
    api = FakeApi(projects=[], snapshots=[])
    runner = AcceptanceRunner(api, FakeDocker([]), tmp_path, repository_token="read-only")

    selected = asyncio.run(runner.ensure_project())

    assert selected["id"] == "7"
    assert api.created == [{
        "repository_url": LIBAOM_REPOSITORY,
        "revision": LIBAOM_REVISION,
        "worker_count": 4,
        "repository_token": "read-only",
    }]


def test_public_api_collects_exact_line_evidence_from_clean_coverage() -> None:
    class CoverageApi(PublicProjectApi):
        def __init__(self):
            self.calls: list[tuple[str, dict]] = []

        async def _json(self, method: str, path: str, **kwargs):
            assert method == "GET"
            self.calls.append((path, kwargs.get("params", {})))
            if path.endswith("/coverage/source"):
                return {
                    "total_lines": 80,
                    "lines": [
                        {"number": 41, "covered": False, "strategy_count": 0},
                        {"number": 42, "covered": True, "strategy_count": 1},
                    ],
                }
            if path.endswith("/coverage/lines/42"):
                return {"evidence": [coverage_witness(1)], "pagination": {"total": 1}}
            raise AssertionError(path)

    api = CoverageApi()
    tree = coverage()
    tree["files"][0]["total_lines"] = 80

    result = asyncio.run(api._coverage_evidence("7", tree))

    assert result == [coverage_witness(1)]
    assert api.calls == [
        (
            "/api/projects/7/coverage/source",
            {"path": "av1/decoder/decodeframe.c", "start_line": 1, "end_line": 80},
        ),
        (
            "/api/projects/7/coverage/lines/42",
            {"path": "av1/decoder/decodeframe.c", "limit": 500, "offset": 0},
        ),
    ]


def test_docker_observer_reads_the_immutable_strategy_and_corpus_contract(tmp_path: Path) -> None:
    config_root = tmp_path / "config"
    corpus_root = tmp_path / "corpus"
    config_root.mkdir()
    corpus_root.mkdir()
    strategy = docker_campaign(1, "afl")["strategy"]
    (config_root / "strategy.json").write_text(json.dumps(strategy), encoding="utf-8")
    (config_root / "sanitizer-intent.json").write_text(json.dumps({
        "applied_primary": ["address", "undefined"],
    }), encoding="utf-8")
    (corpus_root / "seed").write_bytes(b"seed")
    labels = {
        "com.bigeye.managed": "fuzz-campaign",
        "com.bigeye.project-id": "7",
        "com.bigeye.commit-sha": LIBAOM_REVISION,
        "com.bigeye.campaign-id": "1",
        "com.bigeye.image-id": IMAGE,
        "com.bigeye.engine": "afl",
    }
    container = SimpleNamespace(
        id="container-1",
        reload=lambda: None,
        attrs={
            "Image": IMAGE,
            "State": {"Status": "running"},
            "Config": {
                "Labels": labels,
                "Entrypoint": None,
                "Cmd": ["afl-fuzz", "--", "/opt/bigeye/build/fuzzer"],
                "Env": ["ASAN_OPTIONS=abort_on_error=1", "OPENAI_API_KEY=must-not-appear"],
            },
            "Mounts": [
                {"Type": "bind", "Source": str(config_root), "Destination": "/campaign/config"},
                {"Type": "bind", "Source": str(corpus_root), "Destination": "/campaign/corpus"},
            ],
        },
    )

    observed = DockerCampaignObserver._container(container, 7, LIBAOM_REVISION)

    assert observed["strategy"] == strategy
    assert observed["corpus"]["file_count"] == 1
    assert observed["sanitizers"] == ["address", "undefined"]
    assert "OPENAI_API_KEY" not in json.dumps(observed)


def test_validated_clock_starts_only_after_real_container_and_clean_coverage(tmp_path: Path) -> None:
    healthy = [campaign(1, "afl"), campaign(2, "libfuzzer")]
    api = FakeApi(projects=[], snapshots=[
        snapshot(campaigns=[], coverage_value=None),
        snapshot(campaigns=healthy, coverage_value=coverage()),
        snapshot(campaigns=healthy, coverage_value=coverage()),
    ])
    docker = FakeDocker([
        [],
        [docker_campaign(1, "afl"), docker_campaign(2, "libfuzzer")],
        [docker_campaign(1, "afl"), docker_campaign(2, "libfuzzer")],
    ])
    clock = Clock()
    runner = AcceptanceRunner(
        api, docker, tmp_path, now=clock.now, sleeper=clock.sleep, poll_seconds=60,
    )

    report = asyncio.run(runner.run(validated_seconds=60))

    assert report["validated_fuzzing_started_at"] == "2026-07-21T08:01:00Z"
    assert report["validated_fuzzing_finished_at"] == "2026-07-21T08:02:00Z"
    assert report["elapsed_validated_fuzzing_seconds"] == 60
    assert {item["engine"] for item in report["campaigns"]} == {"afl", "libfuzzer"}
    assert report["coverage"]["lines"]["covered"] == 120
    assert report["coverage"]["branches"]["covered"] == 40
    assert report["agent_runs"][0]["agent"] == "Campaign manager"
    assert report["targets"][0]["content_hash"] == "c" * 64
    assert report["configurations"][0]["content_hash"] == "d" * 64
    assert {item["id"] for item in report["targets"]} == {101, 102}
    assert {item["id"] for item in report["configurations"]} == {201, 202, 301, 302}
    assert all(item["id"] != 999 for item in [*report["targets"], *report["configurations"]])
    assert report["targets"][0]["name"] == "target-1"
    assert report["corpus"]["campaigns"]["1"]["file_count"] == 2
    assert report["campaigns"][0]["strategy"]["argv"] == [
        "/opt/bigeye/build/fuzzer", "{input}",
    ]
    assert any(item["kind"] == "workflow.error" for item in report["failures"])


def test_validated_clock_rejects_stale_project_aggregate_coverage(tmp_path: Path) -> None:
    healthy = [campaign(1, "afl"), campaign(2, "libfuzzer")]
    stale = coverage_witness(99)
    current = snapshot(
        campaigns=healthy,
        coverage_value=coverage(),
        coverage_evidence=[stale],
    )
    clock = Clock()
    runner = AcceptanceRunner(
        FakeApi(projects=[], snapshots=[current, current]),
        FakeDocker([[
            docker_campaign(1, "afl"), docker_campaign(2, "libfuzzer"),
        ]]),
        tmp_path,
        now=clock.now,
        sleeper=clock.sleep,
        poll_seconds=60,
        start_timeout_seconds=60,
    )

    with pytest.raises(AcceptanceBlocker, match="no active fuzzer reached exact libaom code"):
        asyncio.run(runner.run(validated_seconds=60))

    latest = json.loads((tmp_path / "latest-report.json").read_text(encoding="utf-8"))
    assert latest["elapsed_validated_fuzzing_seconds"] == 0


@pytest.mark.parametrize(
    ("engine", "instance_type"),
    (("afl", "component-level"), ("libfuzzer", "system-level")),
)
def test_docker_observer_rejects_engine_instance_type_mismatch(
    tmp_path: Path, engine: str, instance_type: str,
) -> None:
    config_root = tmp_path / "config"
    corpus_root = tmp_path / "corpus"
    config_root.mkdir()
    corpus_root.mkdir()
    (corpus_root / "seed").write_bytes(b"seed")
    strategy = docker_campaign(1, engine)["strategy"]
    strategy["instance_type"] = instance_type
    (config_root / "strategy.json").write_text(json.dumps(strategy), encoding="utf-8")
    (config_root / "sanitizer-intent.json").write_text(json.dumps({
        "applied_primary": ["address", "undefined"],
    }), encoding="utf-8")
    container = SimpleNamespace(
        id="container-1",
        reload=lambda: None,
        attrs={
            "Image": IMAGE,
            "State": {"Status": "running"},
            "Config": {
                "Labels": {
                    "com.bigeye.managed": "fuzz-campaign",
                    "com.bigeye.project-id": "7",
                    "com.bigeye.commit-sha": LIBAOM_REVISION,
                    "com.bigeye.campaign-id": "1",
                    "com.bigeye.image-id": IMAGE,
                    "com.bigeye.engine": engine,
                },
                "Entrypoint": None,
                "Cmd": ["/opt/bigeye/build/fuzzer"],
                "Env": [],
            },
            "Mounts": [
                {"Type": "bind", "Source": str(config_root), "Destination": "/campaign/config"},
                {"Type": "bind", "Source": str(corpus_root), "Destination": "/campaign/corpus"},
            ],
        },
    )

    with pytest.raises(AcceptanceBlocker, match="engine and instance type"):
        DockerCampaignObserver._container(container, 7, LIBAOM_REVISION)


@pytest.mark.parametrize("missing", ("sanitizers", "corpus"))
def test_validated_clock_requires_baseline_sanitizers_and_exact_corpus(
    tmp_path: Path, missing: str,
) -> None:
    healthy = [campaign(1, "afl"), campaign(2, "libfuzzer")]
    observed = [docker_campaign(1, "afl"), docker_campaign(2, "libfuzzer")]
    if missing == "sanitizers":
        observed[0]["sanitizers"] = ["address"]
    else:
        observed[0]["corpus"] = {"file_count": 0, "sha256": "b" * 64}
    current = snapshot(campaigns=healthy, coverage_value=coverage())
    clock = Clock()
    runner = AcceptanceRunner(
        FakeApi(projects=[], snapshots=[current, current]),
        FakeDocker([observed]),
        tmp_path,
        now=clock.now,
        sleeper=clock.sleep,
        poll_seconds=60,
        start_timeout_seconds=60,
    )

    with pytest.raises(AcceptanceBlocker, match="no active fuzzer reached exact libaom code"):
        asyncio.run(runner.run(validated_seconds=60))


def test_runner_preserves_partial_report_and_raises_a_concise_acceptance_blocker(tmp_path: Path) -> None:
    only_afl = [campaign(1, "afl")]
    api = FakeApi(projects=[], snapshots=[
        snapshot(campaigns=only_afl, coverage_value=coverage()),
        snapshot(campaigns=only_afl, coverage_value=coverage()),
    ])
    clock = Clock()
    runner = AcceptanceRunner(
        api, FakeDocker([[docker_campaign(1, "afl")]]), tmp_path,
        now=clock.now, sleeper=clock.sleep, poll_seconds=60,
    )

    with pytest.raises(AcceptanceBlocker, match="component-level libFuzzer"):
        asyncio.run(runner.run(validated_seconds=60))

    latest = json.loads((tmp_path / "latest-report.json").read_text(encoding="utf-8"))
    assert latest["failures"]
    assert "component-level libFuzzer" in latest["failures"][-1]["message"]


def test_runner_resumes_validated_elapsed_time_without_counting_observer_downtime(tmp_path: Path) -> None:
    prior = {
        "run_id": "20260721T070000Z-deadbeef",
        "tag": LIBAOM_TAG,
        "repository_url": LIBAOM_REPOSITORY,
        "requested_revision": LIBAOM_REVISION,
        "resolved_revision": LIBAOM_REVISION,
        "project_id": "7",
        "validated_fuzzing_started_at": "2026-07-21T07:00:00Z",
        "validated_fuzzing_finished_at": None,
        "elapsed_validated_fuzzing_seconds": 60,
        "execution_slot_limit": 4,
        "maximum_active_heavy_jobs": None,
        "heavy_job_observation": {
            "available": False,
            "reason": "compilation leases are process-local and have no public read-only identity",
        },
        "maximum_active_fuzzing_jobs": 2,
        "maximum_healthy_candidates": 2,
        "targets": [], "configurations": [], "campaigns": [],
        "coverage": {"lines": None, "functions": None, "branches": None},
        "coverage_evidence": [coverage_witness(1)],
        "corpus": {"campaigns": {}}, "findings": [], "agent_runs": [],
        "retries": [], "failures": [],
    }
    atomic_write_report(tmp_path, prior)
    healthy = [campaign(1, "afl"), campaign(2, "libfuzzer")]
    current = snapshot(campaigns=healthy, coverage_value=coverage())
    api = FakeApi(projects=[{
        "id": "7", "repository_url": LIBAOM_REPOSITORY,
        "requested_revision": LIBAOM_REVISION, "worker_count": 4,
        "commit_sha": LIBAOM_REVISION, "error": None,
    }], snapshots=[current, current])
    docker = FakeDocker([[
        docker_campaign(1, "afl"), docker_campaign(2, "libfuzzer"),
    ]])
    clock = Clock()
    runner = AcceptanceRunner(
        api, docker, tmp_path, now=clock.now, sleeper=clock.sleep, poll_seconds=60,
    )

    report = asyncio.run(runner.run(validated_seconds=120))

    assert report["run_id"] == prior["run_id"]
    assert report["validated_fuzzing_started_at"] == prior["validated_fuzzing_started_at"]
    assert report["elapsed_validated_fuzzing_seconds"] == 120
    assert report["validated_fuzzing_finished_at"] == "2026-07-21T08:01:00Z"


def test_runner_does_not_resume_a_legacy_report_that_mislabeled_fuzzers_as_heavy_jobs(
    tmp_path: Path,
) -> None:
    project = {
        "id": "7",
        "repository_url": LIBAOM_REPOSITORY,
        "requested_revision": LIBAOM_REVISION,
        "worker_count": 4,
        "commit_sha": LIBAOM_REVISION,
        "error": None,
    }
    legacy = {
        "run_id": "20260721T070000Z-deadbeef",
        "tag": LIBAOM_TAG,
        "repository_url": LIBAOM_REPOSITORY,
        "requested_revision": LIBAOM_REVISION,
        "resolved_revision": LIBAOM_REVISION,
        "project_id": "7",
        "validated_fuzzing_started_at": "2026-07-21T07:00:00Z",
        "validated_fuzzing_finished_at": None,
        "elapsed_validated_fuzzing_seconds": 60,
        "execution_slot_limit": 4,
        "maximum_active_heavy_jobs": 2,
    }
    atomic_write_report(tmp_path, legacy)
    runner = AcceptanceRunner(FakeApi(projects=[project], snapshots=[]), FakeDocker([]), tmp_path)

    assert runner._resume_report(project, validated_seconds=120) is None


def test_report_verification_enforces_revision_engines_coverage_duration_and_slots() -> None:
    afl = {
        **campaign(1, "afl"),
        **{
            key: value
            for key, value in docker_campaign(1, "afl").items()
            if key not in {"campaign_id", "engine"}
        },
    }
    libfuzzer = {
        **campaign(2, "libfuzzer"),
        **{
            key: value
            for key, value in docker_campaign(2, "libfuzzer").items()
            if key not in {"campaign_id", "engine"}
        },
    }
    report = {
        "repository_url": LIBAOM_REPOSITORY,
        "requested_revision": LIBAOM_REVISION,
        "resolved_revision": LIBAOM_REVISION,
        "validated_fuzzing_started_at": "2026-07-21T08:00:00Z",
        "validated_fuzzing_finished_at": "2026-07-21T08:02:00Z",
        "elapsed_validated_fuzzing_seconds": 120,
        "execution_slot_limit": 4,
        "maximum_active_heavy_jobs": None,
        "heavy_job_observation": {
            "available": False,
            "reason": "compilation leases are process-local and have no public read-only identity",
        },
        "maximum_active_fuzzing_jobs": 4,
        "maximum_healthy_candidates": 4,
        "targets": [
            {"id": 101, "role": "target", "content_hash": "c" * 64},
            {"id": 102, "role": "target", "content_hash": "c" * 64},
        ],
        "configurations": [
            {"id": 201, "role": "configuration", "content_hash": "d" * 64},
            {"id": 202, "role": "configuration", "content_hash": "d" * 64},
            {"id": 301, "role": "coverage", "content_hash": "e" * 64},
            {"id": 302, "role": "coverage", "content_hash": "e" * 64},
        ],
        "campaigns": [afl, libfuzzer],
        "coverage": coverage()["summary"],
        "coverage_evidence": [coverage_witness(1), coverage_witness(2)],
        "corpus": {"campaigns": {}},
        "findings": [],
        "agent_runs": [{"event": "agent.end", "agent": "Campaign manager"}],
        "failures": [],
    }
    assert verify_report(report, required_seconds=120) == []

    broken = dict(report)
    broken["campaigns"] = [report["campaigns"][0]]
    assert any("component-level libFuzzer" in value for value in verify_report(broken, 120))
    broken = dict(report)
    broken["coverage"] = {**report["coverage"], "branches": None}
    assert any("branch coverage" in value for value in verify_report(broken, 120))
    broken = dict(report)
    broken["maximum_active_fuzzing_jobs"] = 5
    assert any("slot limit" in value for value in verify_report(broken, 120))
    broken = dict(report)
    broken["maximum_active_heavy_jobs"] = 4
    assert any("compilation" in value for value in verify_report(broken, 120))
    broken = dict(report)
    broken["coverage_evidence"] = [coverage_witness(99)]
    assert any("same active strategy" in value for value in verify_report(broken, 120))
    broken = {**report, "campaigns": [dict(afl), dict(libfuzzer)]}
    broken["campaigns"][0]["sanitizers"] = ["address"]
    assert any("AFL++ lacks initial ASan and UBSan" in value for value in verify_report(broken, 120))
    broken = {**report, "campaigns": [dict(afl), dict(libfuzzer)]}
    broken["campaigns"][0]["corpus"] = {"file_count": 0, "total_bytes": 0, "sha256": "b" * 64}
    assert any("corpus evidence" in value for value in verify_report(broken, 120))
    broken = {**report, "targets": [dict(value) for value in report["targets"]]}
    broken["targets"][0]["content_hash"] = "0" * 64
    assert any("strategy asset inventory" in value for value in verify_report(broken, 120))


def test_atomic_report_keeps_run_history_and_replaces_latest(tmp_path: Path) -> None:
    report = {"run_id": "20260721T080000Z-a1b2c3d4", "findings": []}

    run_path, latest_path = atomic_write_report(tmp_path, report)

    assert run_path == tmp_path / report["run_id"] / "report.json"
    assert latest_path == tmp_path / "latest-report.json"
    assert json.loads(run_path.read_text(encoding="utf-8")) == report
    assert json.loads(latest_path.read_text(encoding="utf-8")) == report
    assert list(tmp_path.rglob("*.tmp")) == []


def test_playwright_observer_is_read_only_and_covers_all_live_views() -> None:
    spec = (ROOT / "tests/e2e/libaom-hour.spec.ts").read_text(encoding="utf-8")

    for required in (
        LIBAOM_REPOSITORY,
        LIBAOM_REVISION,
        "Overview",
        "Fuzzing",
        "Source",
        "Findings",
        "Activity",
        "Current manager activity",
        "/api/projects",
        "/campaigns",
        "/coverage/tree",
        "/logs/activity",
        "cpu_exposure_seconds",
        "last_heartbeat_at",
    ):
        assert required in spec
    for forbidden in (
        "request.post(",
        "request.put(",
        "request.patch(",
        "request.delete(",
        "/pause",
        "/resume",
        "Start project",
        "New project",
        "docker rm",
        "page.route(",
    ):
        assert forbidden.casefold() not in spec.casefold()
