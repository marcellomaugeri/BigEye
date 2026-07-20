from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


class _Container:
    def __init__(self, logs: bytes = b""):
        self._logs = logs

    def stats(self, stream=False):
        assert stream is False
        return {"cpu_stats": {"cpu_usage": {"total_usage": 2_500_000_000}}}

    def logs(self, **kwargs):
        assert kwargs["tail"] == 200
        return self._logs


class _Containers:
    def __init__(self, container):
        self._container = container

    def get(self, container_id):
        assert container_id == "container-9"
        return self._container


def _campaign_workspace(root: Path, engine: str) -> Path:
    campaign = root / "projects" / "7" / "campaigns" / "9"
    for name in ("corpus", "output", "config", "logs"):
        (campaign / name).mkdir(parents=True, exist_ok=True)
    if engine == "afl":
        for name in ("queue", "crashes"):
            (campaign / "output" / "main" / name).mkdir(parents=True)
    return campaign


def _observe(root: Path, engine: str, logs: bytes = b""):
    from backend.services.campaigns.production_runtime import DockerCampaignMonitor

    return _observe_with_monitor(
        DockerCampaignMonitor(root, clock=lambda: NOW), root, engine, logs,
    )


def _observe_with_monitor(
    monitor, root: Path, engine: str, logs: bytes = b"", artifact_cursors=None,
):
    client = SimpleNamespace(containers=_Containers(_Container(logs)))
    project = SimpleNamespace(id=7)
    campaign = SimpleNamespace(id=9)
    identity = SimpleNamespace(container_id="container-9")
    invocation = SimpleNamespace(engine=engine)
    return monitor.observe(
        client, project, campaign, identity, invocation, artifact_cursors or {},
    )


def test_afl_monitor_parses_bounded_stats_and_hashes_new_artifacts(tmp_path: Path) -> None:
    campaign = _campaign_workspace(tmp_path, "afl")
    (campaign / "output" / "main" / "fuzzer_stats").write_text(
        "execs_done        : 1234\n"
        "execs_per_sec     : 45.5\n"
        "corpus_count      : 7\n"
        "saved_crashes     : 1\n",
    )
    (campaign / "output" / "main" / "queue" / "id:000001").write_bytes(b"queue")
    (campaign / "output" / "main" / "crashes" / "id:000002").write_bytes(b"crash")

    observed = _observe(tmp_path, "afl")

    assert observed.executions == 1234
    assert observed.executions_per_second == 45.5
    assert observed.queue_files == 1
    assert observed.crash_files == 1
    assert [(item.kind, item.relative_path) for item in observed.artifacts] == [
        ("crash", "output/main/crashes/id:000002"),
        ("corpus", "output/main/queue/id:000001"),
    ]
    assert all(len(item.content_sha256) == 64 for item in observed.artifacts)


def test_libfuzzer_monitor_uses_bounded_logs_and_never_follows_artifact_symlinks(
    tmp_path: Path,
) -> None:
    campaign = _campaign_workspace(tmp_path, "libfuzzer")
    (campaign / "corpus" / "seed").write_bytes(b"seed")
    (campaign / "output" / "crash-deadbeef").write_bytes(b"crash")
    (campaign / "output" / "session.log").write_bytes(b"not an artifact")
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    (campaign / "output" / "crash-link").symlink_to(outside)
    logs = (
        b"#20 INITED cov: 4 ft: 5 corp: 2/5b exec/s: 10 rss: 10Mb\n"
        b"#345 NEW cov: 8 ft: 9 corp: 3/9b lim: 4 exec/s: 77 rss: 11Mb\n"
    )

    with pytest.raises(ValueError, match="unsafe entry"):
        _observe(tmp_path, "libfuzzer", logs)

    (campaign / "output" / "crash-link").unlink()
    observed = _observe(tmp_path, "libfuzzer", logs)
    assert observed.executions == 345
    assert observed.executions_per_second == 77.0
    assert observed.queue_files == 1
    assert observed.crash_files == 1
    assert {item.relative_path for item in observed.artifacts} == {
        "corpus/seed", "output/crash-deadbeef",
    }


def test_monitor_cursor_eventually_visits_more_than_one_bounded_artifact_page(
    tmp_path: Path,
) -> None:
    from backend.services.campaigns.production_runtime import DockerCampaignMonitor

    campaign = _campaign_workspace(tmp_path, "afl")
    queue = campaign / "output" / "main" / "queue"
    for index in range(520):
        (queue / f"id:{index:06d}").write_bytes(str(index).encode())
    first = _observe_with_monitor(DockerCampaignMonitor(tmp_path, clock=lambda: NOW), tmp_path, "afl")
    cursors = {
        kind: (observed_ns, name)
        for kind, observed_ns, name in first.next_artifact_cursors
    }
    second = _observe_with_monitor(
        DockerCampaignMonitor(tmp_path, clock=lambda: NOW), tmp_path, "afl",
        artifact_cursors=cursors,
    )
    third = _observe_with_monitor(
        DockerCampaignMonitor(tmp_path, clock=lambda: NOW), tmp_path, "afl",
        artifact_cursors={
            kind: (observed_ns, name)
            for kind, observed_ns, name in second.next_artifact_cursors
        },
    )

    visited = {item.relative_path for item in (*first.artifacts, *second.artifacts)}
    assert first.queue_files == second.queue_files == 520
    assert len(first.artifacts) == 512
    assert len(second.artifacts) == 8
    assert len(visited) == 520
    assert third.artifacts == ()
    assert third.next_artifact_cursors == second.next_artifact_cursors


def test_libfuzzer_durable_cursor_observes_a_later_low_hash_name_after_restart(
    tmp_path: Path,
) -> None:
    from backend.services.campaigns.production_runtime import DockerCampaignMonitor

    campaign = _campaign_workspace(tmp_path, "libfuzzer")
    high = campaign / "corpus" / ("f" * 64)
    high.write_bytes(b"first")
    os.utime(high, ns=(1_000_000_000, 1_000_000_000))
    first = _observe_with_monitor(
        DockerCampaignMonitor(tmp_path, clock=lambda: NOW), tmp_path, "libfuzzer",
    )
    low = campaign / "corpus" / ("0" * 64)
    low.write_bytes(b"later")
    os.utime(low, ns=(2_000_000_000, 2_000_000_000))

    second = _observe_with_monitor(
        DockerCampaignMonitor(tmp_path, clock=lambda: NOW), tmp_path, "libfuzzer",
        artifact_cursors={
            kind: (observed_ns, name)
            for kind, observed_ns, name in first.next_artifact_cursors
        },
    )
    third = _observe_with_monitor(
        DockerCampaignMonitor(tmp_path, clock=lambda: NOW), tmp_path, "libfuzzer",
        artifact_cursors={
            kind: (observed_ns, name)
            for kind, observed_ns, name in second.next_artifact_cursors
        },
    )

    assert [item.relative_path for item in first.artifacts] == ["corpus/" + "f" * 64]
    assert [item.relative_path for item in second.artifacts] == ["corpus/" + "0" * 64]
    assert third.artifacts == ()


def test_oversized_libfuzzer_log_sample_is_truncated_to_its_bounded_tail(
    tmp_path: Path,
) -> None:
    _campaign_workspace(tmp_path, "libfuzzer")
    logs = b"x" * (300 * 1024) + b"\n#92 NEW cov: 8 ft: 9 corp: 3/9b exec/s: 12\n"

    observed = _observe(tmp_path, "libfuzzer", logs)

    assert observed.executions == 92
    assert observed.executions_per_second == 12.0


def test_monitor_rejects_an_unbounded_engine_stats_file(tmp_path: Path) -> None:
    campaign = _campaign_workspace(tmp_path, "afl")
    (campaign / "output" / "main" / "fuzzer_stats").write_bytes(b"x" * (64 * 1024 + 1))

    with pytest.raises(OverflowError, match="stats file"):
        _observe(tmp_path, "afl")


def test_runtime_periodically_resamples_without_a_review_deadline() -> None:
    from backend.services.campaigns.production_runtime import RepositoryCampaignRuntime

    runtime = RepositoryCampaignRuntime(
        tasks=None,
        assets=None,
        campaigns=None,
        discovery=None,
        containers=None,
        monitor_interval_seconds=0.01,
    )

    async def exercise() -> None:
        signal = asyncio.Event()
        async with asyncio.timeout(0.2):
            await runtime.wait_for_change(7, signal, None)
        assert signal.is_set() is False

    asyncio.run(exercise())


def test_artifact_processor_runs_crash_pipeline_before_corpus_and_persists_observability() -> None:
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.services.campaigns.production_evidence import (
        ArtifactProcessingOutcome,
        CampaignEvidenceProcessor,
    )
    from backend.services.campaigns.production_runtime import CampaignProgressObservation

    order = []

    class Handler:
        def __init__(self, kind):
            self.kind = kind

        async def process(self, **values):
            order.append(self.kind)
            artifact = values["artifact"]
            return ArtifactProcessingOutcome(
                artifact=artifact,
                accepted=True,
                evidence_id=f"{self.kind}:{artifact.content_sha256}",
                reason=f"{self.kind} evidence retained",
                durable_relative_path=f"durable/{self.kind}/{artifact.content_sha256}",
            )

    class Minimiser:
        async def minimise_if_needed(self, **_values):
            order.append("minimise")
            return "corpus-minimisation:7:9"

    class Events:
        def __init__(self):
            self.calls = []

        async def append(self, project_id, stream, payload):
            self.calls.append((project_id, stream, payload))

    crash = CampaignArtifactObservation("crash", "output/crash-a", "a" * 64, 5)
    corpus = CampaignArtifactObservation("corpus", "corpus/seed", "b" * 64, 4)
    progress = CampaignProgressObservation(
        campaign_id=9, cpu_seconds=2.0, heartbeat_at=NOW,
        queue_files=1, crash_files=1, evidence_id="progress:9", container_id="container-9",
        executions=100, executions_per_second=10.0, artifacts=(crash, corpus),
    )
    events = Events()
    service = CampaignEvidenceProcessor(
        corpus=Handler("corpus"), crashes=Handler("crash"),
        minimiser=Minimiser(), events=events,
    )

    result = asyncio.run(service.process(
        project=SimpleNamespace(id=7), campaign=SimpleNamespace(id=9),
        invocation=SimpleNamespace(engine="libfuzzer"), progress=progress, assets=(),
    ))

    assert order == ["crash", "corpus", "minimise"]
    assert result.corpus_opportunity is True
    assert result.replayed_crash is True
    assert result.evidence_ids == (
        "crash:" + "a" * 64,
        "corpus:" + "b" * 64,
        "corpus-minimisation:7:9",
    )
    assert [call[1] for call in events.calls] == ["activity", "activity", "debug"]


def test_runtime_passes_monitor_artifacts_to_processor_and_exposes_only_validated_wake_facts() -> None:
    from unittest.mock import AsyncMock

    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.services.campaigns.production_evidence import CampaignProcessingResult
    from backend.services.campaigns.production_runtime import (
        CampaignProgressObservation,
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=1)
    campaign = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="libfuzzer", stopped_at=None, next_review_after=None, error=None,
    )
    tasks, assets, campaigns = AsyncMock(), AsyncMock(), AsyncMock()
    tasks.list_for_project.return_value = []
    assets.list_for_project.return_value = []
    campaigns.list_for_project.return_value = [campaign]
    campaigns.record_heartbeat.return_value = False
    artifact = CampaignArtifactObservation("crash", "output/crash-a", "a" * 64, 5)
    progress = CampaignProgressObservation(
        9, 2.0, NOW, 0, 1, "progress:9", "container-9", artifacts=(artifact,),
    )
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation(
        (9,), (), ({"evidence_id": "progress:9"},), (progress,),
    )
    processor = AsyncMock()
    processor.process.return_value = CampaignProcessingResult(
        corpus_opportunity=False,
        replayed_crash=True,
        evidence=({"evidence_id": "finding:abc", "trusted_instructions": False},),
    )
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=SimpleNamespace(evidence=lambda _project_id: ()), containers=containers,
        invocations=SimpleNamespace(load=lambda *_args: SimpleNamespace(engine="libfuzzer")),
        evidence_processor=processor,
    )

    snapshot = asyncio.run(runtime.reconcile(project))

    assert snapshot.replayed_crash is True
    assert snapshot.corpus_opportunity is False
    assert "finding:abc" in snapshot.evidence_ids
    processor.process.assert_awaited_once()


def test_runtime_advances_durable_artifact_cursors_only_after_the_complete_page_succeeds() -> None:
    from unittest.mock import AsyncMock

    from backend.services.campaigns.production_evidence import CampaignProcessingResult
    from backend.services.campaigns.production_runtime import (
        CampaignProgressObservation,
        ContainerObservation,
        RepositoryCampaignRuntime,
    )

    project = SimpleNamespace(id=7, commit_sha="a" * 40, worker_count=1)
    campaign = SimpleNamespace(
        id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        engine="afl", stopped_at=None, next_review_after=None, error=None,
    )
    tasks, assets, campaigns = AsyncMock(), AsyncMock(), AsyncMock()
    tasks.list_for_project.return_value = []
    assets.list_for_project.return_value = []
    campaigns.list_for_project.return_value = [campaign]
    campaigns.record_heartbeat.return_value = False
    progress = CampaignProgressObservation(
        9, 2.0, NOW, 520, 0, "progress:9", "container-9",
        next_artifact_cursors=(("queue", 20, "id:000519"),),
    )
    containers = AsyncMock()
    containers.reconcile.return_value = ContainerObservation((9,), (), (), (progress,))
    processor = AsyncMock()
    processor.process.side_effect = [RuntimeError("retry page"), CampaignProcessingResult(False, False, ())]
    artifact_state = AsyncMock()
    artifact_state.cursors.return_value = {"queue": (10, "id:000511")}
    runtime = RepositoryCampaignRuntime(
        tasks=tasks, assets=assets, campaigns=campaigns,
        discovery=SimpleNamespace(evidence=lambda _project_id: ()), containers=containers,
        invocations=SimpleNamespace(load=lambda *_args: SimpleNamespace(engine="afl")),
        evidence_processor=processor, artifact_state=artifact_state,
    )

    asyncio.run(runtime.reconcile(project))
    artifact_state.advance_cursors.assert_not_awaited()
    asyncio.run(runtime.reconcile(project))

    assert containers.reconcile.await_args_list[0].args[3] == {
        9: {"queue": (10, "id:000511")},
    }
    artifact_state.advance_cursors.assert_awaited_once_with(
        7, 9, (("queue", 20, "id:000519"),),
    )
