from __future__ import annotations

import asyncio
import json
from hashlib import sha256
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest


IMAGE_ID = "sha256:" + "a" * 64


def run(awaitable):
    return asyncio.run(awaitable)


class FakeReproducer:
    def __init__(self):
        self.cancelled = False

    async def prepare(self, project_id: int, finding_id: int):
        from backend.services.findings.reproduce_finding import PreparedReproduction

        assert (project_id, finding_id) == (7, 5)
        testcase = Path(self.testcase)
        return PreparedReproduction(
            project_id=7, finding_id=5, image_id=IMAGE_ID,
            command=("/opt/bigeye/reproduce", "/finding/input"),
            environment=MappingProxyType({"ASAN_OPTIONS": "abort_on_error=1"}),
            testcase=testcase,
        )

    async def execute(self, prepared, emit):
        try:
            await emit("output", {"stream": "stderr", "text": b"AddressSanitizer:\xff overflow\x1b[31m\n"})
            return SimpleNamespace(exit_code=1, terminal_reason="exited")
        except asyncio.CancelledError:
            self.cancelled = True
            raise

    def reconcile_orphan(self, identity):
        self.reconciled = identity


def test_registry_persists_sanitised_stream_and_final_record(tmp_path: Path) -> None:
    from backend.services.findings.reproduction_registry import ReproductionRegistry

    service = FakeReproducer()
    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"crash")
    service.testcase = testcase
    registry = ReproductionRegistry(tmp_path / "workspace", service)

    async def scenario():
        started = await registry.start(7, 5)
        events = [event async for event in registry.stream(7, 5, started.run_id)]
        await registry.close()
        return started, events

    started, events = run(scenario())
    assert len(started.run_id) == 32
    assert [event["event"] for event in events] == ["reproduction", "output", "reproduction"]
    assert events[1]["data"] == {
        "stream": "stderr", "text": "AddressSanitizer:\ufffd overflow\n",
    }
    assert events[-1]["data"]["phase"] == "completed"
    run_root = (
        tmp_path / "workspace" / "projects" / "7" / "findings" / "5"
        / "reproductions" / started.run_id
    )
    assert "AddressSanitizer:\ufffd overflow\n" == (run_root / "terminal.log").read_text()
    final = json.loads((run_root / "final.json").read_text())
    assert final["phase"] == "completed" and final["exit_code"] == 1
    assert "ASAN_OPTIONS" not in json.dumps(events)
    assert registry._runs == registry._tasks == registry._locks == registry._queues == {}


def test_registry_persists_verified_sanitizer_crash_as_a_truthful_timeout(tmp_path: Path) -> None:
    from backend.services.findings.reproduction_registry import ReproductionRegistry
    from backend.services.findings.reproduce_finding import ReproductionOutcome

    class VerifiedTimeout(FakeReproducer):
        async def execute(self, prepared, emit):
            await emit("output", {"stream": "stderr", "text": "ERROR: AddressSanitizer decoder.c:36\n"})
            return ReproductionOutcome(
                None,
                "AddressSanitizer crash reproduced; emulator cleanup timed out",
                timed_out=True,
                sanitizer_crash_observed=True,
            )

    service = VerifiedTimeout()
    service.testcase = tmp_path / "testcase.input"
    Path(service.testcase).write_bytes(b"crash")
    registry = ReproductionRegistry(tmp_path / "workspace", service)

    async def scenario():
        started = await registry.start(7, 5)
        return started, [event async for event in registry.stream(7, 5, started.run_id)]

    started, events = run(scenario())
    final = events[-1]["data"]
    assert final["phase"] == "timed_out"
    assert final["exit_code"] is None
    assert final["sanitizer_crash_observed"] is True
    stored = json.loads((
        tmp_path / "workspace" / "projects" / "7" / "findings" / "5"
        / "reproductions" / started.run_id / "final.json"
    ).read_text())
    assert stored == final


def test_registry_rejects_duplicate_and_capacity_then_prunes_terminal_state(tmp_path: Path) -> None:
    from backend.services.findings.reproduction_registry import ReproductionBusy, ReproductionRegistry

    entered = asyncio.Event()

    class Blocking(FakeReproducer):
        async def prepare(self, project_id, finding_id):
            prepared = await super().prepare(7, 5)
            return __import__("dataclasses").replace(prepared, project_id=project_id, finding_id=finding_id)
        async def execute(self, prepared, emit):
            entered.set()
            await asyncio.Future()

    service = Blocking()
    service.testcase = tmp_path / "input"
    service.testcase.write_bytes(b"crash")
    registry = ReproductionRegistry(tmp_path / "workspace", service, max_concurrent=1)

    async def scenario():
        await registry.start(7, 5)
        await entered.wait()
        with __import__("pytest").raises(ReproductionBusy, match="already active"):
            await registry.start(7, 5)
        with __import__("pytest").raises(ReproductionBusy, match="capacity"):
            await registry.start(7, 6)
        await registry.close()

    run(scenario())
    assert registry._runs == registry._tasks == registry._locks == registry._queues == {}


@pytest.mark.parametrize("failure_stage", ["directory", "identity", "event", "task"])
def test_registry_releases_admission_after_each_pre_task_failure(
    tmp_path: Path, monkeypatch, failure_stage: str,
) -> None:
    from backend.services.findings.reproduction_registry import ReproductionRegistry

    service = FakeReproducer()
    service.testcase = tmp_path / "input"
    service.testcase.write_bytes(b"crash")
    registry = ReproductionRegistry(tmp_path / "workspace", service, max_concurrent=1)

    original_directory = registry._directory
    original_atomic = registry._atomic_json
    original_emit = registry._emit

    if failure_stage == "directory":
        monkeypatch.setattr(registry, "_directory", lambda _key: (_ for _ in ()).throw(OSError("directory")))
    elif failure_stage == "identity":
        monkeypatch.setattr(registry, "_atomic_json", lambda *_args: (_ for _ in ()).throw(OSError("identity")))
    elif failure_stage == "event":
        async def fail_event(*_args): raise OSError("event")
        monkeypatch.setattr(registry, "_emit", fail_event)
    else:
        monkeypatch.setattr(registry, "_launch", lambda *_args: (_ for _ in ()).throw(OSError("task")), raising=False)

    async def scenario():
        with pytest.raises(OSError, match=failure_stage):
            await registry.start(7, 5)
        monkeypatch.setattr(registry, "_directory", original_directory)
        monkeypatch.setattr(registry, "_atomic_json", original_atomic)
        monkeypatch.setattr(registry, "_emit", original_emit)
        if failure_stage == "task":
            monkeypatch.undo()
        admitted = await registry.start(7, 5)
        events = [event async for event in registry.stream(7, 5, admitted.run_id)]
        await registry.close()
        return events

    assert run(scenario())[-1]["data"]["phase"] == "completed"


def test_sealed_bundle_verifies_itself_without_mutable_resolver(tmp_path: Path) -> None:
    from backend.fuzzing.crashes.reproduction_bundle import ReproductionBundleStore

    identity = {
        "project_id": 7, "finding_id": 5, "commit_sha": "a" * 40,
        "image_id": IMAGE_ID, "command": ["/reproduce", "/finding/input"],
        "environment": [["ASAN_OPTIONS", "abort_on_error=1"]],
        "sanitizer": "asan", "configuration": "exact",
        "testcase_sha256": sha256(b"crash").hexdigest(),
        "target_asset_hash": "b" * 64, "configuration_asset_hash": "c" * 64,
        "coverage_asset_hash": "d" * 64,
    }
    bundle_id = sha256(json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    root = tmp_path / "workspace" / "projects" / "7" / "findings" / "5" / "bundle" / bundle_id
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({"bundle_id": bundle_id, **identity}) + "\n")
    (root / "testcase.input").write_bytes(b"crash")
    store = ReproductionBundleStore(tmp_path / "workspace", resolver=SimpleNamespace(
        verify=lambda _request: (_ for _ in ()).throw(AssertionError("mutable resolver used")),
    ))

    sealed = store.load_sealed(7, 5)
    assert sealed.bundle_id == bundle_id and sealed.verified is True
    (root / "testcase.input").write_bytes(b"tampered")
    with __import__("pytest").raises(ValueError, match="verification"):
        store.load_sealed(7, 5)


def test_prepare_freezes_current_validated_generation_when_bundle_is_not_yet_sealed(
    tmp_path: Path,
) -> None:
    from backend.services.findings.reproduce_finding import FindingReproductionService

    finding = SimpleNamespace(id=5, project_id=7, reproducible=True, error=None)
    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"crash")
    manifest = {
        "bundle_id": "b" * 64, "project_id": 7, "finding_id": 5,
        "image_id": IMAGE_ID, "command": ["/reproduce", "{input}"],
        "environment": [], "testcase_sha256": sha256(b"crash").hexdigest(),
        "sanitizer": "address",
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    bundle = SimpleNamespace(
        bundle_id="b" * 64, root=tmp_path, manifest=MappingProxyType(manifest), verified=True,
    )

    class Bundles:
        def __init__(self): self.freeze_calls = []
        def load_sealed(self, project_id, finding_id):
            raise ValueError("not sealed")
        async def freeze_for_finding(self, project_id, finding_id):
            self.freeze_calls.append((project_id, finding_id))
            return bundle

    class Docker:
        def connect(self):
            return SimpleNamespace(
                api=SimpleNamespace(inspect_image=lambda image_id: {
                    "Id": image_id, "Os": "linux", "Architecture": "amd64",
                }),
                close=lambda: None,
            )

    bundles = Bundles()
    service = FindingReproductionService(
        tmp_path,
        SimpleNamespace(get=lambda finding_id: asyncio.sleep(0, result=finding)),
        bundles,
        Docker(),
        finding_artifacts=SimpleNamespace(detail=lambda selected: {
            "reproducer": {"sha256": sha256(b"crash").hexdigest(), "size": 5},
            "replay": {"clean_variant": {
                "crashed": True, "error": None, "image_id": IMAGE_ID,
                "sanitizer": "address", "source_location": "src/decoder.c:36",
            }},
            "grouping": {
                "failure_class": "address", "reproducible": True,
                "harness_misuse": False,
                "minimised_sha256": sha256(b"crash").hexdigest(),
                "frames": [{"function": "decode_payload", "source_location": "decoder.c:36"}],
            },
        }),
    )
    prepared = run(service.prepare(7, 5))
    assert prepared.testcase == testcase.resolve()
    assert prepared.command == ("/reproduce", "/finding/input")
    assert prepared.expected_sanitizer == "address"
    assert prepared.expected_function == "decode_payload"
    assert prepared.expected_source_location == "src/decoder.c:36"
    assert prepared.bundle_id == "b" * 64
    assert bundles.freeze_calls == [(7, 5)]


def test_prepare_accepts_exact_stdin_marker_and_seals_bounded_testcase_bytes(
    tmp_path: Path,
) -> None:
    from backend.services.findings.reproduce_finding import FindingReproductionService

    finding = SimpleNamespace(id=5, project_id=7, reproducible=True, error=None)
    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"\x00exact-stdin\xff")
    manifest = {
        "bundle_id": "b" * 64, "project_id": 7, "finding_id": 5,
        "image_id": IMAGE_ID, "command": ["/opt/bigeye/build/decoder_cli", "{stdin}"],
        "environment": [], "testcase_sha256": sha256(b"\x00exact-stdin\xff").hexdigest(),
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    bundle = SimpleNamespace(bundle_id="b" * 64, root=tmp_path)

    class Docker:
        def connect(self):
            return SimpleNamespace(
                api=SimpleNamespace(inspect_image=lambda image_id: {
                    "Id": image_id, "Os": "linux", "Architecture": "amd64",
                }),
                close=lambda: None,
            )

    service = FindingReproductionService(
        tmp_path,
        SimpleNamespace(get=lambda finding_id: asyncio.sleep(0, result=finding)),
        SimpleNamespace(load_sealed=lambda *_args: bundle),
        Docker(),
    )

    prepared = run(service.prepare(7, 5))

    assert prepared.command == ("/opt/bigeye/build/decoder_cli",)
    assert prepared.stdin_bytes == b"\x00exact-stdin\xff"
    assert prepared.testcase == testcase.resolve()


def test_execute_passes_only_prepared_stdin_bytes_to_named_reproduction(
    tmp_path: Path, monkeypatch,
) -> None:
    from backend.fuzzing.docker.container_runner import ContainerResult
    from backend.services.findings.reproduce_finding import (
        FindingReproductionService,
        PreparedReproduction,
    )

    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"exact-stdin")
    prepared = PreparedReproduction(
        7, 5, IMAGE_ID, ("/opt/bigeye/build/decoder_cli",), MappingProxyType({}),
        testcase, run_id="a" * 32, stdin_bytes=b"exact-stdin",
    )
    observed = {}

    async def execute(self, image, command, timeout, sink, testcase_path, **kwargs):
        observed.update(
            image=image, command=command, timeout=timeout,
            testcase_path=testcase_path, kwargs=kwargs,
        )
        return ContainerResult(1, "AddressSanitizer\n")

    monkeypatch.setattr(
        "backend.services.findings.reproduce_finding.ContainerRunner.run_reproduction",
        execute,
    )
    service = FindingReproductionService(
        tmp_path, SimpleNamespace(), SimpleNamespace(),
        SimpleNamespace(connect=lambda: SimpleNamespace(close=lambda: None)),
    )

    outcome = run(service.execute(prepared, lambda *_args: asyncio.sleep(0)))

    assert outcome.exit_code == 1
    assert observed["command"] == ["/opt/bigeye/build/decoder_cli"]
    assert observed["kwargs"]["stdin_bytes"] == b"exact-stdin"
    assert observed["kwargs"]["run_id"] == "a" * 32


def test_verified_emulated_asan_timeout_preserves_timeout_truth_and_crash_observation(
    tmp_path: Path, monkeypatch,
) -> None:
    from backend.fuzzing.docker.container_runner import ContainerTimedOut
    from backend.services.findings.reproduce_finding import FindingReproductionService

    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"crash")
    prepared = __import__("backend.services.findings.reproduce_finding", fromlist=["PreparedReproduction"]).PreparedReproduction(
        project_id=7, finding_id=5, image_id=IMAGE_ID,
        command=("/reproduce", "/finding/input"), environment=MappingProxyType({}),
        testcase=testcase, run_id="a" * 32, expected_sanitizer="address",
        expected_function="decode_payload", expected_source_location="src/decoder.c:36",
        bundle_id="b" * 64, testcase_sha256=sha256(b"crash").hexdigest(),
    )
    observed = {}

    async def timeout(self, image, command, seconds, sink, testcase_path, **kwargs):
        observed.update(image=image, command=command, testcase=testcase_path, kwargs=kwargs)
        raise ContainerTimedOut(
            "wait froze",
            stderr=("ERROR: AddressSanitizer: stack-buffer-overflow src/decoder.c:36\n"
                    "==1==ABORTING\nqemu: uncaught target signal 6 (Aborted)\n"),
            cleanup_verified=True,
        )

    monkeypatch.setattr("backend.services.findings.reproduce_finding.ContainerRunner.run_reproduction", timeout)
    service = FindingReproductionService(
        tmp_path, SimpleNamespace(), SimpleNamespace(),
        SimpleNamespace(connect=lambda: SimpleNamespace(close=lambda: None)),
    )
    emitted = []
    outcome = run(service.execute(prepared, lambda event, data: asyncio.sleep(0, result=emitted.append((event, data)))))

    assert outcome.exit_code is None and outcome.timed_out is True
    assert outcome.sanitizer_crash_observed is True
    assert outcome.terminal_reason == "AddressSanitizer crash reproduced; emulator cleanup timed out"
    assert emitted == [("output", {
        "stream": "stdout",
        "text": "BigEye verified sanitizer evidence against retained replay: src/decoder.c:36 (decode_payload)\n",
    })]
    assert observed["command"] == ["/reproduce", "/finding/input"]
    assert observed["testcase"] == testcase


@pytest.mark.parametrize("change", [
    "cleanup", "sanitizer", "source", "qemu", "command", "testcase",
])
def test_unverified_timeout_is_not_reclassified_as_a_reproduced_crash(
    tmp_path: Path, monkeypatch, change: str,
) -> None:
    from backend.fuzzing.docker.container_runner import ContainerTimedOut
    from backend.services.findings.reproduce_finding import FindingReproductionService, PreparedReproduction

    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"crash")
    prepared = PreparedReproduction(
        7, 5, IMAGE_ID, ("/reproduce", "/finding/input"), MappingProxyType({}), testcase,
        run_id="a" * 32, expected_sanitizer="address", expected_function="decode_payload",
        expected_source_location="src/decoder.c:36",
        bundle_id="b" * 64, testcase_sha256=sha256(b"crash").hexdigest(),
    )
    stderr = ("ERROR: AddressSanitizer: stack-buffer-overflow src/decoder.c:36\n"
              "==1==ABORTING\nqemu: uncaught target signal 6 (Aborted)\n")
    if change == "sanitizer": stderr = stderr.replace("AddressSanitizer", "UndefinedBehaviorSanitizer")
    if change == "source": prepared = __import__("dataclasses").replace(
        prepared, expected_source_location=None,
    )
    if change == "qemu": stderr = stderr.replace("qemu: uncaught target signal 6 (Aborted)\n", "")
    if change == "command": prepared = __import__("dataclasses").replace(
        prepared, command=("/reproduce", "/some/other/input"),
    )
    if change == "testcase": testcase.write_bytes(b"changed after sealing")

    async def timeout(*_args, **_kwargs):
        raise ContainerTimedOut("wait froze", stderr=stderr, cleanup_verified=change != "cleanup")

    monkeypatch.setattr("backend.services.findings.reproduce_finding.ContainerRunner.run_reproduction", timeout)
    service = FindingReproductionService(
        tmp_path, SimpleNamespace(), SimpleNamespace(),
        SimpleNamespace(connect=lambda: SimpleNamespace(close=lambda: None)),
    )
    with pytest.raises(ContainerTimedOut):
        run(service.execute(prepared, lambda *_args: asyncio.sleep(0)))


@pytest.mark.parametrize("command", [
    ["/reproduce"],
    ["/reproduce", "{input}", "{input}"],
    ["/reproduce", "--file={input}"],
    ["/reproduce", "{stdin}", "{stdin}"],
    ["/reproduce", "{input}", "{stdin}"],
    ["/reproduce", "--stdin={stdin}"],
])
def test_prepare_rejects_an_incomplete_or_unsafe_frozen_input_marker(
    tmp_path: Path, command: list[str],
) -> None:
    from backend.services.findings.reproduce_finding import (
        FindingNotReproducible,
        FindingReproductionService,
    )

    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"crash")
    manifest = {
        "bundle_id": "b" * 64, "project_id": 7, "finding_id": 5,
        "image_id": IMAGE_ID, "command": command, "environment": [],
        "testcase_sha256": sha256(b"crash").hexdigest(),
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    bundle = SimpleNamespace(bundle_id="b" * 64, root=tmp_path)
    service = FindingReproductionService(
        tmp_path,
        SimpleNamespace(get=lambda finding_id: asyncio.sleep(0, result=SimpleNamespace(
            id=5, project_id=7, reproducible=True, error=None,
        ))),
        SimpleNamespace(load_sealed=lambda *_args: bundle),
        SimpleNamespace(),
    )

    with pytest.raises(FindingNotReproducible, match="command marker"):
        run(service.prepare(7, 5))


def test_on_demand_bundle_uses_selected_reproducer_and_clean_replay_contract(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.crashes.reproduction_bundle import (
        ProductionReproductionBundleResolver,
        ReproductionBundleStore,
    )

    finding = SimpleNamespace(
        id=5, project_id=7, fingerprint="f" * 64, reproducible=True, error=None,
    )
    campaign = SimpleNamespace(
        id=9, project_id=7, target_asset_id=11, configuration_asset_id=12,
    )
    assets = [
        SimpleNamespace(id=11, project_id=7, content_hash="b" * 64, validated_at=datetime.now(UTC), error=None),
        SimpleNamespace(id=12, project_id=7, content_hash="c" * 64, validated_at=datetime.now(UTC), error=None),
        SimpleNamespace(id=13, project_id=7, content_hash="d" * 64, validated_at=datetime.now(UTC), error=None),
    ]
    coverage = SimpleNamespace(
        project_id=7, commit_sha="a" * 40, clean_image_id=IMAGE_ID,
        clean_content_hash="e" * 64, target_asset_id=11, configuration_asset_id=12,
        clean_build_configuration_asset_id=12, coverage_asset_id=13,
        replay_command=("/opt/bigeye/reproduce", "{input}"),
        replay_environment=(("ASAN_OPTIONS", "abort_on_error=1"),),
    )

    class Images:
        def get(self, image_id): return SimpleNamespace(id=image_id)
    class Docker:
        def connect(self): return SimpleNamespace(images=Images(), close=lambda: None)

    resolver = ProductionReproductionBundleResolver(
        projects=SimpleNamespace(get=lambda project_id: asyncio.sleep(
            0, result=SimpleNamespace(id=7, commit_sha="a" * 40),
        )),
        findings=SimpleNamespace(get=lambda finding_id: asyncio.sleep(0, result=finding)),
        finding_artifacts=SimpleNamespace(
            read_reproducer=lambda selected: b"crash",
            detail=lambda selected: {
                "replay": {"clean_variant": {
                    "crashed": True, "sanitizer": "address", "image_id": IMAGE_ID,
                    "error": None,
                }},
            },
        ),
        assets=SimpleNamespace(list_for_project=lambda project_id: asyncio.sleep(0, result=assets)),
        campaigns=SimpleNamespace(for_finding=lambda project_id, fingerprint: asyncio.sleep(
            0, result=[campaign],
        )),
        invocations=SimpleNamespace(load_coverage=lambda project_id, campaign_id: coverage),
        docker=Docker(),
    )
    store = ReproductionBundleStore(tmp_path / "bundles", resolver)
    bundle = run(store.freeze_for_finding(7, 5))
    manifest = bundle.manifest
    assert manifest["testcase_sha256"] == sha256(b"crash").hexdigest()
    assert manifest["image_id"] == IMAGE_ID
    assert manifest["command"] == ["/opt/bigeye/reproduce", "{input}"]
    assert manifest["target_asset_hash"] == "b" * 64
    assert manifest["configuration_asset_hash"] == "c" * 64
    assert manifest["coverage_asset_hash"] == "d" * 64
    assert store.load_sealed(7, 5).bundle_id == bundle.bundle_id


def test_registry_marks_incomplete_history_interrupted_on_startup(tmp_path: Path) -> None:
    root = tmp_path / "workspace" / "projects" / "7" / "findings" / "5" / "reproductions" / ("b" * 32)
    root.mkdir(parents=True)
    (root / "events.jsonl").write_text(
        json.dumps({"event": "reproduction", "data": {"phase": "starting"}}) + "\n",
        encoding="utf-8",
    )
    identity = {"run_id": "b" * 32, "labels": {"com.bigeye.reproduction.run_id": "b" * 32}}
    (root / "container.json").write_text(json.dumps(identity) + "\n")

    from backend.services.findings.reproduction_registry import ReproductionRegistry

    service = FakeReproducer()
    service.testcase = tmp_path / "unused"
    ReproductionRegistry(tmp_path / "workspace", service)

    final = json.loads((root / "final.json").read_text())
    assert final["phase"] == "interrupted"
    assert final["terminal_reason"] == "backend restarted before reproduction completed"
    assert service.reconciled == identity


def test_registry_retries_the_exact_orphan_identity_until_cleanup_is_verified(tmp_path: Path) -> None:
    root = tmp_path / "workspace" / "projects" / "7" / "findings" / "5" / "reproductions" / ("c" * 32)
    root.mkdir(parents=True)
    (root / "events.jsonl").write_text(json.dumps({"event": "reproduction", "data": {"phase": "starting"}}) + "\n")
    from backend.fuzzing.docker.container_runner import reproduction_container_identity

    identity = reproduction_container_identity("c" * 32, 7, 5)
    (root / "container.json").write_text(json.dumps(identity) + "\n")

    class TransientFailure(FakeReproducer):
        def __init__(self):
            super().__init__()
            self.reconciled = []

        def reconcile_orphan(self, recorded_identity):
            self.reconciled.append(recorded_identity)
            if len(self.reconciled) == 1:
                raise RuntimeError("docker secret detail")

    from backend.services.findings.reproduction_registry import ReproductionRegistry
    service = TransientFailure()
    service.testcase = tmp_path / "unused"
    ReproductionRegistry(tmp_path / "workspace", service)

    assert not (root / "final.json").exists()
    pending = json.loads((root / "cleanup.json").read_text())
    assert pending["phase"] == "cleanup_pending"
    assert pending["verified"] is False
    assert pending["reason"] == "backend restarted; container cleanup could not be verified"
    assert "secret" not in json.dumps(pending)

    ReproductionRegistry(tmp_path / "workspace", service)

    final = json.loads((root / "final.json").read_text())
    assert final["phase"] == "interrupted"
    assert final["terminal_reason"] == "backend restarted before reproduction completed"
    cleanup = json.loads((root / "cleanup.json").read_text())
    assert cleanup["phase"] == "cleanup_verified"
    assert cleanup["verified"] is True
    assert service.reconciled == [identity, identity]


def test_registry_stream_disconnect_cancels_active_reproduction(tmp_path: Path) -> None:
    from backend.services.findings.reproduction_registry import ReproductionRegistry
    from backend.services.findings.reproduce_finding import PreparedReproduction

    entered = asyncio.Event()

    class Blocking(FakeReproducer):
        async def execute(self, prepared: PreparedReproduction, emit):
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.cancelled = True
                raise

    service = Blocking()
    testcase = tmp_path / "testcase.input"
    testcase.write_bytes(b"crash")
    service.testcase = testcase
    registry = ReproductionRegistry(tmp_path / "workspace", service)

    async def scenario():
        started = await registry.start(7, 5)
        await entered.wait()
        stream = registry.stream(7, 5, started.run_id)
        await anext(stream)
        await stream.aclose()
        for _ in range(10):
            if service.cancelled:
                break
            await asyncio.sleep(0)
        await registry.close()

    run(scenario())
    assert service.cancelled is True
