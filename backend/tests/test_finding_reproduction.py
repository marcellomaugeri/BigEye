from __future__ import annotations

import asyncio
import json
from hashlib import sha256
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType, SimpleNamespace


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


def test_registry_records_interrupted_when_orphan_cleanup_cannot_be_verified(tmp_path: Path) -> None:
    root = tmp_path / "workspace" / "projects" / "7" / "findings" / "5" / "reproductions" / ("c" * 32)
    root.mkdir(parents=True)
    (root / "events.jsonl").write_text(json.dumps({"event": "reproduction", "data": {"phase": "starting"}}) + "\n")
    (root / "container.json").write_text(json.dumps({"run_id": "c" * 32}) + "\n")

    class Failing(FakeReproducer):
        def reconcile_orphan(self, _identity):
            raise RuntimeError("docker secret detail")

    from backend.services.findings.reproduction_registry import ReproductionRegistry
    service = Failing()
    service.testcase = tmp_path / "unused"
    ReproductionRegistry(tmp_path / "workspace", service)

    final = json.loads((root / "final.json").read_text())
    assert final["phase"] == "interrupted"
    assert final["terminal_reason"] == "backend restarted; container cleanup could not be verified"
    assert "secret" not in json.dumps(final)


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
