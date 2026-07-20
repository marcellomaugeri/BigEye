from __future__ import annotations

import asyncio
import json
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


def test_registry_marks_incomplete_history_interrupted_on_startup(tmp_path: Path) -> None:
    root = tmp_path / "workspace" / "projects" / "7" / "findings" / "5" / "reproductions" / ("b" * 32)
    root.mkdir(parents=True)
    (root / "events.jsonl").write_text(
        json.dumps({"event": "reproduction", "data": {"phase": "starting"}}) + "\n",
        encoding="utf-8",
    )

    from backend.services.findings.reproduction_registry import ReproductionRegistry

    service = FakeReproducer()
    service.testcase = tmp_path / "unused"
    ReproductionRegistry(tmp_path / "workspace", service)

    final = json.loads((root / "final.json").read_text())
    assert final["phase"] == "interrupted"
    assert final["terminal_reason"] == "backend restarted before reproduction completed"


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
