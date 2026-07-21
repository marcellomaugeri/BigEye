"""Bounded active reproduction registry with durable file-backed evidence."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from uuid import uuid4

from backend.fuzzing.crashes.artifacts import sanitise_terminal_output
from backend.fuzzing.docker.container_runner import reproduction_container_identity


_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_TERMINAL = {"completed", "failed", "timed_out", "interrupted"}


class ReproductionBusy(RuntimeError):
    """The small local reproduction safety capacity is already occupied."""


@dataclass(frozen=True)
class ReproductionRun:
    run_id: str
    project_id: int
    finding_id: int
    phase: str
    started_at: datetime
    completed_at: datetime | None
    image_id: str
    command: tuple[str, ...]
    exit_code: int | None = None
    terminal_reason: str | None = None
    sanitizer_crash_observed: bool = False


class ReproductionRegistry:
    def __init__(self, workspace: Path, reproducer, *, max_concurrent: int = 2):
        candidate = Path(workspace)
        if candidate.is_symlink():
            raise ValueError("reproduction workspace must not be a symlink")
        candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._workspace = candidate.resolve(strict=True)
        self._reproducer = reproducer
        if type(max_concurrent) is not int or max_concurrent <= 0:
            raise ValueError("reproduction concurrency limit must be positive")
        self._max_concurrent = max_concurrent
        self._admission = asyncio.Lock()
        self._active_findings: set[tuple[int, int]] = set()
        self._reserved = 0
        self._runs: dict[tuple[int, int, str], ReproductionRun] = {}
        self._tasks: dict[tuple[int, int, str], asyncio.Task] = {}
        self._queues: dict[tuple[int, int, str], set[asyncio.Queue]] = {}
        self._locks: dict[tuple[int, int, str], asyncio.Lock] = {}
        self._recover_incomplete()

    async def start(self, project_id: int, finding_id: int) -> ReproductionRun:
        finding_key = (project_id, finding_id)
        async with self._admission:
            if finding_key in self._active_findings:
                raise ReproductionBusy("finding reproduction is already active")
            if self._reserved >= self._max_concurrent:
                raise ReproductionBusy("local reproduction capacity is occupied")
            self._active_findings.add(finding_key)
            self._reserved += 1
        key = None
        reservation_owned = True
        try:
            prepared = await self._reproducer.prepare(project_id, finding_id)
            now = datetime.now(UTC)
            run_id = uuid4().hex
            if hasattr(prepared, "run_id"):
                prepared = replace(prepared, run_id=run_id)
            run = ReproductionRun(
                run_id, project_id, finding_id, "starting", now, None,
                prepared.image_id, prepared.command,
            )
            key = (project_id, finding_id, run.run_id)
            self._runs[key] = run
            self._queues[key] = set()
            self._locks[key] = asyncio.Lock()
            self._directory(key).mkdir(parents=True, mode=0o700)
            self._atomic_json(
                self._directory(key) / "container.json",
                reproduction_container_identity(run_id, project_id, finding_id),
            )
            await self._emit(key, "reproduction", self._view(run))
            task = self._launch(key, prepared)
            self._tasks[key] = task
            reservation_owned = False
            return run
        except BaseException:
            if key is not None:
                self._runs.pop(key, None)
                self._tasks.pop(key, None)
                self._locks.pop(key, None)
                self._queues.pop(key, None)
            if reservation_owned:
                await self._release(finding_key)
            raise

    def _launch(self, key, prepared) -> asyncio.Task:
        return asyncio.create_task(self._drive(key, prepared))

    async def stream(self, project_id: int, finding_id: int, run_id: str):
        key = self._key(project_id, finding_id, run_id)
        queue: asyncio.Queue = asyncio.Queue(maxsize=128)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            history = self._history(key)
            self._queues.setdefault(key, set()).add(queue)
        terminal = False
        try:
            for event in history:
                terminal = event["event"] == "reproduction" and event["data"].get("phase") in _TERMINAL
                yield event
            while not terminal:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except TimeoutError:
                    yield {"comment": "heartbeat"}
                    continue
                terminal = event["event"] == "reproduction" and event["data"].get("phase") in _TERMINAL
                yield event
            task = self._tasks.get(key)
            if task is not None and not task.done():
                await asyncio.shield(task)
        finally:
            subscribers = self._queues.get(key, set())
            subscribers.discard(queue)
            task = self._tasks.get(key)
            if not terminal and task is not None and not task.done():
                task.cancel()
            elif terminal and not subscribers and (task is None or task.done()):
                self._runs.pop(key, None)
                self._tasks.pop(key, None)
                self._locks.pop(key, None)
                self._queues.pop(key, None)

    async def close(self) -> None:
        tasks = tuple(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _drive(self, key, prepared) -> None:
        try:
            outcome = await self._reproducer.execute(
                prepared, lambda event, data: self._emit(key, event, data),
            )
            phase = "timed_out" if getattr(outcome, "timed_out", False) else "completed"
            await self._finish(
                key, phase, outcome.exit_code, outcome.terminal_reason,
                sanitizer_crash_observed=getattr(outcome, "sanitizer_crash_observed", False),
            )
        except asyncio.CancelledError:
            await self._finish(key, "interrupted", None, "reproduction cancelled")
            raise
        except Exception as error:
            phase = "timed_out" if error.__class__.__name__ == "ContainerTimedOut" else "failed"
            await self._finish(key, phase, None, "reproduction timed out" if phase == "timed_out" else "reproduction failed")
        finally:
            self._tasks.pop(key, None)
            self._runs.pop(key, None)
            self._locks.pop(key, None)
            self._queues.pop(key, None)
            await self._release((key[0], key[1]))

    async def _release(self, finding_key: tuple[int, int]) -> None:
        async with self._admission:
            if finding_key in self._active_findings:
                self._active_findings.remove(finding_key)
                self._reserved -= 1

    async def _finish(
        self, key, phase: str, exit_code: int | None, reason: str, *,
        sanitizer_crash_observed: bool = False,
    ) -> None:
        current = self._runs[key]
        run = replace(
            current, phase=phase, completed_at=datetime.now(UTC),
            exit_code=exit_code, terminal_reason=reason,
            sanitizer_crash_observed=sanitizer_crash_observed,
        )
        self._runs[key] = run
        data = self._view(run)
        self._atomic_json(self._directory(key) / "final.json", data)
        await self._emit(key, "reproduction", data)

    async def _emit(self, key, event: str, data: dict) -> None:
        if event == "output":
            data = {"stream": data["stream"], "text": sanitise_terminal_output(data["text"])}
        record = {"event": event, "data": data}
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            directory = self._directory(key)
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            with (directory / "events.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(encoded); handle.flush()
            if event == "output":
                with (directory / "terminal.log").open("a", encoding="utf-8") as handle:
                    handle.write(data["text"]); handle.flush()
            for queue in tuple(self._queues.get(key, ())):
                await queue.put(record)

    def _history(self, key) -> list[dict]:
        path = self._directory(key) / "events.jsonl"
        if not path.is_file() or path.is_symlink():
            raise LookupError("reproduction run not found")
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def _key(self, project_id: int, finding_id: int, run_id: str):
        if type(project_id) is not int or project_id <= 0 or type(finding_id) is not int or finding_id <= 0 or _RUN_ID.fullmatch(run_id) is None:
            raise LookupError("reproduction run not found")
        key = (project_id, finding_id, run_id)
        self._history(key)
        return key

    def _directory(self, key) -> Path:
        project_id, finding_id, run_id = key
        return self._workspace / "projects" / str(project_id) / "findings" / str(finding_id) / "reproductions" / run_id

    @staticmethod
    def _view(run: ReproductionRun) -> dict:
        return {
            "run_id": run.run_id, "phase": run.phase,
            "started_at": run.started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": None if run.completed_at is None else run.completed_at.isoformat().replace("+00:00", "Z"),
            "image_id": run.image_id, "command": list(run.command),
            "exit_code": run.exit_code, "terminal_reason": run.terminal_reason,
            "sanitizer_crash_observed": run.sanitizer_crash_observed,
        }

    @staticmethod
    def _atomic_json(path: Path, data: dict) -> None:
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)

    def _recover_incomplete(self) -> None:
        root = self._workspace / "projects"
        if not root.is_dir() or root.is_symlink():
            return
        for events in root.glob("*/findings/*/reproductions/*/events.jsonl"):
            run_root = events.parent
            if run_root.is_symlink() or (run_root / "final.json").exists() or _RUN_ID.fullmatch(run_root.name) is None:
                continue
            attempted_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            try:
                project_id = int(events.parents[4].name)
                finding_id = int(events.parents[2].name)
                identity_path = run_root / "container.json"
                if identity_path.is_symlink() or not identity_path.is_file():
                    raise ValueError("reproduction container identity is unavailable")
                identity = json.loads(identity_path.read_text(encoding="utf-8"))
                self._reproducer.reconcile_orphan(identity)
            except Exception:
                try:
                    self._atomic_json(run_root / "cleanup.json", {
                        "phase": "cleanup_pending",
                        "verified": False,
                        "attempted_at": attempted_at,
                        "reason": "backend restarted; container cleanup could not be verified",
                    })
                except (OSError, ValueError):
                    pass
                continue
            try:
                self._atomic_json(run_root / "cleanup.json", {
                    "phase": "cleanup_verified",
                    "verified": True,
                    "attempted_at": attempted_at,
                })
                data = {
                    "run_id": run_root.name, "phase": "interrupted", "started_at": None,
                    "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "image_id": None, "command": [], "exit_code": None,
                    "terminal_reason": "backend restarted before reproduction completed",
                    "sanitizer_crash_observed": False,
                }
                with events.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"event": "reproduction", "data": data}, sort_keys=True) + "\n")
                self._atomic_json(run_root / "final.json", data)
            except (OSError, ValueError):
                continue
