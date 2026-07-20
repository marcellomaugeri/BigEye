"""Process-local admission accounting for Docker compilation and fuzzing jobs."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProjectExecutionSnapshot:
    """One project-local view of the heavy jobs currently occupying capacity."""

    compilation_count: int
    pending_start_count: int
    running_campaign_ids: frozenset[int]
    limit: int

    @property
    def occupied(self) -> int:
        return self.compilation_count + self.pending_start_count + len(self.running_campaign_ids)

    @property
    def free_slots(self) -> int:
        return max(self.limit - self.occupied, 0)


@dataclass
class _ProjectLedger:
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)
    limit: int = 0
    compilations: dict[str, int | None] = field(default_factory=dict)
    pending_starts: set[int] = field(default_factory=set)
    running_campaign_ids: frozenset[int] = frozenset()


class _CompilationLease:
    def __init__(self, slots: "ProjectExecutionSlots", project_id: int, operation_id: str):
        self._slots = slots
        self._project_id = project_id
        self._operation_id = operation_id
        self._closed = False

    async def promote(self, campaign_id: int) -> None:
        """Record the exact fuzzer that replaces this compilation on context exit."""
        _positive(campaign_id, "campaign ID")
        ledger = self._slots._ledger(self._project_id)
        async with ledger.condition:
            if self._closed or self._operation_id not in ledger.compilations:
                raise RuntimeError("compilation lease is no longer active")
            ledger.compilations[self._operation_id] = campaign_id

    async def _close(self) -> None:
        if self._closed:
            return
        ledger = self._slots._ledger(self._project_id)
        async with ledger.condition:
            campaign_id = ledger.compilations.pop(self._operation_id, None)
            if campaign_id is not None:
                ledger.running_campaign_ids = ledger.running_campaign_ids | frozenset({campaign_id})
            self._closed = True
            ledger.condition.notify_all()


class _FuzzingStartReservation:
    def __init__(self, slots: "ProjectExecutionSlots", project_id: int, campaign_id: int):
        self._slots = slots
        self._project_id = project_id
        self._campaign_id = campaign_id
        self._promoted = False
        self._closed = False

    async def promote(self) -> None:
        """Atomically replace this pending start with its Docker-started campaign."""
        ledger = self._slots._ledger(self._project_id)
        async with ledger.condition:
            if self._closed or self._campaign_id not in ledger.pending_starts:
                raise RuntimeError("fuzzing start reservation is no longer active")
            ledger.pending_starts.remove(self._campaign_id)
            ledger.running_campaign_ids = ledger.running_campaign_ids | frozenset({self._campaign_id})
            self._promoted = True
            ledger.condition.notify_all()

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _traceback) -> None:
        if self._closed:
            return
        ledger = self._slots._ledger(self._project_id)
        async with ledger.condition:
            if not self._promoted:
                ledger.pending_starts.discard(self._campaign_id)
                ledger.condition.notify_all()
            self._closed = True


class ProjectExecutionSlots:
    """In-memory only project capacity for bounded Docker-heavy jobs."""

    def __init__(self):
        self._ledgers: dict[int, _ProjectLedger] = {}

    @asynccontextmanager
    async def compilation(self, project, operation_id: str):
        """Reserve one heavy-job slot and allow atomic promotion to a running fuzzer."""
        project_id, _ = _project(project)
        await self.configure(project)
        if (
            not isinstance(operation_id, str) or not operation_id.strip()
            or len(operation_id) > 256 or "\x00" in operation_id
        ):
            raise ValueError("compilation operation ID is invalid")
        ledger = self._ledger(project_id)
        async with ledger.condition:
            if operation_id in ledger.compilations:
                raise ValueError("compilation operation ID is already active")
            await ledger.condition.wait_for(lambda: self._available(ledger))
            ledger.compilations[operation_id] = None
        lease = _CompilationLease(self, project_id, operation_id)
        try:
            yield lease
        finally:
            await lease._close()

    async def try_fuzzing_start(self, project, campaign_id: int) -> _FuzzingStartReservation | None:
        """Return one exclusive start reservation, or None when capacity is full."""
        project_id, _ = _project(project)
        await self.configure(project)
        _positive(campaign_id, "campaign ID")
        ledger = self._ledger(project_id)
        async with ledger.condition:
            if campaign_id in ledger.running_campaign_ids:
                return None
            if campaign_id in ledger.pending_starts:
                return None
            if not self._available(ledger):
                return None
            ledger.pending_starts.add(campaign_id)
        return _FuzzingStartReservation(self, project_id, campaign_id)

    async def observe_running(self, project_id: int, campaign_ids: frozenset[int]) -> None:
        """Replace attested running identities after deterministic Docker inspection."""
        _positive(project_id, "project ID")
        if (
            not isinstance(campaign_ids, frozenset)
            or any(type(campaign_id) is not int or campaign_id <= 0 for campaign_id in campaign_ids)
        ):
            raise ValueError("running campaign IDs must be a frozen set of positive integers")
        ledger = self._ledger(project_id)
        async with ledger.condition:
            ledger.running_campaign_ids = campaign_ids
            ledger.pending_starts.difference_update(campaign_ids)
            ledger.condition.notify_all()

    async def configure(self, project) -> None:
        """Refresh a project's configured heavy-job limit and wake admission waiters."""
        project_id, limit = _project(project)
        ledger = self._ledger(project_id)
        async with ledger.condition:
            ledger.limit = limit
            ledger.condition.notify_all()

    async def snapshot(self, project) -> ProjectExecutionSnapshot:
        """Return capacity derived solely from Docker-heavy project work."""
        project_id, _ = _project(project)
        await self.configure(project)
        ledger = self._ledger(project_id)
        async with ledger.condition:
            return ProjectExecutionSnapshot(
                compilation_count=len(ledger.compilations),
                pending_start_count=len(ledger.pending_starts),
                running_campaign_ids=ledger.running_campaign_ids,
                limit=ledger.limit,
            )

    def notify(self, project_id: int) -> None:
        """Re-evaluate compilation waiters after a heavy-job state change."""
        _positive(project_id, "project ID")
        ledger = self._ledgers.get(project_id)
        if ledger is None:
            return
        asyncio.get_running_loop().create_task(self._notify(ledger))

    def _ledger(self, project_id: int) -> _ProjectLedger:
        return self._ledgers.setdefault(project_id, _ProjectLedger())

    @staticmethod
    def _available(ledger: _ProjectLedger) -> bool:
        return (
            len(ledger.compilations)
            + len(ledger.pending_starts)
            + len(ledger.running_campaign_ids)
        ) < ledger.limit

    @staticmethod
    async def _notify(ledger: _ProjectLedger) -> None:
        async with ledger.condition:
            ledger.condition.notify_all()


def _project(project) -> tuple[int, int]:
    project_id = getattr(project, "id", None)
    limit = getattr(project, "worker_count", None)
    _positive(project_id, "project ID")
    _positive(limit, "project worker count")
    return project_id, limit


def _positive(value, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
