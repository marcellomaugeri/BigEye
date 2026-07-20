"""Continuous, event-driven ownership of one project's campaign decisions."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from dataclasses import replace
import inspect

from backend.services.campaigns.wake_rules import CampaignSnapshot, ReviewTrigger, WakeEvaluator


class PostgresProjectLock:
    """Hold one session advisory lock for the complete coordinator lifetime."""

    def __init__(self, pool):
        self._pool = pool

    @asynccontextmanager
    async def acquire(self, project_id: int):
        _project_id(project_id)
        async with self._pool.acquire() as connection:
            acquired = await connection.fetchval(
                "SELECT pg_try_advisory_lock($1::bigint)", project_id,
            )
            if type(acquired) is not bool:
                raise RuntimeError("PostgreSQL returned an invalid advisory lock result")
            primary_error = None
            try:
                yield acquired
            except BaseException as error:
                primary_error = error
                raise
            finally:
                if acquired:
                    try:
                        released = await connection.fetchval(
                            "SELECT pg_advisory_unlock($1::bigint)", project_id,
                        )
                        if released is not True:
                            raise RuntimeError("PostgreSQL did not release the project advisory lock")
                    except BaseException as cleanup_error:
                        if primary_error is not None:
                            primary_error.add_note(f"project advisory unlock also failed: {cleanup_error}")
                        else:
                            raise


class ProjectCoordinator:
    """Reconcile durable facts and invoke the manager only for typed wake triggers."""

    def __init__(
        self,
        *,
        projects,
        bootstrap,
        discovery,
        manager,
        decision_executor,
        runtime,
        advisory_lock,
        events=None,
        wake_evaluator: WakeEvaluator | None = None,
        clock=None,
    ):
        self.projects = projects
        self._bootstrap = bootstrap
        self._discovery = discovery
        self._manager = manager
        self.decision_executor = decision_executor
        self._runtime = runtime
        self._advisory_lock = advisory_lock
        self._events = events
        self._wake_evaluator = wake_evaluator or WakeEvaluator()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._previous: dict[int, CampaignSnapshot] = {}
        self._signals: dict[int, asyncio.Event] = {}
        self._actions: dict[int, asyncio.Lock] = {}

    @property
    def manager(self):
        return self._manager

    async def run(self, project_id: int) -> None:
        """Own one project until cancellation, pause/error, or another process owns it."""
        _project_id(project_id)
        async with self._advisory_lock.acquire(project_id) as acquired:
            if not acquired:
                return
            await self._bootstrap.schedule(project_id)
            project = await self.projects.get(project_id)
            if project is None or project.error is not None:
                return
            if project.paused_at is None:
                await self._discover(project)
            while True:
                project = await self.projects.get(project_id)
                if project is None or project.error is not None:
                    return
                snapshot = await self._runtime.reconcile(project)
                if not isinstance(snapshot, CampaignSnapshot):
                    raise TypeError("campaign runtime must return a CampaignSnapshot")
                await self.tick(project_id, snapshot)
                await self._wait_for_change(project_id, snapshot)

    async def tick(self, project_id: int, snapshot: CampaignSnapshot) -> ReviewTrigger | None:
        """Apply one complete observation without polling or retaining Docker handles."""
        _project_id(project_id)
        if not isinstance(snapshot, CampaignSnapshot):
            raise TypeError("campaign observation must be a CampaignSnapshot")
        project = await self.projects.get(project_id)
        if project is None or project.error is not None:
            return None
        action_lock = self._actions.setdefault(project_id, asyncio.Lock())
        async with action_lock:
            if project.paused_at is not None:
                await self._runtime.pause(project_id)
                self._previous[project_id] = snapshot
                return None

            if snapshot.active_workers > project.worker_count:
                await self._runtime.enforce_worker_count(
                    project, snapshot.active_workers - project.worker_count,
                )
            free_slots = max(project.worker_count - snapshot.active_workers, 0)
            if snapshot.free_slots != free_slots:
                snapshot = replace(snapshot, free_slots=free_slots)

            previous = self._previous.get(project_id)
            trigger = self._wake_evaluator.evaluate(previous, snapshot, self._now())
            if trigger is not None and trigger.reason == "review window expired":
                snapshot = replace(snapshot, review_due=True)
            self._previous[project_id] = snapshot
            if trigger is None:
                return None

            if trigger.stop_campaign:
                await self._runtime.stop_campaigns(project, trigger.evidence_ids)
            try:
                context = await _await(self._runtime.review_context(project, snapshot))
                evidence = await _await(self._runtime.review_evidence(project, snapshot, trigger))
                decision = await self._manager.review(context, evidence, trigger.reason)
                await self.decision_executor.execute(project, decision)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                await self._record_manager_failure(project_id, trigger, error)
            return trigger

    def notify(self, project_id: int) -> None:
        """Wake one event wait after settings, Docker, asset, or evidence changes."""
        _project_id(project_id)
        self._signals.setdefault(project_id, asyncio.Event()).set()

    async def pause(self, project_id: int) -> None:
        """Gracefully stop project workers while preserving every durable artefact."""
        _project_id(project_id)
        action_lock = self._actions.setdefault(project_id, asyncio.Lock())
        async with action_lock:
            await self._runtime.pause(project_id)
        self.notify(project_id)

    async def resume(self, project_id: int) -> None:
        """Verify immutable identity before restarting the selected campaigns."""
        _project_id(project_id)
        project = await self.projects.get(project_id)
        if project is None:
            raise KeyError(project_id)
        if project.commit_sha is None:
            raise ValueError("project commit must be resolved before campaign resume")
        action_lock = self._actions.setdefault(project_id, asyncio.Lock())
        async with action_lock:
            await self._runtime.verify_resume(project)
            await self._runtime.resume(project)
        self.notify(project_id)

    async def _discover(self, project) -> None:
        discover = getattr(self._discovery, "discover", None)
        if discover is not None:
            await _await(discover(project))

    async def _wait_for_change(self, project_id: int, snapshot: CampaignSnapshot) -> None:
        signal = self._signals.setdefault(project_id, asyncio.Event())
        deadline = snapshot.next_review_after
        now = self._now()
        if deadline is not None and deadline <= now:
            deadline = None
        waiter = getattr(self._runtime, "wait_for_change", None)
        try:
            if waiter is not None:
                await _await(waiter(project_id, signal, deadline))
            elif deadline is None:
                await signal.wait()
            else:
                timeout = max((deadline - now).total_seconds(), 0.0)
                try:
                    async with asyncio.timeout(timeout):
                        await signal.wait()
                except TimeoutError:
                    pass
        finally:
            signal.clear()

    async def _record_manager_failure(
        self, project_id: int, trigger: ReviewTrigger, error: Exception,
    ) -> None:
        if self._events is None:
            return
        await self._events.append(project_id, "activity", {
            "decision": "manager review deferred",
            "motivation": f"Campaign review failed with {type(error).__name__}",
            "evidence_ids": list(trigger.evidence_ids),
            "next_review_condition": trigger.reason,
        })

    async def _apply_cpu_checkpoint(self, project, snapshot: CampaignSnapshot) -> None:
        """Task 15 seam: persist one runtime checkpoint without choosing retirement here."""
        apply_checkpoint = getattr(self._runtime, "apply_cpu_checkpoint", None)
        if apply_checkpoint is not None:
            await _await(apply_checkpoint(project, snapshot))

    async def _retirement_candidates(self, project, snapshot: CampaignSnapshot):
        """Task 15 seam: obtain evidence candidates; the manager still decides."""
        candidates = getattr(self._runtime, "retirement_candidates", None)
        if candidates is None:
            return ()
        return await _await(candidates(project, snapshot))

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("coordinator clock must return a timezone-aware datetime")
        return now


async def _await(value):
    return await value if inspect.isawaitable(value) else value


def _project_id(value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("project ID must be a positive integer")
