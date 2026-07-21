"""Continuous, event-driven ownership of one project's campaign decisions."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from dataclasses import dataclass, replace
import hashlib
import inspect
import json
import math

from backend.fuzzing.coverage.overlap import RetirementCandidate
from backend.agents.outputs.campaign_review import RetirementActionRecord
from backend.services.campaigns.wake_rules import CampaignSnapshot, ReviewTrigger, WakeEvaluator
from backend.services.observability.redaction import redact


MANAGER_RETRY_DELAY_SECONDS = 30
MANAGER_FAILURE_BACKOFF_SECONDS = 300
MAX_MANAGER_REVIEW_ATTEMPTS = 2
MANAGER_REVIEW_TIMEOUT_SECONDS = 120


class ActionExecutionFailed(RuntimeError):
    """Keep a manager-selected deterministic action retryable without hiding its failure."""

    def __init__(self, evidence: dict):
        super().__init__("one or more selected campaign actions failed")
        self.evidence = evidence


@dataclass(frozen=True)
class _PendingReview:
    trigger: ReviewTrigger
    attempts: int
    retry_after: datetime
    context: object | None = None
    evidence: tuple[dict, ...] = ()
    prepared_actions: tuple[object, ...] = ()


class PostgresProjectLock:
    """Hold one session advisory lock for the complete coordinator lifetime."""

    def __init__(self, pool):
        self._pool = pool

    @asynccontextmanager
    async def acquire(self, project_id: int):
        lock_keys = _project_lock_keys(project_id)
        async with self._pool.acquire() as connection:
            acquired = await connection.fetchval(
                "SELECT pg_try_advisory_lock($1::integer, $2::integer)", *lock_keys,
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
                            "SELECT pg_advisory_unlock($1::integer, $2::integer)", *lock_keys,
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
        execution_slots=None,
        target_lifecycle=None,
        manager_retry_delay_seconds: float = MANAGER_RETRY_DELAY_SECONDS,
        manager_failure_backoff_seconds: float = MANAGER_FAILURE_BACKOFF_SECONDS,
    ):
        for value, label in (
            (manager_retry_delay_seconds, "manager retry delay"),
            (manager_failure_backoff_seconds, "manager failure backoff"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 < value <= 86_400
            ):
                raise ValueError(f"{label} must be finite and positive")
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
        self._execution_slots = execution_slots
        self._target_lifecycle = target_lifecycle
        self._manager_retry_delay_seconds = float(manager_retry_delay_seconds)
        self._manager_failure_backoff_seconds = float(manager_failure_backoff_seconds)
        self._previous: dict[int, CampaignSnapshot] = {}
        self._latest: dict[int, CampaignSnapshot] = {}
        self._pending_reviews: dict[int, _PendingReview] = {}
        self._action_failures: dict[int, dict[str, dict]] = {}
        self._action_failures_loaded: set[int] = set()
        self._signals: dict[int, asyncio.Event] = {}
        self._actions: dict[int, asyncio.Lock] = {}

    @property
    def manager(self):
        return self._manager

    async def run(self, project_id: int) -> None:
        """Own one project until cancellation, error, or another process owns it."""
        _project_id(project_id)
        async with self._advisory_lock.acquire(project_id) as acquired:
            if not acquired:
                return
            await self._bootstrap.schedule(project_id)
            project = await self.projects.get(project_id)
            if project is None or project.error is not None:
                return
            await self._discover(project)
            while True:
                project = await self.projects.get(project_id)
                if project is None or project.error is not None:
                    return
                pending = self._pending_reviews.get(project_id)
                now = self._now()
                durable_wake = getattr(project, "manager_wake_at", None)
                review_due = (
                    pending is not None and pending.retry_after <= now
                ) or (
                    durable_wake is not None and durable_wake <= now
                )
                if review_due:
                    refresh = getattr(type(self._runtime), "reconcile_for_review", None)
                    snapshot = await _await(
                        refresh(self._runtime, project)
                        if refresh is not None else self._runtime.reconcile(project)
                    )
                elif pending is not None and project_id in self._latest:
                    # A newly scheduled retry wakes the same event wait immediately. Do not
                    # enter artifact replay before its deadline; the due path above performs
                    # one fresh, lightweight review reconciliation first.
                    snapshot = self._latest[project_id]
                else:
                    snapshot = await self._interruptible_reconcile(project_id, project)
                    if snapshot is None:
                        continue
                if not isinstance(snapshot, CampaignSnapshot):
                    raise TypeError("campaign runtime must return a CampaignSnapshot")
                self._latest[project_id] = snapshot
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
        snapshot = replace(snapshot, manager_wake_at=getattr(project, "manager_wake_at", None))
        action_lock = self._actions.setdefault(project_id, asyncio.Lock())
        async with action_lock:
            await self._apply_cpu_checkpoint(project, snapshot)

            pending = self._pending_reviews.get(project_id)
            retirement_evidence = ()
            prepared_actions = pending.prepared_actions if pending is not None else ()
            if pending is None:
                retirement_candidates = await self._retirement_candidates(project, snapshot)
                if any(candidate.project_id != project_id for candidate in retirement_candidates):
                    raise ValueError("retirement candidate belongs to another project")
                retirement_evidence = tuple(
                    _retirement_evidence(candidate) for candidate in retirement_candidates
                )
                retirement_actions = tuple(
                    _retirement_action(candidate) for candidate in retirement_candidates
                )
                progression_actions = ()
                progression_provider = getattr(type(self._runtime), "progression_actions", None)
                if progression_provider is not None:
                    progression_actions = tuple(
                        await _await(progression_provider(self._runtime, project_id))
                    )
                lifecycle_actions = ()
                if self._target_lifecycle is not None:
                    lifecycle_actions = tuple(await _await(
                        self._target_lifecycle.prepared_actions(project_id)
                    ))
                prepared_actions = (*retirement_actions, *progression_actions, *lifecycle_actions)
                retirement_evidence = (*retirement_evidence, *(
                    {
                        "evidence_id": action.action_id,
                        "kind": "target_lifecycle_action",
                        "action_kind": action.kind,
                        "supporting_evidence_ids": list(action.evidence_ids),
                        "trusted_instructions": False,
                    }
                    for action in lifecycle_actions
                ))
                if retirement_evidence:
                    snapshot = replace(
                        snapshot,
                        overlap_candidate=True,
                        evidence_ids=tuple(dict.fromkeys((
                            *snapshot.evidence_ids,
                            *(item["evidence_id"] for item in retirement_evidence),
                        ))),
                    )

            if snapshot.active_workers > project.worker_count:
                await self._runtime.enforce_worker_count(
                    project, snapshot.active_workers - project.worker_count,
                )
            free_slots = (
                (await self._execution_slots.snapshot(project)).free_slots
                if self._execution_slots is not None
                else max(project.worker_count - snapshot.active_workers, 0)
            )
            if snapshot.free_slots != free_slots:
                snapshot = replace(snapshot, free_slots=free_slots)

            now = self._now()
            if pending is not None and pending.retry_after > now:
                return None
            previous = self._previous.get(project_id)
            trigger = pending.trigger if pending is not None else self._wake_evaluator.evaluate(
                previous, snapshot, now,
            )
            if trigger is None:
                self._previous[project_id] = snapshot
                return None

            if trigger.stop_campaign and pending is None:
                await self._runtime.stop_campaigns(project, trigger.evidence_ids)
            context = pending.context if pending is not None else None
            evidence = []
            manager_decision = None
            wake_at = None
            try:
                if context is None:
                    context = await _await(self._runtime.review_context(project, snapshot))
                current_evidence = await _await(
                    self._runtime.review_evidence(project, snapshot, trigger)
                )
                if not isinstance(current_evidence, list):
                    raise TypeError("campaign review evidence must be a list")
                evidence = [
                    *current_evidence,
                    *(dict(item) for item in pending.evidence),
                    *retirement_evidence,
                ] if pending is not None else [*current_evidence, *retirement_evidence]
                failures = await self._unresolved_action_failures(project_id)
                evidence = _prioritise_action_failures(failures, evidence)
                async with asyncio.timeout(MANAGER_REVIEW_TIMEOUT_SECONDS):
                    if prepared_actions:
                        decision = await self._manager.review(
                            context, evidence, trigger.reason,
                            prepared_actions=prepared_actions,
                        )
                    else:
                        decision = await self._manager.review(context, evidence, trigger.reason)
                selected_manager_decision = getattr(decision, "decision", None)
                if type(getattr(
                    selected_manager_decision, "next_review_delay_seconds", None,
                )) is int:
                    manager_decision = selected_manager_decision
                    wake_at = self._now() + timedelta(
                        seconds=manager_decision.next_review_delay_seconds
                    )
                results = await self.decision_executor.execute(project, decision)
                if isinstance(results, list):
                    failures = [result for result in results if getattr(result, "succeeded", True) is False]
                    if failures:
                        raise ActionExecutionFailed(_action_failure_evidence(project_id, failures))
                    await self._resolve_action_failures(
                        project_id,
                        evidence,
                        _successful_target_corrections(decision, results),
                    )
                if manager_decision is not None:
                    await self._schedule_manager_review(
                        project, wake_at, manager_decision.next_review_reason,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as error:
                attempts = (pending.attempts if pending is not None else 0) + 1
                retry_delay = (
                    self._manager_retry_delay_seconds
                    if attempts < MAX_MANAGER_REVIEW_ATTEMPTS
                    else self._manager_failure_backoff_seconds
                )
                failure_time = self._now()
                retry_at = failure_time + timedelta(seconds=retry_delay)
                earlier_deadlines = tuple(
                    deadline for deadline in (
                        wake_at,
                        snapshot.manager_wake_at,
                        snapshot.next_review_after,
                    )
                    if deadline is not None and deadline > failure_time
                )
                if earlier_deadlines:
                    retry_at = min(retry_at, *earlier_deadlines)
                retry_evidence = tuple(dict(item) for item in evidence)
                if isinstance(error, ActionExecutionFailed):
                    await self._record_action_failure(project_id, error.evidence)
                    retry_evidence = (*retry_evidence, error.evidence)
                retry_reason = (
                    f"Retry after {type(error).__name__}: {trigger.reason}"
                    if attempts < MAX_MANAGER_REVIEW_ATTEMPTS
                    else f"Failure backoff after {type(error).__name__}: {trigger.reason}"
                )
                await self._schedule_manager_review(project, retry_at, retry_reason)
                if attempts < MAX_MANAGER_REVIEW_ATTEMPTS:
                    self._pending_reviews[project_id] = _PendingReview(
                        trigger, attempts, retry_at,
                        context,
                        retry_evidence,
                        prepared_actions,
                    )
                else:
                    self._pending_reviews.pop(project_id, None)
                    self._previous[project_id] = _scheduled_snapshot(snapshot, trigger, retry_at)
                # Persistence above has committed the replacement deadline. Wake the same
                # coordinator event used by settings/runtime notifications so a stale wait is
                # replaced without polling or requiring a registry restart.
                self.notify(project_id)
                await self._record_manager_failure(project_id, trigger, error)
            else:
                self._pending_reviews.pop(project_id, None)
                if manager_decision is not None:
                    self._previous[project_id] = _scheduled_snapshot(snapshot, trigger, wake_at)
                else:
                    self._previous[project_id] = _consumed_snapshot(snapshot, trigger)
            return trigger

    def notify(self, project_id: int) -> None:
        """Wake one event wait after settings, Docker, asset, or evidence changes."""
        _project_id(project_id)
        if self._execution_slots is not None:
            self._execution_slots.notify(project_id)
        self._signals.setdefault(project_id, asyncio.Event()).set()

    async def _interruptible_reconcile(self, project_id: int, project):
        """Cancel long artifact work when a durable review deadline or notification wins."""
        signal = self._signals.setdefault(project_id, asyncio.Event())
        deadline = getattr(project, "manager_wake_at", None)
        pending = self._pending_reviews.get(project_id)
        if pending is not None and (deadline is None or pending.retry_after < deadline):
            deadline = pending.retry_after
        reconcile = asyncio.create_task(self._runtime.reconcile(project))
        interrupt = asyncio.create_task(self._wait_for_interrupt(signal, deadline))
        try:
            done, _ = await asyncio.wait(
                (reconcile, interrupt), return_when=asyncio.FIRST_COMPLETED,
            )
            if reconcile in done:
                await _cancel_task(interrupt)
                return await reconcile
            await _cancel_task(reconcile)
            if signal.is_set():
                signal.clear()
            return None
        finally:
            await _cancel_task(interrupt)
            await _cancel_task(reconcile)

    async def _wait_for_interrupt(
        self, signal: asyncio.Event, deadline: datetime | None,
    ) -> None:
        if deadline is None:
            await signal.wait()
            return
        timeout = max((deadline - self._now()).total_seconds(), 0.0)
        try:
            async with asyncio.timeout(timeout):
                await signal.wait()
        except TimeoutError:
            pass

    async def _discover(self, project) -> None:
        discover = getattr(self._discovery, "discover", None)
        if discover is not None:
            await _await(discover(project))

    async def _wait_for_change(self, project_id: int, snapshot: CampaignSnapshot) -> None:
        signal = self._signals.setdefault(project_id, asyncio.Event())
        project = await self.projects.get(project_id)
        deadline = getattr(project, "manager_wake_at", None) if project is not None else None
        now = self._now()
        if deadline is not None and deadline <= now:
            deadline = None
        pending = self._pending_reviews.get(project_id)
        if pending is not None and (deadline is None or pending.retry_after < deadline):
            deadline = pending.retry_after
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
            "next_review_reason": trigger.reason,
        })

    async def _record_action_failure(self, project_id: int, evidence: dict) -> None:
        evidence_id = evidence["evidence_id"]
        self._action_failures.setdefault(project_id, {})[evidence_id] = dict(evidence)
        if self._events is not None:
            await self._events.append(project_id, "debug", {
                **evidence,
                "event": "campaign.action_execution_failed",
                "trusted_instructions": False,
            })

    async def _unresolved_action_failures(self, project_id: int) -> tuple[dict, ...]:
        retained = self._action_failures.setdefault(project_id, {})
        if project_id in self._action_failures_loaded:
            return tuple(retained.values())
        self._action_failures_loaded.add(project_id)
        reader = getattr(type(self._events), "read_latest", None)
        if reader is None:
            return tuple(retained.values())
        before = -1
        resolved: set[str] = set()
        while True:
            page = await _await(reader(self._events, project_id, "debug", before, 100))
            if not isinstance(page, list):
                break
            for event in page:
                payload = getattr(event, "payload", None)
                if not isinstance(payload, dict):
                    continue
                if payload.get("event") == "campaign.action_failures_resolved":
                    resolved.update(
                        value for value in payload.get("resolved_evidence_ids", ())
                        if isinstance(value, str)
                    )
                    continue
                evidence_id = payload.get("evidence_id")
                if (
                    payload.get("kind") == "action_execution_failure"
                    and isinstance(evidence_id, str)
                    and evidence_id not in resolved
                    and evidence_id not in retained
                ):
                    retained[evidence_id] = {
                        key: value for key, value in payload.items()
                        if key not in {"event", "trusted_instructions"}
                    }
            if not getattr(page, "has_more", False) or page.next_offset == before:
                break
            before = page.next_offset
        return tuple(retained.values())

    async def _resolve_action_failures(
        self, project_id: int, evidence: list[dict], correction_action_ids: tuple[str, ...],
    ) -> None:
        if not correction_action_ids:
            return
        failed = tuple(
            item for item in evidence
            if item.get("kind") == "action_execution_failure"
        )
        if len(failed) != 1:
            return
        evidence_id = failed[0].get("evidence_id")
        retained = self._action_failures.setdefault(project_id, {})
        retained_failures = tuple(
            item for item in retained.values()
            if item.get("kind") == "action_execution_failure"
        )
        if (
            not isinstance(evidence_id, str)
            or len(retained_failures) != 1
            or retained_failures[0].get("evidence_id") != evidence_id
        ):
            return
        action_ids = retained_failures[0].get("action_ids")
        failure_details = retained_failures[0].get("failures")
        if (
            not isinstance(action_ids, (list, tuple))
            or len(action_ids) != 1
            or not isinstance(action_ids[0], str)
            or not isinstance(failure_details, (list, tuple))
            or len(failure_details) != 1
            or not isinstance(failure_details[0], dict)
            or failure_details[0].get("action_id") != action_ids[0]
        ):
            return
        failed_action_ids = {action_ids[0]}
        if not set(correction_action_ids).isdisjoint(failed_action_ids):
            return
        resolved_ids = (evidence_id,)
        for evidence_id in resolved_ids:
            retained.pop(evidence_id, None)
        if self._events is not None:
            await self._events.append(project_id, "debug", {
                "event": "campaign.action_failures_resolved",
                "resolved_evidence_ids": list(resolved_ids),
                "correction_action_ids": list(correction_action_ids),
                "trusted_instructions": False,
            })

    async def _schedule_manager_review(self, project, deadline: datetime, reason: str) -> None:
        await self.projects.schedule_manager_review(project.id, deadline, reason)
        schedule = getattr(self._runtime, "schedule_next_review", None)
        if schedule is not None:
            await _await(schedule(project, deadline, reason))

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
        values = await _await(candidates(project, snapshot))
        if (
            not isinstance(values, (tuple, list))
            or len(values) > 256
            or any(not isinstance(value, RetirementCandidate) for value in values)
        ):
            raise TypeError("retirement candidates must be bounded validated evidence")
        return tuple(values)

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("coordinator clock must return a timezone-aware datetime")
        return now


async def _await(value):
    return await value if inspect.isawaitable(value) else value


async def _cancel_task(task: asyncio.Task) -> None:
    if not task.done():
        task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def _prioritise_action_failures(failures, evidence) -> list[dict]:
    ordered = []
    seen = set()
    for item in (*failures, *evidence):
        if not isinstance(item, dict):
            continue
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or evidence_id in seen:
            continue
        seen.add(evidence_id)
        ordered.append(dict(item))
        if len(ordered) == 64:
            break
    return ordered


def _successful_target_corrections(decision, results) -> tuple[str, ...]:
    candidate_ids = {
        record.action_id for record in getattr(decision, "selected_pipeline_operations", ())
        if getattr(record, "operation", None) in {"build", "probe"}
    }
    candidate_ids.update(
        record.result_id for record in getattr(decision, "selected_target_proposals", ())
        if isinstance(getattr(record, "result_id", None), str)
    )
    return tuple(sorted(
        result.action_id for result in results
        if getattr(result, "succeeded", False) is True
        and result.action_id in candidate_ids
    ))


def _action_failure_evidence(project_id: int, failures: list[object]) -> dict:
    action_ids = sorted({str(result.action_id)[:128] for result in failures})
    error_types = sorted({
        str(result.error.error_type)[:64]
        for result in failures
        if getattr(result, "error", None) is not None
    })
    details = []
    for result in failures:
        error = getattr(result, "error", None)
        if error is None:
            continue
        item = {
            "action_id": str(result.action_id)[:128],
            "error_type": str(error.error_type)[:64],
            "message": str(error.message)[:2_000],
        }
        raw_details = getattr(error, "details", None)
        if isinstance(raw_details, dict):
            item.update({
                key: value for key, value in raw_details.items()
                if key in {
                    "phase", "command", "exit_code", "stderr", "generated_path_mapping",
                    "failing_seed", "testcase_sha256",
                }
            })
        details.append(redact(item))
    identity = json.dumps(
        {"action_ids": action_ids, "error_types": error_types, "failures": details},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()[:16]
    return {
        "evidence_id": f"action-failure:{project_id}:{digest}",
        "kind": "action_execution_failure",
        "action_ids": action_ids,
        "error_types": error_types,
        "failures": details,
    }


def _project_id(value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("project ID must be a positive integer")


def _project_lock_keys(project_id: int) -> tuple[int, int]:
    """Losslessly place a BIGINT project ID in PostgreSQL's disjoint two-key lock space."""
    _project_id(project_id)
    if project_id > 0x7FFF_FFFF_FFFF_FFFF:
        raise ValueError("project ID must fit PostgreSQL BIGINT")
    high = project_id >> 32
    low = project_id & 0xFFFF_FFFF
    if low > 0x7FFF_FFFF:
        low -= 0x1_0000_0000
    return high, low


def _retirement_evidence(candidate: RetirementCandidate) -> dict:
    return {
        "evidence_id": (
            f"retirement:{candidate.project_id}:{candidate.campaign_id}:{candidate.strategy_asset_id}:"
            f"{candidate.retained_campaign_id}:{candidate.retained_strategy_asset_id}"
        ),
        "project_id": candidate.project_id,
        "campaign_id": candidate.campaign_id,
        "strategy_asset_id": candidate.strategy_asset_id,
        "retained_campaign_id": candidate.retained_campaign_id,
        "retained_strategy_asset_id": candidate.retained_strategy_asset_id,
        "supporting_evidence_ids": list(candidate.evidence_ids),
        "reason": candidate.reason,
        "reversible": candidate.reversible,
        "preserved": ["assets", "corpus", "evidence", "reason"],
    }


def _retirement_action(candidate: RetirementCandidate) -> RetirementActionRecord:
    return RetirementActionRecord(
        action_id=(
            f"retirement:{candidate.project_id}:{candidate.campaign_id}:{candidate.strategy_asset_id}:"
            f"{candidate.retained_campaign_id}:{candidate.retained_strategy_asset_id}"
        ),
        project_id=candidate.project_id,
        campaign_id=candidate.campaign_id,
        strategy_asset_id=candidate.strategy_asset_id,
        retained_campaign_id=candidate.retained_campaign_id,
        retained_strategy_asset_id=candidate.retained_strategy_asset_id,
        evidence_ids=candidate.evidence_ids,
        reason=candidate.reason,
        reversible=candidate.reversible,
    )


def _consumed_snapshot(snapshot: CampaignSnapshot, trigger: ReviewTrigger) -> CampaignSnapshot:
    if trigger.reason == "review window expired" and not snapshot.review_due:
        return replace(snapshot, manager_wake_at=None)
    return snapshot


def _scheduled_snapshot(
    snapshot: CampaignSnapshot, trigger: ReviewTrigger, deadline: datetime,
) -> CampaignSnapshot:
    return replace(
        _consumed_snapshot(snapshot, trigger),
        review_due=False,
        next_review_after=deadline,
        manager_wake_at=deadline,
    )
