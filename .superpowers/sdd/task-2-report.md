# Task 2 report: project heavy-job execution slots

## Implemented behaviour

- Added `ProjectExecutionSlots`, a process-local ledger for compilation leases, pending start reservations, and Docker-observed running campaign IDs.
- Compilation leases wait only for Docker-heavy capacity and release in `finally`, including cancellation. A successful target preparation promotes its lease to the exact campaign ID only after `start_exact()` succeeds.
- Recovery first replaces the running-ID ledger with owned Docker observations. It reserves only available stopped campaigns, starts those exact candidates, promotes successful starts, and leaves excess campaigns durably queued without blocking reconciliation.
- Progression starts use the same nonblocking reservation. Stops, retirement, worker-limit enforcement, terminal observations, and coordinator settings notifications update or wake the ledger.
- The coordinator's `free_slots` comes from the heavy-job snapshot. `worker_count` remains the compatible project JSON field. No agent module imports the slot service.

## Corrected start contract

The first brief's wait-only interface was not safe for the existing synchronous recovery call path: a waiter could return before Docker start and another caller could admit simultaneously, while persisted-but-not-running rows could make recovery deadlock. The corrected contract uses atomic pending-start reservations and Docker-observed running identities; it does not count unstopped database rows or add a database lease table.

## RED/GREEN evidence

RED:

```text
backend/.venv/bin/python -m pytest backend/tests/test_execution_slots.py -q
2 failed: ModuleNotFoundError: backend.services.campaigns.execution_slots
```

GREEN:

```text
backend/.venv/bin/python -m pytest backend/tests/test_execution_slots.py backend/tests/test_target_preparation.py backend/tests/test_campaign_monitor.py backend/tests/test_project_coordinator.py backend/tests/test_coordinator_production_wiring.py -q
145 passed in 2.37s

backend/.venv/bin/python -m pytest backend/tests -q
1123 passed, 1 skipped, 3 deselected, 1 warning in 13.41s
```

## Files changed

- `backend/services/campaigns/execution_slots.py`
- `backend/services/campaigns/production_preparation.py`
- `backend/services/campaigns/production_runtime.py`
- `backend/services/campaigns/project_coordinator.py`
- `backend/api/dependencies.py`
- `backend/tests/test_execution_slots.py`
- `backend/tests/test_campaign_monitor.py`
- `backend/tests/test_coordinator_production_wiring.py`

## Commit

Task 2 implementation baseline: `734ed46`.

## Self-review and concerns

- The ledger is deliberately process-local and clears on restart; recovery reconstructs running identity from Docker before starts are attempted.
- Existing unrelated working-tree changes were not touched or staged.
- The full suite has one existing third-party `StarletteDeprecationWarning`; there were no test failures.

## Review fixes

- Each project ledger now stores its current configured limit. `compilation`,
  `try_fuzzing_start`, and `snapshot` refresh that limit from their supplied
  project, while admission predicates read the ledger value. A settings update
  configures the exact updated project before waking its coordinator.
- Reconciliation clears Docker-observed running campaign IDs when there are no
  active persisted campaigns, without connecting to Docker or treating a
  terminal persisted row as active.

### RED

```text
backend/.venv/bin/python -m pytest backend/tests/test_execution_slots.py backend/tests/test_campaign_monitor.py backend/tests/test_project_settings.py -q
3 failed, 20 passed in 2.62s

AttributeError: 'ProjectExecutionSlots' object has no attribute 'configure'
assert frozenset({9}) == frozenset()
TypeError: ProjectSettingsService.__init__() takes from 2 to 3 positional arguments but 4 were given
```

### GREEN

```text
backend/.venv/bin/python -m pytest backend/tests/test_execution_slots.py backend/tests/test_campaign_monitor.py backend/tests/test_project_settings.py -q
23 passed in 1.58s

backend/.venv/bin/python -m pytest backend/tests/test_execution_slots.py backend/tests/test_target_preparation.py backend/tests/test_campaign_monitor.py backend/tests/test_project_coordinator.py backend/tests/test_coordinator_production_wiring.py backend/tests/test_project_settings.py -q
148 passed in 3.34s

backend/.venv/bin/python -m pytest backend/tests -q
1126 passed, 1 skipped, 3 deselected, 1 warning in 12.45s
```

### Warning

```text
backend/.venv/lib/python3.14/site-packages/fastapi/testclient.py:1
  /Users/marcellomaugeri/Documents/BigEye/.worktrees/bigeye-backbone/backend/.venv/lib/python3.14/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa
```
