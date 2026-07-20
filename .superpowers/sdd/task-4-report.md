# Task 4 report: incremental pipeline actions

## Architecture

- Worker operation tool calls remain inert audit requests. After a worker attempt passes validation,
  `CampaignReviewCollection` derives a separate content-addressed `PipelineOperationRecord` bound to
  the project, worker tool call, draft paths, assertions, and factual evidence.
- The manager sees the stable pipeline action ID. Only an ID selected in `bounded_actions` enters the
  executable action set. `DecisionExecutor` then delegates it to `PipelineOperationService`; an
  unselected request cannot execute.
- `PipelineOperationService` validates project containment, dispatches only `build`, `probe`,
  `replay`, or `coverage`, records bounded debug/event evidence, and leases capacity only for
  compilation. Production target preparation already owns its complete compile-to-fuzzer lease, so
  dependency wiring does not acquire a second slot. Standalone replay and coverage processing never
  use a heavy slot.
- Generated versions now reuse exact validated content and select the latest healthy version as the
  parent of a small changed target/configuration/coverage asset. The target and coverage layer cache
  remains content-addressed; corpus-only paths remain outside image preparation.
- `TargetLifecycleService` authorises, but does not expose direct agent deletion. Never-functional
  deletion requires complete absence of successful probe/campaign/coverage/finding dependencies.
  Overlap deletion requires two comparable clean checkpoints, full subsumption, no unique crash,
  and a healthy retained strategy. Healthy low-value work produces a reversible unschedule action.
- `ReproductionBundleStore` atomically freezes and verifies the exact image, command, environment,
  sanitizer/configuration, minimal testcase, asset hashes, and commit before a finding-dependent
  deletion can be authorised. Runtime cleanup preserves images for stopped healthy campaigns.

## RED / GREEN evidence

RED was established before production implementation with:

```text
backend/.venv/bin/python -m pytest \
  backend/tests/test_pipeline_operations.py \
  backend/tests/test_target_preparation.py \
  backend/tests/test_overlap.py -q

11 failed, 76 passed
```

The failures were the expected missing pipeline record/service, manager promotion boundary, and
target lifecycle service.

Focused GREEN after implementation:

```text
backend/.venv/bin/python -m pytest \
  backend/tests/test_pipeline_operations.py \
  backend/tests/test_target_preparation.py \
  backend/tests/test_campaign_progression.py \
  backend/tests/test_overlap.py \
  backend/tests/test_crash_pipeline.py \
  backend/tests/test_release_persistence.py \
  backend/tests/test_agents.py \
  backend/tests/test_agent_tracing.py \
  backend/tests/test_coordinator_production_wiring.py -q

299 passed in 3.24s
```

Complete backend verification:

```text
backend/.venv/bin/python -m pytest -q

1142 passed, 1 skipped, 3 deselected in 13.42s
```

The full run reports one existing Starlette/httpx deprecation warning.

## Files

- `backend/agents/outputs/campaign_review.py`
- `backend/agents/tools/agent_dispatch.py`
- `backend/api/dependencies.py`
- `backend/fuzzing/campaigns/production_factory.py`
- `backend/fuzzing/campaigns/target_preparation.py`
- `backend/fuzzing/crashes/reproduction_bundle.py`
- `backend/repositories/asset_repository.py`
- `backend/services/campaigns/decision_executor.py`
- `backend/services/campaigns/pipeline_operations.py`
- `backend/services/campaigns/production_runtime.py`
- `backend/services/campaigns/target_lifecycle.py`
- `backend/tests/test_pipeline_operations.py`
- `backend/tests/test_overlap.py`
- `backend/tests/test_crash_pipeline.py`

`backend/agents/tools/agent_dispatch.py` is a necessary minimal addition to the plan's enumerated
file list: it binds the inert request to project/evidence context and returns the distinct
application-owned action ID to the manager. Without this wiring, manager selection cannot authorise
deterministic execution.

## Self-review and concerns

- No worker receives a host shell or Docker client, and no operation string outside the four-item
  vocabulary validates.
- Heavy capacity remains limited to compilation and actively fuzzing jobs; replay, coverage
  processing, lifecycle reasoning, bundle freezing, RAG, and agent calls are outside the ledger.
- Unselected and rejected worker attempts cannot execute. Sibling selected actions still fail
  independently through `ActionResult`.
- Lifecycle decisions fail closed on incomplete evidence or an unverifiable finding bundle. The
  implementation deliberately preserves healthy stopped assets rather than deleting them early.
- No user-facing lifecycle controls were added.
- Live Docker/agent acceptance is outside Task 4 and remains covered by the later controlled-loop and
  one-hour acceptance tasks; Task 4 verification used the focused and complete backend suites.

## Review correction

The rejected first pass exposed four boundary errors: operation requests were dispatched through
generic dependencies instead of typed production adapters, action identity omitted immutable input
state, preparation could repair while retaining the compilation lease, and lifecycle/bundle checks
were not connected to the manager/executor path. The correction now:

- binds build/probe to the exact accepted `TargetProposalRecord` and replay/coverage to an immutable
  campaign/artifact snapshot, with draft hashes and the project commit included in the action ID;
- executes all four operations through explicit production adapters and performs draft CAS before
  the first side effect;
- persists selected/completed/failed action state in a project-scoped atomic journal, so a restart
  cannot repeat a selected side effect and a failed selection wakes the manager with durable evidence;
- persists build/probe outcomes and releases the compilation slot before publishing failure and
  waking the manager; production preparation no longer invokes an internal repair agent;
- derives lifecycle actions from persisted evidence, executes them only through manager selection,
  and applies revision/content CAS immediately before deletion;
- verifies authoritative bundle dependencies and pins verified Docker images through cleanup;
- scopes target ancestry by stable logical target identity and successful probe lineage only; and
- records hashing/CAS/build failures in bounded debug output instead of losing the failure boundary.

Correction RED was `4 failed, 8 passed` in `test_pipeline_operations.py`. Focused correction GREEN
was `149 passed in 2.88s` across pipeline operations, overlap, crash pipeline, target preparation,
recovery cleanup, and development database tests. Additional compatibility verification passed
`113` baseline sanitizer tests; the manager/coordinator/agent group reached `194 passed` with one
stale count assertion, which was corrected. The full backend suite was deliberately deferred at the
integration owner's request to prioritise the demo handoff; it must be run once after all concurrent
task branches are integrated.

The final critical review tightened three remaining boundaries. Never-functional deletion now locks
and revalidates the exact failed attempt revision, removes only that asset's probe FK rows, and
deletes the asset in the same transaction. Overlap deletion now accepts the exact authorised
campaign identity, removes only its candidate-strategy coverage rows/checkpoints, detaches only that
stopped campaign, and leaves retained-strategy evidence intact. Build/probe promotion requires the
complete generated-path set and matching SHA snapshot; once promoted, the raw proposal ID is no
longer a selectable or manager-visible action. The targeted immutable-selection and real PostgreSQL
18.4 FK suite passed `12` tests, the lifecycle overlap suite passed `17` tests, and the schema
contract returned `DO` against the same disposable database. No broad suite was run for this final
correction, as requested.

Promotion also rejects a worker attempt that requests both build and probe for the same bound
proposal. The collection validates all pending promotions before publishing any action, quarantines
the ambiguous audit requests, and removes the attempt's unbound outputs on failure. A focused
regression confirms that one build or one probe remains valid while the combined pair yields no
actionable ID (`12 passed`).
