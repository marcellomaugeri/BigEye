# BigEye Continuous Agent Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task with a fresh implementer and reviewer for every task.

**Goal:** Complete BigEye as a continuously running local fuzz-testing product whose project manager dynamically delegates bounded work, prepares and repairs agent-generated system and component targets, runs at most the configured number of CPU-heavy compilation or fuzzing jobs, measures clean coverage, triages crashes, and exposes real evidence through the UI.

**Architecture:** Keep FastAPI, the OpenAI Agents SDK, and orchestration on the host. Keep PostgreSQL, builds, probes, fuzzers, coverage replay, and finding reproduction in Docker on `linux/amd64`. One Terra manager owns each project and invokes the same general Luna fuzzing-worker agent multiple times through `Agent.as_tool()`; deterministic services validate and execute selected work. The configured project limit applies only to Docker compilation and active fuzzing jobs, never to OpenAI agent runs, crash triage, corpus reasoning, source inspection, or other API-side work.

**Tech Stack:** Python 3.14, FastAPI, asyncpg, OpenAI Agents SDK, Docker SDK for Python, PostgreSQL 18.4, React, TypeScript, Vite, Vitest, Playwright, pytest, LLVM 18, libFuzzer, AFL++ 4.21c, Docker Desktop on macOS or Docker Engine/Desktop on Linux.

## Global constraints

- Work in `/Users/marcellomaugeri/Documents/BigEye/.worktrees/bigeye-backbone` on `codex/bigeye-backbone`.
- Preserve existing uncommitted work. Before each task, inspect `git diff -- <task paths>` and stage only the files named by that task.
- Use test-driven development: add the failing focused test, run it and observe the expected failure, make the smallest implementation, then run the focused and neighbouring suites.
- Keep the backend on the host in `backend/.venv`; Docker is only for PostgreSQL and bounded repository build, probe, fuzzing, coverage, minimisation, replay, and reproduction work.
- Force `platform="linux/amd64"` in every image build and container run. Reject images whose inspected OS/architecture is not Linux/amd64.
- Do not use OSS-Fuzz or OSS-Fuzz-Gen code, images, Dockerfiles, build scripts, harnesses, corpora, dictionaries, or generated assets.
- Keep PostgreSQL as the structured store and file-backed artefacts under ignored `workspace/`. Update `backend/database/schema.sql` and its schema-contract tests directly; do not add migration tooling before release.
- Keep MVC boundaries: HTTP controllers translate requests, Pydantic views shape responses, repositories contain SQL, services own business workflows, and fuzzing/agents packages provide domain capabilities.
- Do not add fake campaigns, sample metrics, generated findings, or test-only runtime fallbacks to production code.
- Do not expose a host shell or raw Docker client to an agent. Agent tools must use contained project-relative paths and application-owned services.
- Do not expose manual pause, resume, stop, restart, or corpus editing controls. Pausing a container internally for atomic corpus replacement remains an implementation detail.
- Keep the existing database/API field `worker_count` for compatibility, but label it `Concurrent jobs` in the UI and interpret it only as the number of concurrent Docker compilation plus active-fuzzing jobs. Default it to four.
- Start new targets with ASan and UBSan. Add other sanitiser/configuration variants only when evidence justifies them. Keep AFL++ system-level and libFuzzer component-level measurements distinguishable.
- Missing line, function, or branch measurements are `null`/unavailable, never zero. Coverage percentages are derived only when numerator and denominator share the exact clean build.
- Retain exact revision, asset hashes, image IDs, commands, environment, corpus/testcase hashes, and deterministic evidence IDs. Do not infer a vulnerability from an agent statement alone.
- Keep the exact finding classifications: `harness-induced false positive`, `improper contract usage`, `true vulnerability`, `flaky or environmental`, and `unresolved`.
- Use deterministic priority rank plus a plain-language reason. Do not introduce an opaque numeric severity score.
- No task in this plan requires a new Python or frontend dependency. If implementation evidence proves one is required, install that exact package in `backend/.venv` with `python -m pip install`, then immediately refresh `backend/requirements.txt` with `python -m pip freeze`.

---

## Task 1: Persist manager-selected review deadlines and remove user pause semantics

**Files:**

- Modify: `backend/database/schema.sql`
- Modify: `backend/database/schema_contract.sql`
- Modify: `backend/models/project.py`
- Modify: `backend/repositories/project_repository.py`
- Modify: `backend/agents/outputs/campaign_decision.py`
- Modify: `backend/agents/prompts/manager.py`
- Modify: `backend/services/campaigns/project_coordinator.py`
- Modify: `backend/services/campaigns/wake_rules.py`
- Modify: `backend/services/projects/project_settings.py`
- Modify: `backend/api/controllers/settings.py`
- Modify: `backend/api/views/project.py`
- Test: `backend/tests/test_project_coordinator.py`
- Test: `backend/tests/test_wake_rules.py`
- Test: `backend/tests/test_agents.py`
- Test: `backend/tests/test_project_api.py`
- Test: `backend/tests/test_development_database.py`
- Test: `backend/tests/test_release_persistence.py`

### Step 1: Write failing structured-decision and persistence tests

Add tests proving that a valid manager decision contains a manager-selected positive delay and reason, with strict bounds:

```python
decision = CampaignDecision(
    decision="Keep the healthy parser campaigns running.",
    motivation="Coverage is still increasing on the exact clean build.",
    evidence_ids=["coverage:project:1:checkpoint:3"],
    bounded_actions=[],
    next_review_delay_seconds=900,
    next_review_reason="Recheck the current coverage slope and corpus growth.",
    uncertainty="The branch denominator is not available yet.",
)
assert decision.next_review_delay_seconds == 900
```

Test rejection at `59` and `3601` seconds. Test `ProjectRepository.schedule_manager_review(project_id, wake_at, reason)` and `clear_manager_review(project_id)` against PostgreSQL. A freshly created project must have both fields `NULL`.

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_agents.py \
  backend/tests/test_project_coordinator.py \
  backend/tests/test_wake_rules.py \
  backend/tests/test_development_database.py -q
```

Expected: new tests fail because the output and project-level wake fields do not exist.

### Step 2: Replace the fixed manager delay with a typed manager choice

Change `CampaignDecision` to:

```python
class CampaignDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(min_length=1, max_length=500)
    motivation: str = Field(min_length=1, max_length=2_000)
    evidence_ids: list[str] = Field(max_length=64)
    bounded_actions: list[str] = Field(max_length=16)
    next_review_delay_seconds: int = Field(ge=60, le=3_600)
    next_review_reason: str = Field(min_length=1, max_length=1_000)
    uncertainty: str = Field(min_length=1, max_length=2_000)
```

Update the manager prompt to require a concrete delay based on the selected work and to forbid “never” or an unbounded wait. Keep `parallel_tool_calls=True`.

### Step 3: Persist the project-level wake before campaigns exist

Replace `paused_at` in the fresh schema with:

```sql
manager_wake_at TIMESTAMPTZ,
manager_wake_reason TEXT,
```

Expose the two fields on `Project`. Add repository methods:

```python
async def schedule_manager_review(
    self, project_id: int, wake_at: datetime, reason: str,
) -> None:
    """Persist the exact next project-manager wake."""

async def clear_manager_review(self, project_id: int) -> None:
    """Clear a consumed project-manager wake."""
```

Every project query must select these fields. Remove `pause()` and `resume()` from the repository and the project-settings service. Remove the project pause/resume HTTP routes and `paused` response field. Keep the runtime's private container pause operation used for quiescent corpus replacement.

### Step 4: Make the coordinator use durable project deadlines

In `ProjectCoordinator.tick`:

- ignore the removed pause state;
- pass the project wake deadline into the snapshot before wake evaluation;
- after a successful manager review, calculate `wake_at = now + timedelta(seconds=decision.decision.next_review_delay_seconds)` and persist it with `decision.decision.next_review_reason`;
- on a manager/action failure, persist a bounded retry deadline before returning;
- clear or replace an expired deadline atomically as the review is consumed;
- continue running healthy fuzz containers during an OpenAI error;
- use a manager wall-clock timeout and existing turn budget; never wait forever for an API call.

The coordinator's wait deadline must be the earliest of:

1. persisted manager wake;
2. an in-memory bounded retry after a transient failure;
3. an event notification.

`WakeEvaluator` must emit `review window expired` for the project deadline even when no campaign exists. It must still wake early for build/probe results, crashes, health changes, coverage/corpus changes, plateaus, configuration opportunities, overlap candidates, and a newly free heavy-job slot.

### Step 5: Verify focused and neighbouring tests

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_agents.py \
  backend/tests/test_project_coordinator.py \
  backend/tests/test_wake_rules.py \
  backend/tests/test_project_api.py \
  backend/tests/test_development_database.py \
  backend/tests/test_release_persistence.py -q
```

Expected: all pass; no API route exposes pause or resume; a manager-selected deadline survives service reconstruction.

### Step 6: Commit

```bash
git add backend/database/schema.sql backend/database/schema_contract.sql \
  backend/models/project.py backend/repositories/project_repository.py \
  backend/agents/outputs/campaign_decision.py backend/agents/prompts/manager.py \
  backend/services/campaigns/project_coordinator.py \
  backend/services/campaigns/wake_rules.py \
  backend/services/projects/project_settings.py \
  backend/api/controllers/settings.py backend/api/views/project.py \
  backend/tests/test_project_coordinator.py backend/tests/test_wake_rules.py \
  backend/tests/test_agents.py backend/tests/test_project_api.py \
  backend/tests/test_development_database.py backend/tests/test_release_persistence.py
git commit -m "feat: persist manager review deadlines"
```

---

## Task 2: Enforce project execution slots only around compilation and fuzzing

**Files:**

- Create: `backend/services/campaigns/execution_slots.py`
- Modify: `backend/repositories/campaign_repository.py`
- Modify: `backend/services/campaigns/production_preparation.py`
- Modify: `backend/services/campaigns/production_runtime.py`
- Modify: `backend/services/campaigns/project_coordinator.py`
- Modify: `backend/api/dependencies.py`
- Test: `backend/tests/test_execution_slots.py`
- Test: `backend/tests/test_target_preparation.py`
- Test: `backend/tests/test_campaign_monitor.py`
- Test: `backend/tests/test_project_coordinator.py`
- Test: `backend/tests/test_coordinator_production_wiring.py`

### Step 1: Write failing slot-accounting tests

Create an asynchronous test with a project limit of four. Hold two compilation leases and report two active fuzzing campaigns. A fifth compilation must wait. Releasing one compilation must immediately admit it. In the same test, run ten dummy agent-side coroutines and prove none call or wait on the slot service.

The public service contract is:

```python
class ProjectExecutionSlots:
    @asynccontextmanager
    async def compilation(self, project, operation_id: str):
        """Reserve one heavy-job slot for a bounded compilation transaction."""

    async def wait_for_fuzzing_start(
        self, project, campaign_id: int | None = None,
    ) -> None:
        """Wait until one active-fuzzing slot is available."""

    def notify(self, project_id: int) -> None:
        """Re-evaluate waiters after a heavy job changes state."""
```

Run:

```bash
backend/.venv/bin/python -m pytest backend/tests/test_execution_slots.py -q
```

Expected: failure because no slot service exists.

### Step 2: Implement one process-local compilation ledger plus durable active-fuzzer counts

`ProjectExecutionSlots` must:

- validate a positive project ID and limit;
- serialize admission decisions per project with `asyncio.Condition`;
- ask `CampaignRepository.count_active(project_id, excluding_campaign_id=None)` for unstopped campaigns;
- count in-flight compilation leases in memory;
- admit work only when `active_fuzzers + compilation_leases < project.worker_count`;
- release compilation leases in `finally`, including cancellation and build failure;
- clear process-local compilation leases naturally on process restart; active fuzzers are reconstructed from campaign/container reconciliation;
- never be imported by agent runner/dispatch code.

Do not add an execution-lease database table. Compilation processes die with the host process; active fuzzers already have durable campaign/container identity.

### Step 3: Gate all heavy start points

Wrap the complete normal/project/target/coverage build and probe preparation transaction in:

```python
async with self._execution_slots.compilation(
    project, f"prepare-target:{record.result_id}",
):
    prepared = await self._preparation.prepare(project, record)
    campaign = await self._publish_and_start(project, record, prepared)
```

Holding the compilation lease through campaign start prevents the completed build and new fuzzer from briefly exceeding the limit. The lease is then replaced by the active campaign count.

Before runtime recovery/resume/replacement starts a stopped campaign container, call `wait_for_fuzzing_start(project, campaign.id)`. Existing active campaigns must not acquire a second slot. Every campaign stop, terminal container observation, completed build, or settings limit change calls `notify(project_id)`.

In the coordinator, compute `free_slots` from the slot service's heavy-job snapshot, not from OpenAI runs. Rename local variables from `worker` to `job` where they represent Docker work, without renaming the stored `worker_count` compatibility field.

### Step 4: Verify the limit and independent agent concurrency

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_execution_slots.py \
  backend/tests/test_target_preparation.py \
  backend/tests/test_campaign_monitor.py \
  backend/tests/test_project_coordinator.py \
  backend/tests/test_coordinator_production_wiring.py -q
```

Expected: four total heavy jobs are admitted; a fifth waits; agent calls do not consume slots; slot cancellation does not leak capacity.

### Step 5: Commit

```bash
git add backend/services/campaigns/execution_slots.py \
  backend/repositories/campaign_repository.py \
  backend/services/campaigns/production_preparation.py \
  backend/services/campaigns/production_runtime.py \
  backend/services/campaigns/project_coordinator.py backend/api/dependencies.py \
  backend/tests/test_execution_slots.py backend/tests/test_target_preparation.py \
  backend/tests/test_campaign_monitor.py backend/tests/test_project_coordinator.py \
  backend/tests/test_coordinator_production_wiring.py
git commit -m "feat: limit only heavy project jobs"
```

---

## Task 3: Replace fixed specialists with one dynamically assigned fuzzing worker

**Files:**

- Create: `backend/agents/fuzzing_worker.py`
- Create: `backend/agents/prompts/fuzzing_worker.py`
- Create: `backend/agents/outputs/fuzzing_worker_result.py`
- Modify: `backend/agents/manager.py`
- Modify: `backend/agents/tools/agent_dispatch.py`
- Modify: `backend/agents/outputs/campaign_review.py`
- Modify: `backend/agents/workflow.py`
- Modify: `backend/services/campaigns/production_evidence_factory.py`
- Delete: `backend/agents/specialists/system_target.py`
- Delete: `backend/agents/specialists/component_target.py`
- Delete: `backend/agents/specialists/crash_triage.py`
- Delete: `backend/agents/prompts/system_target.py`
- Delete: `backend/agents/prompts/component_target.py`
- Delete: `backend/agents/prompts/crash_triage.py`
- Test: `backend/tests/test_agents.py`
- Test: `backend/tests/test_agent_live.py`
- Test: `backend/tests/test_agent_tracing.py`
- Test: `backend/tests/test_crash_pipeline.py`
- Test: `backend/tests/test_coordinator_production_wiring.py`

### Step 1: Write failing general-worker tests

Test that the manager receives exactly one tool named `run_fuzzing_worker`, that the tool is created with `Agent.as_tool()`, and that the manager may issue that tool more than once in one turn with distinct assignments. Use a barrier in the fake runner to prove two calls overlap in time.

The request remains deliberately general:

```python
class FuzzingWorkerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignment: str = Field(min_length=1, max_length=4_000)
    evidence_ids: list[str] = Field(max_length=64)
```

The result supports one or more concrete outcomes without encoding permanent agent roles:

```python
class FuzzingWorkerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2_000)
    evidence_ids: list[str] = Field(max_length=64)
    target_proposals: list[TargetProposal] = Field(max_length=4)
    triage_results: list[TriageResult] = Field(max_length=16)
    operation_request_ids: list[str] = Field(max_length=16)
    recommendations: list[str] = Field(max_length=16)
    uncertainty: str = Field(min_length=1, max_length=2_000)
```

Do not add a worker-role enum. The manager gives a bounded natural-language assignment such as preparing a system target, repairing an existing target, inspecting a plateau, improving a corpus, or triaging replay evidence.

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_agents.py backend/tests/test_agent_live.py \
  backend/tests/test_agent_tracing.py -q
```

Expected: failure because dispatch still exposes three fixed tools.

### Step 2: Build one general worker with the complete bounded capability set

`build_fuzzing_worker(model)` must construct a normal Agents SDK `Agent[AgentContext]` with:

- code navigation: list, bounded read, text search, Git metadata;
- RAG/evidence retrieval;
- generated draft list/read/create/compare-and-swap edit;
- official web research with citation validation;
- bounded pipeline-operation requests;
- structured `FuzzingWorkerResult` output.

The prompt must state:

- the checkout is immutable and untrusted;
- all edits go under the project generated-assets root;
- existing working harnesses/configurations must be changed incrementally;
- system work uses AFL++ and component work uses libFuzzer;
- begin with ASan and UBSan;
- return evidence-backed proposals, never claim that a requested operation ran;
- no host shell, raw Docker, project selection, recursive delegation, or unverified vulnerability claim.

Use Luna first. Retry once with Terra only when deterministic output/evidence validation fails or the worker explicitly reports that the bounded assignment exceeds the first model's capability. Do not retry/escalate authentication, transport, quota, or service failures as if they were reasoning failures.

### Step 3: Keep the manager as the only dispatcher

Replace the three fixed `Agent.as_tool()` objects with repeated calls to one `run_fuzzing_worker` tool. Retain `parallel_tool_calls=True`. Validate every tool call against the exact evidence IDs assigned by the current review and use the SDK tool-call ID to keep concurrent results separate.

Rename internal records from `SpecialistInvocation` to `WorkerInvocation` and from specialist-named fields to `worker_assignment` where doing so improves clarity. Keep stable application-owned result IDs so the manager selects exact target, triage, retirement, progression, or pipeline-operation records.

Workers must not receive the worker-dispatch tool and cannot recursively create agents.

### Step 4: Unify production crash triage with the general worker

Remove the independent direct crash-triage agent construction from `production_evidence_factory.py`. Inject a general-worker runner that receives replay, minimisation, variant, source, contract, and correction evidence as one bounded assignment. Deterministic crash services still own replay, minimisation, fingerprinting, grouping, correction replay, classification validation, and ranking.

Validate each returned classification against the five exact allowed phrases and reject unknown evidence IDs. Keep a separate Terra correction attempt only when deterministic validation fails, not merely because the first result is uncertain.

### Step 5: Verify agent boundaries and concurrency

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_agents.py backend/tests/test_agent_live.py \
  backend/tests/test_agent_tracing.py backend/tests/test_crash_pipeline.py \
  backend/tests/test_coordinator_production_wiring.py -q
```

Expected: one dynamic tool, at least two concurrent calls supported, no recursive dispatch, Luna-first/Terra-correction preserved, and production triage uses the same general worker boundary.

### Step 6: Commit

```bash
git add backend/agents backend/services/campaigns/production_evidence_factory.py \
  backend/tests/test_agents.py backend/tests/test_agent_live.py \
  backend/tests/test_agent_tracing.py backend/tests/test_crash_pipeline.py \
  backend/tests/test_coordinator_production_wiring.py
git commit -m "feat: add dynamic fuzzing workers"
```

---

## Task 4: Complete incremental worker actions, target repair, and safe lifecycle decisions

**Files:**

- Modify: `backend/agents/tools/contained_operations.py`
- Modify: `backend/agents/tools/generated_assets.py`
- Modify: `backend/agents/outputs/campaign_review.py`
- Modify: `backend/fuzzing/campaigns/target_preparation.py`
- Modify: `backend/fuzzing/campaigns/production_factory.py`
- Create: `backend/services/campaigns/pipeline_operations.py`
- Create: `backend/services/campaigns/target_lifecycle.py`
- Create: `backend/fuzzing/crashes/reproduction_bundle.py`
- Modify: `backend/services/campaigns/decision_executor.py`
- Modify: `backend/services/campaigns/production_preparation.py`
- Modify: `backend/services/campaigns/production_runtime.py`
- Modify: `backend/repositories/campaign_repository.py`
- Modify: `backend/repositories/asset_repository.py`
- Modify: `backend/api/dependencies.py`
- Test: `backend/tests/test_pipeline_operations.py`
- Test: `backend/tests/test_target_preparation.py`
- Test: `backend/tests/test_campaign_progression.py`
- Test: `backend/tests/test_overlap.py`
- Test: `backend/tests/test_crash_pipeline.py`
- Test: `backend/tests/test_release_persistence.py`

### Step 1: Write failing tests for iterative, selected actions

Test the following complete sequence without a host shell:

1. a worker writes `targets/parser/harness.c` and `targets/parser/build.sh`;
2. it returns a `TargetProposal` that references those exact drafts;
3. the manager selects its stable result ID;
4. deterministic preparation builds and probes the target in the incremental layer;
5. a failed probe emits bounded evidence and wakes the manager;
6. another worker edits only the failing draft using the current SHA;
7. the repaired proposal reuses the repository/project layers and replaces only the target/coverage descendants;
8. the successful campaign starts when a heavy-job slot is available.

Add lifecycle tests:

- a never-functional target with no successful probe, campaign, useful coverage, or finding dependency may be deleted;
- a healthy but unhelpful target is unscheduled and preserved;
- a fully overlapping target is deletable only after two comparable clean checkpoints, no unique crash group, and a healthy retained strategy;
- a finding-dependent target is frozen into an immutable reproduction bundle before any source asset is removed.

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_pipeline_operations.py \
  backend/tests/test_target_preparation.py \
  backend/tests/test_overlap.py -q
```

Expected: failure because operation records are audit-only and destructive lifecycle evidence is incomplete.

### Step 2: Make pipeline operation requests executable only after manager selection

Replace the current `executed: Literal[False]` audit record with an application-owned action record containing:

```python
class PipelineOperationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str
    project_id: int
    operation: str
    asset_paths: tuple[str, ...]
    assertions: tuple[str, ...]
    worker_tool_call_id: str
    evidence_ids: tuple[str, ...]
```

Keep the operation vocabulary limited to `build`, `probe`, `replay`, and `coverage`, but validate plain strings rather than adding an enum. `PipelineOperationService.execute(project, record)` must:

- resolve only immutable project checkout and generated draft roots;
- dispatch to existing target-preparation, replay, or clean-coverage services;
- acquire a compilation slot only for build/probe operations that compile code; standalone replay and coverage processing do not consume a compilation/fuzzing slot;
- stream output to the project debug log with asset hashes and image IDs;
- return a durable evidence ID and result summary;
- notify the coordinator so the manager can inspect success/failure and make the next incremental assignment.

The agent tool requests work; only the manager-selected action ID authorizes execution.

### Step 3: Preserve working layers and make repair granular

Use existing content hashes and parent labels to prove reuse:

- dependency changes rebuild project plus descendants;
- harness/build-script/fuzz-patch changes rebuild target plus clean-coverage descendants;
- configuration/dictionary/mutator changes create a dependent configuration layer where compilation is unnecessary;
- corpus additions do not rebuild any image;
- no repair starts from an empty generated-assets directory when a validated parent exists.

Build failures, direct-start crashes, irrelevant-project coverage, invalid seeds, and failed assertions must become deterministic evidence for the next worker. The worker edits only the implicated draft path with compare-and-swap.

### Step 4: Implement conservative target lifecycle rules

`TargetLifecycleService` exposes application-generated action records, not direct agent deletion:

```python
async def never_functional_deletion(project_id: int, target_asset_id: int):
    """Return a deletion action only when complete never-functional evidence exists."""

async def overlapping_deletion(project_id: int, campaign_id: int):
    """Return a deletion action only after two complete comparable checkpoints."""

async def unschedule(project_id: int, campaign_id: int, reason: str):
    """Return a reversible unscheduling action for a functional target."""
```

Deletion requires complete deterministic evidence. Before removing any finding-dependent asset, `ReproductionBundleStore.freeze(bundle_request)` writes a contained manifest plus immutable copies/references for the exact image, command, environment, sanitizer/configuration, minimal testcase, target/configuration/coverage asset hashes, and commit. Reject deletion if the bundle cannot be verified.

Functional nonredundant campaigns are stopped/unscheduled through the internal scheduler but their assets remain available for future replay. Do not expose any of these operations as user buttons.

### Step 5: Verify the complete backend action loop

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_pipeline_operations.py \
  backend/tests/test_target_preparation.py \
  backend/tests/test_campaign_progression.py \
  backend/tests/test_overlap.py \
  backend/tests/test_crash_pipeline.py \
  backend/tests/test_release_persistence.py -q
```

Expected: selected operations run, failed operations wake repair, working parents are reused, and deletion cannot break finding reproduction.

### Step 6: Commit

```bash
git add backend/agents/tools/contained_operations.py \
  backend/agents/tools/generated_assets.py backend/agents/outputs/campaign_review.py \
  backend/fuzzing/campaigns/target_preparation.py \
  backend/fuzzing/campaigns/production_factory.py \
  backend/services/campaigns/pipeline_operations.py \
  backend/services/campaigns/target_lifecycle.py \
  backend/fuzzing/crashes/reproduction_bundle.py \
  backend/services/campaigns/decision_executor.py \
  backend/services/campaigns/production_preparation.py \
  backend/services/campaigns/production_runtime.py \
  backend/repositories/campaign_repository.py backend/repositories/asset_repository.py \
  backend/api/dependencies.py backend/tests/test_pipeline_operations.py \
  backend/tests/test_target_preparation.py backend/tests/test_campaign_progression.py \
  backend/tests/test_overlap.py backend/tests/test_crash_pipeline.py \
  backend/tests/test_release_persistence.py
git commit -m "feat: execute incremental pipeline actions"
```

---

## Task 5: Persist exact clean line, function, and branch coverage totals

**Files:**

- Modify: `backend/database/schema.sql`
- Modify: `backend/database/schema_contract.sql`
- Modify: `backend/fuzzing/coverage/llvm_coverage.py`
- Modify: `backend/fuzzing/coverage/traceability.py`
- Modify: `backend/fuzzing/coverage/exposure.py`
- Modify: `backend/repositories/coverage_repository.py`
- Modify: `backend/api/controllers/coverage.py`
- Modify: `backend/api/views/coverage.py`
- Modify: `backend/services/campaigns/read_campaigns.py`
- Modify: `backend/api/views/campaign.py`
- Test: `backend/tests/test_clean_coverage.py`
- Test: `backend/tests/test_coverage_api.py`
- Test: `backend/tests/test_exposure.py`
- Test: `backend/tests/test_campaign_api.py`
- Test: `backend/tests/test_development_database.py`

### Step 1: Add failing parser tests with zero-count instrumentation

Use a bounded real-shaped `llvm-cov export` fixture containing:

- an instrumented but uncovered line;
- a covered line;
- an instrumented but uncovered function;
- a covered function;
- two branches, one covered and one uncovered.

Assert the snapshot returns exact identities and totals rather than discarding zero-count records:

```python
assert snapshot.summary.lines == CoverageCount(covered=1, total=2)
assert snapshot.summary.functions == CoverageCount(covered=1, total=2)
assert snapshot.summary.branches == CoverageCount(covered=1, total=2)
```

Also assert malformed or unavailable branch data produces `branches=None`, not `0/0`.

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_clean_coverage.py backend/tests/test_coverage_api.py -q
```

Expected: failure because the current parser retains positive segments/functions only and ignores branches.

### Step 2: Extend the clean coverage contract

Add immutable records:

```python
@dataclass(frozen=True)
class CoverageCount:
    covered: int
    total: int

@dataclass(frozen=True)
class CoverageBranch:
    source_path: str
    line_number: int
    branch_index: int
    covered: bool

@dataclass(frozen=True)
class CoverageSummary:
    lines: CoverageCount | None
    functions: CoverageCount | None
    branches: CoverageCount | None
```

Parse LLVM segments, function regions, and branch records with strict size/coordinate bounds. Bind every retained source identity to the exact clean image and local checkout hash. Keep first-testcase evidence for covered lines; branch/function totals do not invent a testcase when no per-input proof exists.

### Step 3: Store inventories and derive aggregates

Add minimal exact-build tables:

```sql
CREATE TABLE coverage_source_summaries (
    project_id BIGINT NOT NULL,
    commit_sha TEXT NOT NULL,
    coverage_asset_id BIGINT NOT NULL,
    source_path TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    covered_lines INTEGER,
    total_lines INTEGER,
    covered_functions INTEGER,
    total_functions INTEGER,
    covered_branches INTEGER,
    total_branches INTEGER,
    PRIMARY KEY (project_id, coverage_asset_id, source_path)
);

CREATE TABLE coverage_branch_evidence (
    project_id BIGINT NOT NULL,
    commit_sha TEXT NOT NULL,
    coverage_asset_id BIGINT NOT NULL,
    source_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    branch_index INTEGER NOT NULL,
    covered BOOLEAN NOT NULL,
    PRIMARY KEY (
        project_id, coverage_asset_id, source_path, line_number, branch_index
    )
);
```

Include the existing foreign keys. Upsert one exact snapshot transactionally. Derive project totals only across comparable exact coverage builds; if multiple campaign snapshots share the same source denominator, union covered identities and keep one denominator. Reject conflicting source hashes or totals instead of averaging.

Correct source CPU exposure: for a source, take the maximum line exposure per campaign and sum campaigns; do not multiply one campaign hour by its reached-line count. Project actual CPU remains the sum of campaign CPU seconds.

### Step 4: Expose honest API measurements

Extend coverage responses with nullable `{covered,total,percent}` records for lines, functions, and branches. Add branch state to source-line responses and make the existing functions endpoint visible to frontend consumers. Extend campaigns with:

- `activity`: `running`, `waiting`, `stopped`, or `failed` as a derived response string;
- five-minute covered-line delta when comparable checkpoints exist;
- total reached lines;
- CPU seconds;
- purpose/configuration and engine as secondary detail.

Do not persist the derived activity string or add an engine/type duplicate.

### Step 5: Verify persistence and API boundaries

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_clean_coverage.py backend/tests/test_coverage_api.py \
  backend/tests/test_exposure.py backend/tests/test_campaign_api.py \
  backend/tests/test_development_database.py -q
```

Expected: exact clean line/function/branch totals are persisted and returned; missing data remains unavailable; exposure is no longer multiplied by lines.

### Step 6: Commit

```bash
git add backend/database/schema.sql backend/database/schema_contract.sql \
  backend/fuzzing/coverage/llvm_coverage.py \
  backend/fuzzing/coverage/traceability.py backend/fuzzing/coverage/exposure.py \
  backend/repositories/coverage_repository.py backend/api/controllers/coverage.py \
  backend/api/views/coverage.py backend/services/campaigns/read_campaigns.py \
  backend/api/views/campaign.py backend/tests/test_clean_coverage.py \
  backend/tests/test_coverage_api.py backend/tests/test_exposure.py \
  backend/tests/test_campaign_api.py backend/tests/test_development_database.py
git commit -m "feat: measure clean branch coverage"
```

---

## Task 6: Add exact read-only finding reproduction with streamed terminal output

**Files:**

- Create: `backend/services/findings/reproduction_registry.py`
- Create: `backend/services/findings/reproduce_finding.py`
- Create: `backend/api/controllers/reproductions.py`
- Create: `backend/api/views/reproduction.py`
- Modify: `backend/api/app.py`
- Modify: `backend/api/dependencies.py`
- Modify: `backend/fuzzing/crashes/artifacts.py`
- Modify: `backend/fuzzing/docker/container_runner.py`
- Test: `backend/tests/test_finding_reproduction.py`
- Test: `backend/tests/test_findings_api.py`
- Test: `backend/tests/test_fuzzing_docker.py`
- Test: `backend/tests/test_recovery_cleanup.py`

### Step 1: Write failing service and HTTP tests

Test `POST /api/projects/{project_id}/findings/{finding_id}/reproductions` and the SSE stream:

```text
event: reproduction
data: {"phase":"starting","image_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":["/opt/bigeye/reproduce","/finding/input"]}

event: output
data: {"stream":"stderr","text":"AddressSanitizer: heap-buffer-overflow"}

event: reproduction
data: {"phase":"completed","exit_code":1}
```

Assert:

- a finding from another project is 404;
- a non-reproducible/incomplete bundle is 409;
- the exact image is inspected as Linux/amd64;
- the command/environment/testcase come only from the frozen bundle;
- the container is network-disabled, read-only, unprivileged, bounded, and removed;
- output is capped and UTF-8 sanitised;
- disconnect/cancellation removes the container;
- the complete sanitised log and final JSON record remain under `workspace/projects/{project_id}/findings/{finding_id}/reproductions/{run_id}/`;
- there is no stdin or websocket endpoint.

Run:

```bash
backend/.venv/bin/python -m pytest backend/tests/test_finding_reproduction.py -q
```

Expected: failure because interactive reproduction does not exist.

### Step 2: Implement a bounded in-memory registry with file-backed history

`ReproductionRegistry` tracks only currently running local tasks and subscriber queues. It writes the durable event log before publishing each SSE event. Run IDs are application-generated UUID hex values. On startup, mark incomplete historical runs as interrupted; never pretend they completed.

Public service methods:

```python
async def start(self, project_id: int, finding_id: int) -> ReproductionRun:
    """Start one exact, contained reproduction run."""

async def stream(self, project_id: int, finding_id: int, run_id: str):
    """Yield persisted and live sanitised terminal events."""

async def close(self) -> None:
    """Cancel active reproductions and remove their containers."""
```

`FindingReproductionService` loads and verifies the immutable reproduction bundle, creates one ephemeral container, mounts only the minimal testcase read-only, and streams Docker stdout/stderr. It does not acquire a project execution slot because reproduction is short, user-requested diagnostic work and not an active campaign/compilation job; it still uses strict CPU/memory/time limits.

### Step 3: Add focused HTTP MVC boundaries

The controller validates IDs and ownership, returns `202` with the run identity, and serves `text/event-stream` with heartbeat comments. Pydantic response views contain only run ID, phase, timestamps, exact image ID, command, exit code, and terminal reason. The API must never return Docker socket details, host paths, repository token, OpenAI key, or unsanitised environment values.

Register the controller in `api/app.py` and inject/close the service in `api/dependencies.py`.

### Step 4: Verify reproduction cleanup and containment

Run:

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_finding_reproduction.py backend/tests/test_findings_api.py \
  backend/tests/test_fuzzing_docker.py backend/tests/test_recovery_cleanup.py -q
```

Expected: read-only streamed reproduction works, every container is removed, and persistent evidence survives a service restart.

### Step 5: Commit

```bash
git add backend/services/findings backend/api/controllers/reproductions.py \
  backend/api/views/reproduction.py backend/api/app.py backend/api/dependencies.py \
  backend/fuzzing/crashes/artifacts.py backend/fuzzing/docker/container_runner.py \
  backend/tests/test_finding_reproduction.py backend/tests/test_findings_api.py \
  backend/tests/test_fuzzing_docker.py backend/tests/test_recovery_cleanup.py
git commit -m "feat: stream exact finding reproduction"
```

---

## Task 7: Complete the professional project UI for autonomous fuzzing

**Files:**

- Create: `frontend/src/models/fuzzing.ts`
- Create: `frontend/src/models/reproduction.ts`
- Create: `frontend/src/controllers/useFuzzing.ts`
- Create: `frontend/src/controllers/useFindingReproduction.ts`
- Create: `frontend/src/components/fuzzing/FuzzingTable.tsx`
- Create: `frontend/src/components/findings/ReproductionTerminal.tsx`
- Create: `frontend/src/views/FuzzingView.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/Navigation.tsx`
- Modify: `frontend/src/controllers/useProjectOverview.ts`
- Modify: `frontend/src/controllers/useProjectSettings.ts`
- Modify: `frontend/src/controllers/useFindings.ts`
- Modify: `frontend/src/controllers/useSourceAssurance.ts`
- Modify: `frontend/src/components/findings/FindingDetail.tsx`
- Modify: `frontend/src/components/coverage/CoverageMap.tsx`
- Modify: `frontend/src/components/coverage/SourceCode.tsx`
- Modify: `frontend/src/views/OverviewView.tsx`
- Modify: `frontend/src/views/SettingsView.tsx`
- Modify: `frontend/src/services/apiClient.ts`
- Modify: `frontend/src/services/eventStream.ts`
- Modify: `frontend/src/models/project.ts`
- Modify: `frontend/src/models/settings.ts`
- Modify: `frontend/src/models/coverage.ts`
- Modify: `frontend/src/app.css`
- Create: `frontend/src/Fuzzing.test.tsx`
- Create: `frontend/src/FindingReproduction.test.tsx`
- Modify: `frontend/src/AppJourney.test.tsx`
- Modify: `frontend/src/Overview.test.tsx`
- Modify: `frontend/src/Findings.test.tsx`
- Modify: `frontend/src/SourceAssurance.test.tsx`
- Modify: `frontend/src/Accessibility.test.tsx`

### Step 1: Write failing UI journey tests

Test the selected-project navigation and real data states:

- `Fuzzing` is a primary navigation item;
- without a project, selecting Overview/Fuzzing/Source/Findings/Activity/Settings redirects to Projects and says `Select or create a project first.`;
- Fuzzing rows show target, configuration/purpose, derived activity, five-minute coverage change, total reach, CPU time, last evidence, and state;
- the underlying `AFL++` or `libFuzzer` label appears only as secondary technical text;
- Overview shows covered/total/percent for lines and branches, active heavy jobs, and manager focus;
- unavailable branch/function data renders `Unavailable`;
- Settings labels `worker_count` as `Concurrent jobs` and has no pause control;
- Findings has `Reproduce` only when deterministic reproduction evidence exists;
- the terminal is read-only, scrollable, has `role="log"`, and has no input/keyboard capture;
- the footer continues showing the manager's real current action or `Fuzzing at full speed!` only when healthy campaigns are genuinely running.

Run:

```bash
npm --prefix frontend test -- --run \
  src/Fuzzing.test.tsx src/FindingReproduction.test.tsx \
  src/AppJourney.test.tsx src/Overview.test.tsx
```

Expected: failure because Fuzzing and streamed reproduction UI do not exist and pause controls remain.

### Step 2: Add Fuzzing MVC without duplicating backend state

`useFuzzing` loads campaign rows through `BigEyeApi.listCampaigns`, subscribes to campaign/coverage/activity event hints, and refreshes the authoritative response. `FuzzingView` renders only the controller model. `FuzzingTable` does not infer process state from timers; it uses the backend-derived activity and timestamps.

Use the approved four/five-colour design vocabulary already in `app.css`: white, black, neutral grey, red accent, and one restrained success colour. Avoid cards and explanatory copy that duplicate the navigation/title. Keep `+ New project` right-aligned on Projects and retain the first-load logo screen.

### Step 3: Expose clean coverage and reproduction

Overview displays the most important comparable totals. Source shows line state, reached functions, branch markers where available, first-testcase traceability, and CPU exposure. Findings starts a reproduction run and attaches the existing event-stream service to the run SSE URL. `ReproductionTerminal` renders the exact lifecycle and output without accepting input.

Keep OpenAI debug traces and tool calls in Activity/debug only; never put model names, token details, or fuzzer brands in primary status labels.

### Step 4: Remove manual campaign/project control surfaces

Delete `pauseProject`, `resumeProject`, pause fields, and pause handlers from frontend models/controllers/services/views. There is no job stop/restart or corpus hex editor. The manager owns scheduling and lifecycle changes.

### Step 5: Verify frontend tests, accessibility, and production build

Run:

```bash
npm --prefix frontend test -- --run
npm --prefix frontend run build
```

Expected: all frontend tests pass; TypeScript builds; primary navigation works; terminal is read-only; no pause/resume request remains in compiled source.

### Step 6: Commit

```bash
git add frontend/src
git commit -m "feat: add autonomous fuzzing workspace"
```

---

## Task 8: Prove the complete loop on an agent-discovered controlled fixture

**Files:**

- Create: `backend/tests/fixtures/whole_loop_project/CMakeLists.txt`
- Create: `backend/tests/fixtures/whole_loop_project/include/decoder.h`
- Create: `backend/tests/fixtures/whole_loop_project/src/decoder.c`
- Create: `backend/tests/fixtures/whole_loop_project/src/decoder_cli.c`
- Create: `backend/tests/fixtures/whole_loop_project/seeds/plain.input`
- Create: `backend/tests/fixtures/whole_loop_project/seeds/framed.input`
- Create: `backend/tests/test_complete_agent_loop.py`
- Modify: `tests/e2e/bigeye.spec.ts`
- Modify: `tests/e2e/acceptanceCleanup.ts`
- Modify: `backend/tests/test_release_acceptance_contract.py`
- Modify: `README.md`

### Step 1: Create a small source project, not prewritten fuzz targets

The fixture contains a library API and a CLI that accept the same byte format through different paths. Include deterministic cases producing:

- one real project memory-safety defect;
- one improper API-contract use detectable only by a bad component harness;
- one harness-induced direct-start failure;
- two byte-distinct inputs with the same true crash fingerprint.

Do not include a fuzz harness, AFL++ command, libFuzzer command, Dockerfile, dictionary, generated corpus, or expected target description. The test may assert outcomes but must not supply target commands to production services.

### Step 2: Write a failing opt-in whole-loop backend test

Gate live API and Docker work with `BIGEYE_LIVE_ACCEPTANCE=1`. Submit the fixture as a normal Git repository with `worker_count=4`. Assert from durable evidence, not mocked runners:

1. the manager calls at least two general workers concurrently;
2. workers generate one system-level and one component-level target;
3. both incremental builds/probes succeed after any bounded repair;
4. real AFL++ and libFuzzer containers run;
5. healthy candidates fill up to four heavy-job slots without limiting agent calls;
6. line and branch clean coverage are published;
7. corpus admission/minimisation runs without a user action;
8. crashes are replayed, minimised, grouped, triaged, and ranked;
9. the three semantic outcomes are represented where the deterministic evidence supports them;
10. duplicate true crashes produce one finding with multiple occurrences;
11. a finding reproduction SSE run emits real terminal output and removes its container;
12. a manager-selected deadline is persisted and a forced overdue deadline wakes the manager;
13. service restart recovers the coordinator and healthy campaigns.

The one-hour real-project clock is not part of this controlled test.

### Step 3: Update Playwright to exercise the real product journey

The browser test creates the fixture project through `+ New project`, opens Fuzzing, verifies dynamic rows, inspects Source line/branch coverage, opens the prioritised Finding, starts read-only reproduction, and opens Activity/debug evidence. Remove all pause/resume steps.

### Step 4: Run the controlled real acceptance

First run deterministic and mocked suites:

```bash
backend/.venv/bin/python -m pytest backend/tests/test_complete_agent_loop.py -q
npm --prefix frontend test -- --run
```

Then load `.env` through the application entrypoint without printing secrets and run:

```bash
BIGEYE_LIVE_ACCEPTANCE=1 backend/.venv/bin/python -m pytest \
  backend/tests/test_complete_agent_loop.py -q -s
BIGEYE_LIVE_ACCEPTANCE=1 npx playwright test tests/e2e/bigeye.spec.ts
```

Expected: the first command proves structural contracts; the live commands prove real Agents SDK, Docker builds, both engines, coverage, triage, and reproduction. If any semantic crash category cannot be produced, fix the pipeline or fixture; do not create a production fallback.

### Step 5: Update Getting started with exact local commands

`README.md` must contain:

```text
# Getting started
1. Copy .env_example to .env and add OPENAI_API_KEY.
2. Start PostgreSQL with Docker Compose.
3. Reset the development schema.
4. Start FastAPI from backend/.venv.
5. Open http://127.0.0.1:8000.
6. Create a project with a public URL or a project-specific read-only token.
```

Document macOS and Linux prerequisites, `linux/amd64`, the four-job default, `.env` auto-loading, and how to inspect Activity/debug logs. Do not claim fuzzing completion until the live test passed.

### Step 6: Commit

```bash
git add backend/tests/fixtures/whole_loop_project \
  backend/tests/test_complete_agent_loop.py tests/e2e/bigeye.spec.ts \
  tests/e2e/acceptanceCleanup.ts backend/tests/test_release_acceptance_contract.py \
  README.md
git commit -m "test: prove the complete agent fuzzing loop"
```

---

## Task 9: Run and record the one-hour libaom v3.13.2 acceptance campaign

**Files:**

- Create: `scripts/run_libaom_acceptance.py`
- Create: `backend/tests/test_libaom_acceptance_contract.py`
- Create: `tests/e2e/libaom-hour.spec.ts`
- Modify: `README.md`
- Runtime output: `workspace/acceptance/libaom-v3.13.2/{run_id}/report.json` plus an atomically replaced `workspace/acceptance/libaom-v3.13.2/latest-report.json`

### Step 1: Write a failing acceptance-runner contract test

Pin only the upstream source identity in code:

```python
LIBAOM_REPOSITORY = "https://aomedia.googlesource.com/aom"
LIBAOM_REVISION = "ad44980d7f3c7a2605c25d51ea96946949000841"
LIBAOM_TAG = "v3.13.2"
```

The runner must submit that repository/revision through the same public project service used by the UI. It must not provide a Dockerfile, build command, harness, seed corpus, engine command, target list, or OSS-Fuzz artefact.

The acceptance report contract is:

```json
{
  "repository_url": "https://aomedia.googlesource.com/aom",
  "requested_revision": "ad44980d7f3c7a2605c25d51ea96946949000841",
  "resolved_revision": "ad44980d7f3c7a2605c25d51ea96946949000841",
  "validated_fuzzing_started_at": "2026-07-20T12:00:00Z",
  "validated_fuzzing_finished_at": "2026-07-20T13:00:00Z",
  "elapsed_validated_fuzzing_seconds": 3600,
  "execution_slot_limit": 4,
  "targets": [],
  "configurations": [],
  "campaigns": [],
  "coverage": {"lines": {}, "functions": {}, "branches": {}},
  "corpus": {},
  "findings": [],
  "agent_runs": [],
  "failures": []
}
```

The timer begins only after the first validated real fuzzer container is active and reaching libaom code. The runner fails if, by the end, it lacks at least one healthy system-level AFL++ campaign, one healthy component-level libFuzzer campaign, exact clean line and branch coverage, or four active heavy jobs once enough healthy candidates exist.

### Step 2: Implement a resumable observation runner

`scripts/run_libaom_acceptance.py` must:

- load the project `.env` through the same settings path as the app without printing secrets;
- start or reuse the exact project by repository and revision;
- observe durable APIs/events and Docker-owned campaign evidence, never inject targets;
- wait through normal manager-selected deadlines while a watchdog flags an overdue wake;
- record every target/configuration asset hash, image ID, command, sanitiser/configuration, corpus hash/count, campaign engine, duration/CPU, coverage numerator/denominator, crash/finding, retry, and failure;
- write an atomic JSON report under ignored workspace;
- support `--validated-seconds 3600` and a short `--validated-seconds 120` smoke run without changing product behaviour;
- exit nonzero with a concise blocker if acceptance conditions are unmet.

### Step 3: Add a UI observation test without controlling the manager

The Playwright test attaches to the running libaom project and verifies that Overview, Fuzzing, Source, Findings, Activity, and the manager footer stay live during the campaign. It must not stop, restart, pause, or edit a campaign.

### Step 4: Run a short smoke campaign

Before the hour, run:

```bash
backend/.venv/bin/python -m pytest backend/tests/test_libaom_acceptance_contract.py -q
backend/.venv/bin/python scripts/run_libaom_acceptance.py --validated-seconds 120
npx playwright test tests/e2e/libaom-hour.spec.ts
```

Expected: two validated minutes after the first healthy fuzzer; both engine types observed or an actionable blocker reported. Fix product problems before starting the hour.

### Step 5: Run the required one-hour campaign

Run:

```bash
backend/.venv/bin/python scripts/run_libaom_acceptance.py --validated-seconds 3600
```

During the hour, observe logs and correct product defects only when evidence shows the manager, workers, build, probe, fuzzers, coverage, corpus, triage, or watchdog is stuck. Do not reset a healthy campaign to make a test pass. The final report must show at least 3,600 seconds after validated fuzzing start.

### Step 6: Verify the report and full release suite

Run:

```bash
backend/.venv/bin/python -m pytest -q
npm --prefix frontend test -- --run
npm --prefix frontend run build
npx playwright test
backend/.venv/bin/python scripts/run_libaom_acceptance.py \
  --verify-report workspace/acceptance/libaom-v3.13.2/latest-report.json
```

Expected: all suites pass and report verification confirms exact revision, 3,600 validated seconds, both engine types, clean coverage, agent-led generation, and no slot violation.

### Step 7: Update README with verified capabilities only

After the report passes, document the exact libaom revision, how to open the recorded project in the UI, where the report is stored, and which measurements were actually available. Do not claim a bug or coverage improvement not present in evidence.

### Step 8: Commit

```bash
git add scripts/run_libaom_acceptance.py \
  backend/tests/test_libaom_acceptance_contract.py tests/e2e/libaom-hour.spec.ts \
  README.md
git commit -m "test: record one-hour libaom campaign"
```

---

## Task 10: Whole-branch review and release verification

**Files:**

- Review all changes from the merge base through `HEAD`.
- Modify only files required to fix reviewer findings.

### Step 1: Generate and review the complete diff

Run:

```bash
git status --short
git diff --stat HEAD~9..HEAD
git diff --check HEAD~9..HEAD
```

Confirm no `.env`, database volume, repository clone, corpus, crash input, generated harness, API trace, or secret is staged.

### Step 2: Run the subagent-driven broad review

Use a fresh Sol reviewer against the whole branch. Require explicit review of:

- Agents SDK `Agent.as_tool()` usage and parallel tool-call safety;
- distinction between API agent concurrency and four heavy-job slots;
- Docker containment and Linux/amd64 enforcement;
- target/build/reproduction path containment;
- manager deadline persistence, timeout, watchdog, and restart recovery;
- crash false-positive/contract/vulnerability boundaries;
- coverage denominator correctness and unavailable values;
- conservative deletion and immutable reproduction dependencies;
- API MVC boundaries and frontend truthfulness;
- absence of OSS-Fuzz/OSS-Fuzz-Gen reuse;
- acceptance evidence and one-hour timer correctness.

Fix every Critical or Important finding with focused tests, then re-run the reviewer.

### Step 3: Final verification

Run:

```bash
backend/.venv/bin/python -m pytest -q
npm --prefix frontend test -- --run
npm --prefix frontend run build
npx playwright test
git diff --check
git status --short
```

Expected: full green suite, clean diff check, only intentional user/pre-existing work remains uncommitted, and the verified one-hour acceptance report exists under ignored `workspace/`.

### Step 4: Commit review fixes when needed

Stage only the exact files changed for a reviewed defect, inspect the staged diff, then run `git commit -m "fix: address release review"`.

Do not create an empty review-fix commit.
