# BigEye Autonomous Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing repository-analysis backbone into a release-ready local application that autonomously builds, runs, improves, measures, and triages continuous AFL++ and libFuzzer campaigns for a user-selected repository.

**Architecture:** FastAPI runs on the host and owns one deterministic coordinator per active project. PostgreSQL stores queryable state, the project workspace stores naturally file-shaped artefacts, the Docker SDK runs all builds and fuzzers in forced `linux/amd64` containers, and a Terra manager invokes bounded Luna/Terra specialists through `Agent.as_tool()` only at evidence-driven review points. React consumes resource APIs and resumable project SSE events through its existing frontend MVC boundaries.

**Tech Stack:** Python 3.14, FastAPI, Uvicorn, `asyncio`, `asyncpg`, OpenAI Agents SDK, Docker SDK for Python, PostgreSQL 18.4 Bookworm, Ubuntu 24.04, LLVM/Clang/libFuzzer 18, AFL++ v4.40c, React, TypeScript, Vite, Radix Primitives, Lucide, Vitest, Testing Library, Playwright, pytest.

## Global Constraints

- Support macOS and Linux hosts; do not add Windows support.
- Run Python, FastAPI, the coordinator, and agents in `backend/.venv`; Docker is only for PostgreSQL and isolated build, coverage, replay, and fuzzing workloads.
- Force `linux/amd64` in Compose, every SDK image build, and every container run.
- Use only BigEye-owned Dockerfiles and layers. Do not use OSS-Fuzz or OSS-Fuzz-Gen images, code, workflows, schemas, or generated artefacts.
- Pin the `linux/amd64` Ubuntu 24.04 base to `sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf`, LLVM/Clang/libFuzzer to 18, and AFL++ to official release v4.40c at upstream commit `e5a8ba39ecf97d05e286fdd4e01da96554dbf64f`.
- Use `pip` only. After every Python dependency change run `backend/.venv/bin/python -m pip freeze > backend/requirements.txt` and verify it equals the environment.
- Use npm and the committed `frontend/package-lock.json` for frontend dependencies.
- Use one `backend/database/schema.sql`; do not add migration tooling or application enum classes.
- Store structured queryable state in PostgreSQL and large or naturally file-shaped artefacts under `workspace/projects/<project-id>/`.
- Keep `.env`, `workspace/`, `.superpowers/`, `backend/.venv/`, Python caches, `frontend/node_modules/`, and `frontend/dist/` ignored.
- Store the optional read-only Git token per project, never return its value, and redact it from commands, Docker contexts, Git remotes, activity, debug logs, and errors.
- Keep repository checkouts immutable. Agents may edit only generated Dockerfiles, harnesses, adapters, configurations, dictionaries, and fuzz-only patches.
- Use Terra for the manager, Luna for a specialist's first bounded attempt, and one Terra escalation only after deterministic validation fails or the task needs deeper judgement.
- Use `Agent.as_tool()` for specialist delegation. Fuzzer workers and coordinator loops are deterministic processes, not agents.
- Do not expose a raw host shell, host-wide filesystem, Docker socket, or Docker SDK client to an agent.
- Start targets simply with ASan and UBSan validation; add configurations, CmpLog, specialised sanitizers, or the AFL++ grammar mutator only after a basic target is healthy and evidence justifies the change.
- Report only clean-source LLVM coverage. Fuzz-only behavioural patches must never contribute to user-facing coverage.
- Never promote a raw crash directly to a finding. Replay, minimise, fingerprint, deduplicate, and preserve uncertainty first.
- Do not display fake projects, campaigns, metrics, findings, logs, or sample runtime records in production code.
- Use the five-colour UI system: black, white, red, warm off-white, neutral grey. Keep engine, model, sanitizer, and Docker names in secondary technical details.
- Meet WCAG 2.2 AA contrast, keyboard, focus, semantic naming, and reduced-motion requirements.
- Every task uses TDD, stages only its named files, and ends with a focused commit.

## Target File Structure

The following structure is created incrementally. A directory is added only by the first task that needs it.

```text
backend/
├── api/
│   ├── app.py
│   ├── dependencies.py
│   ├── controllers/{projects,campaigns,coverage,findings,events,settings}.py
│   └── views/{project,campaign,coverage,finding,event,settings}.py
├── models/{project,task,asset,campaign,coverage,finding}.py
├── database/{connection,schema.sql,reset.sh}
├── repositories/{project,task,asset,campaign,coverage,finding}_repository.py
├── services/
│   ├── projects/{create_project,clone_repository,project_settings}.py
│   ├── campaigns/{coordinator_registry,project_coordinator,wake_rules,decision_executor}.py
│   └── observability/{event_store,event_stream,redaction}.py
├── agents/
│   ├── context.py
│   ├── manager.py
│   ├── specialists/{system_target,component_target,crash_triage}.py
│   ├── outputs/{target_proposal,campaign_decision,triage_result}.py
│   ├── prompts/{manager,system_target,component_target,crash_triage}.py
│   ├── tools/{code_navigation,evidence_retrieval,generated_assets,contained_operations,agent_dispatch}.py
│   └── tracing/{hooks,local_trace}.py
├── fuzzing/
│   ├── images/Dockerfile
│   ├── docker/{client,image_builder,image_inspector,container_runner,fuzz_container}.py
│   ├── layers/{manifest,policy,repository_layer,project_layer,target_layer,coverage_layer}.py
│   ├── assets/{store,validation}.py
│   ├── discovery/{inventory,retrieval}.py
│   ├── engines/afl/{command,stats}.py
│   ├── engines/libfuzzer/{command,stats}.py
│   ├── campaigns/{monitor,probe,target_preparation}.py
│   ├── corpus/{admission,minimisation,synchronisation}.py
│   ├── coverage/{llvm_coverage,traceability,exposure,overlap}.py
│   └── crashes/{quarantine,replay,minimisation,fingerprint,triage}.py
├── tests/
│   ├── fixtures/{system_project,component_project}/
│   └── test_*.py
└── run.py

frontend/src/
├── models/{project,campaign,coverage,finding,event,settings}.ts
├── controllers/{useProjects,useProjectOverview,useSourceAssurance,useFindings,useActivity,useProjectSettings}.ts
├── views/{ProjectsView,OverviewView,SourceAssuranceView,FindingsView,ActivityView,SettingsView}.tsx
├── components/
│   ├── design-system/{Button,Disclosure,EmptyState,Field,StatusText}.tsx
│   ├── coverage/{CoverageMap,SourceTree,SourceCode,LineEvidence}.tsx
│   ├── findings/{FindingList,FindingDetail}.tsx
│   └── activity/{ActivityList,DebugLog}.tsx
├── services/{apiClient,eventStream}.ts
├── App.tsx
└── app.css

scripts/{setup,start,check}.sh
tests/e2e/bigeye.spec.ts
playwright.config.ts
.github/workflows/ci.yml
```

---

### Task 1: Release persistence and project lifecycle

**Files:**
- Modify: `.gitignore`
- Remove: `.env.example`
- Modify: `.env_example`
- Modify: `backend/database/schema.sql`
- Modify: `backend/models/project.py`
- Create: `backend/models/asset.py`
- Create: `backend/models/campaign.py`
- Create: `backend/models/coverage.py`
- Create: `backend/models/finding.py`
- Modify: `backend/repositories/project_repository.py`
- Create: `backend/repositories/asset_repository.py`
- Create: `backend/repositories/campaign_repository.py`
- Create: `backend/repositories/coverage_repository.py`
- Create: `backend/repositories/finding_repository.py`
- Modify: `backend/tests/test_development_database.py`
- Create: `backend/tests/test_release_persistence.py`
- Modify: `backend/api/views/project.py`
- Modify: `backend/services/create_project.py`
- Modify: `backend/services/execute_project_backbone.py`
- Modify: `backend/services/run_project_backbone.py`

**Interfaces:**
- Consumes: existing `asyncpg` pool and integer project/task identifiers.
- Produces: `ProjectRepository.create_with_tasks(repository_url, worker_count, task_names, requested_revision="HEAD", repository_token=None) -> Project`; `get_repository_token(project_id) -> str | None`; `update_settings(project_id, worker_count, repository_token) -> Project`; `pause(project_id)`, `resume(project_id)`; repository classes for `CampaignAsset`, `Campaign`, `CoverageEvidence`, and `Finding`.

- [ ] **Step 1: Replace the minimal-schema contract with release-state tests**

```python
def test_release_schema_has_only_required_tables_and_no_enum_types():
    schema = (ROOT / "backend/database/schema.sql").read_text()
    for table in ("projects", "tasks", "assets", "campaigns", "coverage_evidence", "findings"):
        assert f"CREATE TABLE {table}" in schema
    assert "CREATE TYPE" not in schema
    assert "metadata" not in schema.lower()

def test_project_response_model_never_contains_token():
    from backend.models.project import Project
    assert "repository_token" not in Project.__dataclass_fields__
```

- [ ] **Step 2: Run the persistence tests and confirm the old schema fails**

Run: `backend/.venv/bin/pytest backend/tests/test_development_database.py backend/tests/test_release_persistence.py -q`

Expected: FAIL because release tables and revision/pause fields do not exist.

- [ ] **Step 3: Add the exact release tables and focused models**

```python
@dataclass(frozen=True)
class Project:
    id: int
    repository_url: str
    requested_revision: str
    worker_count: int
    commit_sha: str | None
    token_present: bool
    created_at: datetime
    paused_at: datetime | None
    error: str | None

@dataclass(frozen=True)
class CampaignAsset:
    id: int
    project_id: int
    kind: str
    name: str
    content_hash: str
    parent_id: int | None
    created_at: datetime
    validated_at: datetime | None
    error: str | None

@dataclass(frozen=True)
class Campaign:
    id: int
    project_id: int
    target_asset_id: int
    configuration_asset_id: int | None
    engine: str
    started_at: datetime
    stopped_at: datetime | None
    last_heartbeat_at: datetime | None
    cpu_seconds: float
    next_review_after: datetime | None
    next_review_reason: str | None
    error: str | None

@dataclass(frozen=True)
class CoverageEvidence:
    id: int
    project_id: int
    commit_sha: str
    source_path: str
    line_number: int
    function_name: str | None
    campaign_id: int
    asset_id: int
    first_testcase_sha256: str
    cpu_exposure_seconds: float

@dataclass(frozen=True)
class Finding:
    id: int
    project_id: int
    fingerprint: str
    classification: str
    priority_rank: int | None
    priority_reason: str | None
    description: str
    reproducible: bool
    occurrence_count: int
    created_at: datetime
    triaged_at: datetime | None
    error: str | None
```

Store classification and engine as text; do not add Python or PostgreSQL enum types.

- [ ] **Step 4: Implement transactional repositories and project setting changes**

```python
async def update_settings(self, project_id: int, worker_count: int, repository_token: str | None) -> Project:
    row = await self._pool.fetchrow(
        """UPDATE projects
           SET worker_count = $2,
               repository_token = CASE WHEN $3::text IS NULL THEN repository_token ELSE NULLIF($3, '') END
           WHERE id = $1
           RETURNING id, repository_url, requested_revision, worker_count, commit_sha,
                     repository_token IS NOT NULL AS token_present, created_at, paused_at, error""",
        project_id,
        worker_count,
        repository_token,
    )
    if row is None:
        raise KeyError(project_id)
    return self._project(row)
```

Every repository owns only SQL and row conversion. Add foreign keys and query indexes needed by project, campaign, source path/line, fingerprint, and creation ordering. Preserve one resettable schema file.

- [ ] **Step 5: Keep the existing backbone compatible with continuous projects**

Change `ProjectResponse` to expose requested revision, commit, token presence, pause, and error without `finished_at`. Make the current create service use the repository defaults until Task 2 supplies explicit revision/token values. Replace project completion with error persistence only, and recover projects whose `paused_at` and `error` are both null. These changes keep the full existing backend suite passing while Task 12 later replaces the temporary three-task scheduler.

- [ ] **Step 6: Track environment and generated-state rules**

Update `.gitignore` to ignore `.superpowers/` as a whole. Keep `.env` ignored, remove the duplicate `.env.example`, and commit `.env_example` with only `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `BIGEYE_POSTGRES_PORT`, and an empty `OPENAI_API_KEY`.

- [ ] **Step 7: Reset the local database and run repository tests**

Run: `backend/database/reset.sh && backend/.venv/bin/pytest backend/tests -q`

Expected: the full backend suite PASS; PostgreSQL contains six application tables and no user-defined enum type.

- [ ] **Step 8: Commit**

```bash
git add .gitignore .env.example .env_example backend/database/schema.sql backend/models backend/repositories backend/api/views/project.py backend/services/create_project.py backend/services/execute_project_backbone.py backend/services/run_project_backbone.py backend/tests/test_development_database.py backend/tests/test_release_persistence.py
git commit -m "feat: add release campaign persistence"
```

### Task 2: Project API, immutable revision, token, pause, and settings

**Files:**
- Modify: `backend/api/views/project.py`
- Modify: `backend/api/controllers/projects.py`
- Modify: `backend/api/controllers/settings.py`
- Modify: `backend/api/views/settings.py`
- Create: `backend/services/projects/create_project.py`
- Move and modify: `backend/services/clone_repository.py` -> `backend/services/projects/clone_repository.py`
- Create: `backend/services/projects/project_settings.py`
- Modify: `backend/api/dependencies.py`
- Modify: `backend/tests/test_project_backbone.py`
- Create: `backend/tests/test_project_api.py`

**Interfaces:**
- Consumes: Task 1 project repository methods.
- Produces: `POST /api/projects`, `PATCH /api/projects/{id}/settings`, `POST /api/projects/{id}/pause`, `POST /api/projects/{id}/resume`, `GET /api/projects/{id}/settings`; `CreateProjectRequest(repository_url, revision, worker_count, repository_token)`.

- [ ] **Step 1: Write API boundary tests**

```python
def test_create_accepts_revision_and_token_but_response_redacts_token(client, services):
    response = client.post("/api/projects", json={
        "repository_url": "https://github.com/acme/demo.git",
        "revision": "stable",
        "worker_count": 2,
        "repository_token": "secret-read-token",
    })
    assert response.status_code == 202
    assert response.json()["requested_revision"] == "stable"
    assert response.json()["token_present"] is True
    assert "repository_token" not in response.json()

def test_revision_cannot_be_changed_by_settings(client):
    response = client.patch("/api/projects/7/settings", json={"revision": "other"})
    assert response.status_code == 422
```

- [ ] **Step 2: Run the new API tests and verify failure**

Run: `backend/.venv/bin/pytest backend/tests/test_project_api.py -q`

Expected: FAIL because the request and project-setting routes do not exist.

- [ ] **Step 3: Add strict request/response views and thin controllers**

```python
class CreateProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_url: str = Field(min_length=1, max_length=2048)
    revision: str = Field(default="HEAD", min_length=1, max_length=255)
    worker_count: int = Field(gt=0, le=2_147_483_647)
    repository_token: str | None = Field(default=None, max_length=4096)

class UpdateProjectSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    worker_count: int | None = Field(default=None, gt=0, le=2_147_483_647)
    repository_token: str | None = Field(default=None, max_length=4096)
```

Controllers call one service and map `KeyError` to 404 and validation failures to 422. They never log request bodies.

- [ ] **Step 4: Move project services without compatibility wrappers**

Update imports to `backend.services.projects.*`, delete the old service file after all references change, and keep URL validation and contained path behaviour intact. `ProjectSettingsService` performs pause/resume and setting changes, then notifies the coordinator registry.

- [ ] **Step 5: Run backend tests**

Run: `backend/.venv/bin/pytest backend/tests/test_project_api.py backend/tests/test_project_backbone.py backend/tests/test_final_gaps.py -q`

Expected: PASS with no token value in captured logs or responses.

- [ ] **Step 6: Commit**

```bash
git add backend/api backend/services backend/tests/test_project_api.py backend/tests/test_project_backbone.py backend/tests/test_final_gaps.py
git commit -m "feat: add project revision and controls"
```

### Task 3: Professional frontend shell and project journey

**Files:**
- Modify: `frontend/package.json`
- Modify: `frontend/package-lock.json`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/app.css`
- Modify: `frontend/src/models/project.ts`
- Modify: `frontend/src/models/settings.ts`
- Modify: `frontend/src/services/apiClient.ts`
- Create: `frontend/src/controllers/useProjects.ts`
- Create: `frontend/src/controllers/useProjectSettings.ts`
- Modify: `frontend/src/components/Navigation.tsx`
- Modify: `frontend/src/components/ProjectPicker.tsx`
- Create: `frontend/src/components/design-system/Button.tsx`
- Create: `frontend/src/components/design-system/Disclosure.tsx`
- Create: `frontend/src/components/design-system/EmptyState.tsx`
- Create: `frontend/src/components/design-system/Field.tsx`
- Create: `frontend/src/components/design-system/StatusText.tsx`
- Modify: `frontend/src/views/ProjectsView.tsx`
- Modify: `frontend/src/views/SettingsView.tsx`
- Modify: `frontend/src/AppJourney.test.tsx`
- Create: `frontend/src/Accessibility.test.tsx`

**Interfaces:**
- Consumes: Task 2 HTTP contracts.
- Produces: pages `projects | overview | source | findings | activity | settings`; project creation with revision and optional token; project-scoped settings and pause/resume actions.

- [ ] **Step 1: Write the shell and journey tests first**

```tsx
it('keeps implementation names out of primary navigation', async () => {
  render(<App api={apiDouble()} />);
  expect(await screen.findByRole('navigation', { name: 'Main navigation' })).toBeVisible();
  for (const label of ['AFL++', 'libFuzzer', 'Luna', 'Terra', 'Docker']) {
    expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument();
  }
});

it('creates a project with revision and an optional private token', async () => {
  const api = apiDouble();
  render(<App api={api} />);
  await userEvent.type(screen.getByLabelText('Repository URL'), 'https://github.com/acme/demo.git');
  await userEvent.type(screen.getByLabelText('Revision'), 'stable');
  await userEvent.click(screen.getByRole('button', { name: 'Private repository' }));
  await userEvent.type(screen.getByLabelText('Read-only access token'), 'token');
  await userEvent.click(screen.getByRole('button', { name: 'Start project' }));
  expect(api.createProject).toHaveBeenCalledWith(expect.objectContaining({ revision: 'stable', repository_token: 'token' }));
});
```

- [ ] **Step 2: Run frontend tests and verify failure**

Run: `cd frontend && npm test -- --run src/AppJourney.test.tsx src/Accessibility.test.tsx`

Expected: FAIL because the new navigation and fields are absent.

- [ ] **Step 3: Install only the approved UI dependencies**

First replace every existing `"latest"` entry in `frontend/package.json` with the exact version reported by `npm ls --depth=0`. Then run: `cd frontend && npm install --save-exact @radix-ui/react-dialog @radix-ui/react-tabs @radix-ui/react-tooltip @radix-ui/react-scroll-area lucide-react`

Expected: `package.json` and `package-lock.json` contain exact resolved versions; no chart theme framework is added.

- [ ] **Step 4: Implement the five-colour design system and project controllers**

```css
:root {
  --color-black: #101010;
  --color-white: #ffffff;
  --color-red: #c81e2a;
  --color-warm: #f5f2ed;
  --color-grey: #737373;
  --focus-ring: 0 0 0 3px rgba(200, 30, 42, 0.28);
  color: var(--color-black);
  background: var(--color-warm);
}
```

Use a narrow black navigation, white work surface, hairline separators, minimal radius, no gradients, and no decorative status colours. Split the old all-purpose controller into project and project-settings hooks; views receive data and callbacks only.

- [ ] **Step 5: Implement real creation, project selection, settings, and pause/resume**

After creation, navigate to Overview. Make revision and commit read-only in Settings, worker count editable, and the token input always blank with a “token configured” message. Never place token state in browser storage.

- [ ] **Step 6: Run tests, typecheck, and production build**

Run: `cd frontend && npm test && npm run typecheck && npm run build`

Expected: all commands PASS; production output contains no sample projects or findings.

- [ ] **Step 7: Commit**

```bash
git add frontend/package.json frontend/package-lock.json frontend/src
git commit -m "feat: add professional project shell"
```

### Task 4: Append-only activity, debug logs, and resumable SSE

**Files:**
- Create: `backend/services/observability/redaction.py`
- Create: `backend/services/observability/event_store.py`
- Create: `backend/services/observability/event_stream.py`
- Create: `backend/models/event.py`
- Create: `backend/api/views/event.py`
- Create: `backend/api/controllers/events.py`
- Modify: `backend/api/app.py`
- Modify: `backend/api/dependencies.py`
- Modify: `backend/services/run_project_backbone.py`
- Create: `backend/tests/test_observability.py`

**Interfaces:**
- Consumes: contained workspace path rules.
- Produces: `ProjectEventStore.append(project_id, stream, payload) -> StoredEvent`; `read(project_id, stream, after, limit) -> list[StoredEvent]`; SSE endpoint `/api/projects/{id}/events` honoring `Last-Event-ID`; query endpoint `/api/projects/{id}/logs/{activity|debug}`.

- [ ] **Step 1: Write event durability and redaction tests**

```python
def test_event_id_is_the_durable_jsonl_byte_offset(tmp_path):
    store = ProjectEventStore(tmp_path)
    first = run(store.append(7, "activity", {"message": "one"}))
    second = run(store.append(7, "activity", {"message": "two"}))
    assert first.id == 0
    assert second.id > first.id
    assert [event.payload["message"] for event in run(store.read(7, "activity", first.id, 20))] == ["two"]

def test_redaction_removes_tokens_and_authorization_headers():
    value = redact({"Authorization": "Bearer secret", "repository_token": "secret", "safe": "value"})
    assert value == {"Authorization": "[REDACTED]", "repository_token": "[REDACTED]", "safe": "value"}
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_observability.py -q`

Expected: FAIL with missing observability modules.

- [ ] **Step 3: Implement descriptor-contained JSONL storage**

Each record is one UTF-8 JSON object containing `id`, `created_at`, `stream`, and redacted `payload`. Use the starting byte offset as the event ID, a per-project async lock for append ordering, an 8 MiB response cap, and byte-offset reads that resume only at record boundaries.

- [ ] **Step 4: Replace polling snapshots with resumable events**

```python
@router.get("/projects/{project_id}/events")
async def project_events(project_id: int, request: Request):
    after = request.headers.get("last-event-id")
    cursor = int(after) if after is not None else -1
    return StreamingResponse(
        request.app.state.services.events.stream(project_id, cursor),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )
```

Emit invalidation names such as `project`, `campaigns`, `coverage`, `findings`, `activity`, and `debug`; do not send complete resource snapshots in SSE.

- [ ] **Step 5: Run observability and existing lifecycle tests**

Run: `backend/.venv/bin/pytest backend/tests/test_observability.py backend/tests/test_project_backbone.py backend/tests/test_final_gaps.py -q`

Expected: PASS with reconnect tests proving no duplicate event delivery.

- [ ] **Step 6: Commit**

```bash
git add backend/services/observability backend/models/event.py backend/api backend/services/run_project_backbone.py backend/tests/test_observability.py backend/tests/test_project_backbone.py backend/tests/test_final_gaps.py
git commit -m "feat: add durable project event streams"
```

### Task 5: BigEye-owned LLVM and AFL++ toolchain image

**Files:**
- Modify: `backend/fuzzing/images/Dockerfile`
- Modify: `backend/fuzzing/toolchain/builder.py`
- Modify: `backend/fuzzing/toolchain/verifier.py`
- Modify: `backend/fuzzing/toolchain/service.py`
- Create: `backend/fuzzing/toolchain/verify_image.py`
- Modify: `backend/tests/test_fuzzing_docker.py`
- Create: `backend/tests/test_toolchain_image.py`

**Interfaces:**
- Consumes: existing Docker client, image builder, and inspector.
- Produces: one cached `bigeye-toolchain:<content-hash>` image containing LLVM 18, libFuzzer, ASan, UBSan, `llvm-profdata`, `llvm-cov`, AFL++ v4.40c, `afl-cmin`, `afl-tmin`, `afl-showmap`, and the upstream grammar mutator shared library.

- [ ] **Step 1: Add Dockerfile and verifier contract tests**

```python
def test_toolchain_is_owned_pinned_and_has_no_oss_fuzz_reference():
    dockerfile = (ROOT / "backend/fuzzing/images/Dockerfile").read_text()
    assert "AFL_VERSION=v4.40c" in dockerfile
    assert "e5a8ba39ecf97d05e286fdd4e01da96554dbf64f" in dockerfile
    assert "FROM --platform=linux/amd64 ubuntu@sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf" in dockerfile
    assert "oss-fuzz" not in dockerfile.lower()

def test_verifier_checks_both_engines_and_clean_coverage_tools():
    command = ToolchainVerifier.command()
    for binary in ("clang-18", "llvm-profdata-18", "llvm-cov-18", "afl-fuzz", "afl-cmin", "afl-tmin"):
        assert binary in command
```

- [ ] **Step 2: Run tests and verify failure**

Run: `backend/.venv/bin/pytest backend/tests/test_toolchain_image.py backend/tests/test_fuzzing_docker.py -q`

Expected: FAIL because AFL++ and digest pinning are absent.

- [ ] **Step 3: Build AFL++ from verified official source inside the baseline**

Use the exact Ubuntu digest in Global Constraints. Shallow-fetch the official `v4.40c` tag, assert `git rev-parse HEAD` equals `e5a8ba39ecf97d05e286fdd4e01da96554dbf64f`, compile AFL++ against LLVM 18, compile its included grammar mutator, and remove source/build caches in the same layer. Do not use the upstream AFL++ container image.

- [ ] **Step 4: Extend content hashing and verification**

Include Dockerfile bytes, platform, LLVM version, and AFL++ version in the toolchain tag. The verifier runs under `linux/amd64` and checks binary versions plus a one-file ASan/UBSan/libFuzzer compile and an AFL++ instrumented compile.

- [ ] **Step 5: Run unit tests and real image verification**

Run: `backend/.venv/bin/pytest backend/tests/test_toolchain_image.py backend/tests/test_fuzzing_docker.py -q`

Run: `set -a; . ./.env; set +a; backend/.venv/bin/python -m backend.fuzzing.toolchain.verify_image`

Expected: tests PASS; `verify_image.py` prints one image ID with `linux/amd64`, LLVM 18, and AFL++ 4.40c checks passing. Test its zero success exit code and non-zero verification-failure exit code.

- [ ] **Step 6: Commit**

```bash
git add backend/fuzzing/images/Dockerfile backend/fuzzing/toolchain backend/tests/test_toolchain_image.py backend/tests/test_fuzzing_docker.py
git commit -m "feat: add pinned AFL++ toolchain"
```

### Task 6: Exact revision cloning and repository image layer

**Files:**
- Modify: `backend/services/projects/clone_repository.py`
- Create: `backend/fuzzing/layers/manifest.py`
- Create: `backend/fuzzing/layers/repository_layer.py`
- Modify: `backend/fuzzing/docker/image_builder.py`
- Create: `backend/tests/test_repository_layer.py`
- Modify: `backend/tests/test_project_backbone.py`

**Interfaces:**
- Consumes: project revision/token methods and toolchain image tag.
- Produces: `clone_argv(repository_url, destination) -> list[str]`; `CloneRepositoryService.clone(project, task) -> str`; `RepositoryLayerService.prepare(project_id, repository_root, commit_sha, parent_tag, sink) -> LayerManifest`.

- [ ] **Step 1: Write clone authentication, revision, and safe-context tests**

```python
def test_clone_fetches_requested_revision_and_detaches_exact_commit():
    assert clone_argv("url", "stable", "/repo") == [
        "git", "clone", "--no-checkout", "--", "url", "/repo"
    ]

def test_repository_context_excludes_git_and_secrets(tmp_path):
    manifest = prepare_fixture_context(tmp_path, token="never-copy")
    assert not (manifest.context_dir / ".git").exists()
    assert "never-copy" not in read_all_text(manifest.context_dir)
    assert manifest.labels["bigeye.commit"] == "a" * 40
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_repository_layer.py backend/tests/test_project_backbone.py -q`

Expected: FAIL because revision checkout and repository layers are absent.

- [ ] **Step 3: Implement ephemeral Git ask-pass and exact revision resolution**

Create a mode-0700 temporary directory under the project staging root, a mode-0700 ask-pass script that reads the token from a process environment variable, and delete it in `finally`. Clone without checkout, fetch the requested revision, resolve `^{commit}`, checkout detached, and verify `HEAD` equals the stored SHA. Sanitize every error to `Git command failed` plus a safe operation name.

- [ ] **Step 4: Implement safe context and generated repository Dockerfile**

```python
@dataclass(frozen=True)
class LayerManifest:
    kind: str
    tag: str
    content_hash: str
    parent_tag: str
    dockerfile: Path
    context_dir: Path
    labels: dict[str, str]
```

Copy the checkout without `.git`, symlinks escaping the checkout, workspace data, or credential files. Generate `FROM <parent-tag>`, `WORKDIR /src`, `COPY repository/ /src/`, and BigEye labels. Derive the tag from parent image ID, commit SHA, Dockerfile, and context hash; reuse an inspected matching image.

- [ ] **Step 5: Run tests and a safe layer smoke build**

Run: `backend/.venv/bin/pytest backend/tests/test_repository_layer.py backend/tests/test_project_backbone.py -q`

Expected: PASS; a changed corpus outside the safe context does not change the repository tag.

- [ ] **Step 6: Commit**

```bash
git add backend/services/projects/clone_repository.py backend/fuzzing/layers backend/fuzzing/docker/image_builder.py backend/tests/test_repository_layer.py backend/tests/test_project_backbone.py
git commit -m "feat: add immutable repository layers"
```

### Task 7: Versioned assets and incremental project, target, and coverage layers

**Files:**
- Create: `backend/fuzzing/assets/store.py`
- Create: `backend/fuzzing/assets/validation.py`
- Create: `backend/fuzzing/layers/policy.py`
- Create: `backend/fuzzing/layers/project_layer.py`
- Create: `backend/fuzzing/layers/target_layer.py`
- Create: `backend/fuzzing/layers/coverage_layer.py`
- Create: `backend/tests/test_campaign_assets.py`
- Create: `backend/tests/test_incremental_layers.py`

**Interfaces:**
- Consumes: Task 1 asset repository and Task 6 `LayerManifest`.
- Produces: `AssetStore.create(project_id, kind, name, files, parent_id) -> CampaignAsset`; `validate_generated_dockerfile(text, required_parent) -> None`; `ProjectLayerService.prepare(project, repository_manifest, build_asset, sink) -> LayerManifest`; `TargetLayerService.prepare(project, project_manifest, target_asset, configuration_asset, sink) -> LayerManifest`; `CoverageLayerService.prepare(project, project_manifest, adapter_asset, coverage_configuration, sink) -> LayerManifest`.

- [ ] **Step 1: Write content-addressing and dependency-isolation tests**

```python
def test_corpus_change_does_not_change_target_layer(asset_store, layer_service):
    first = layer_service.tag(harness_hash="h1", build_hash="b1", corpus_hash="c1")
    second = layer_service.tag(harness_hash="h1", build_hash="b1", corpus_hash="c2")
    assert first == second

def test_fuzz_patch_is_rejected_from_clean_coverage_context(policy):
    with pytest.raises(LayerPolicyError, match="fuzz-only patch"):
        policy.validate_coverage_inputs(["target.patch"])
```

- [ ] **Step 2: Run layer tests and verify failure**

Run: `backend/.venv/bin/pytest backend/tests/test_campaign_assets.py backend/tests/test_incremental_layers.py -q`

Expected: FAIL with missing asset and layer modules.

- [ ] **Step 3: Implement atomic asset versions**

Write files into `assets/<id>.staging`, fsync, validate containment and declared hashes, rename to `assets/<id>`, then mark the row validated. Parent version and content hash make rollback explicit. Reject executable host files except generated shell scripts that are executed only inside containers.

- [ ] **Step 4: Implement generated Dockerfile policy**

Allow `ARG`, one `FROM` equal to the required parent, `WORKDIR`, `COPY` from the generated context, `ENV`, and bounded `RUN` steps. Reject additional stages, remote `ADD`, secret mounts, host paths, privileged instructions, and references to OSS-Fuzz. Build steps that acquire dependencies declare network access; target compilation and coverage layers use no network.

- [ ] **Step 5: Implement incremental layer services**

Project dependencies depend on repository image and build asset. Target layers depend on project image plus harness/adapter, fuzz patch, and compile configuration. Coverage layers depend on the clean repository/project image plus an external adapter and coverage configuration, never a fuzz patch. Every service inspects tags before building and records labels for project, commit, layer kind, and content hash.

- [ ] **Step 6: Run tests**

Run: `backend/.venv/bin/pytest backend/tests/test_campaign_assets.py backend/tests/test_incremental_layers.py backend/tests/test_fuzzing_docker.py -q`

Expected: PASS with cache reuse and selective invalidation assertions.

- [ ] **Step 7: Commit**

```bash
git add backend/fuzzing/assets backend/fuzzing/layers backend/tests/test_campaign_assets.py backend/tests/test_incremental_layers.py backend/tests/test_fuzzing_docker.py
git commit -m "feat: add reusable campaign layers"
```

### Task 8: Deterministic discovery and local repository RAG

**Files:**
- Create: `backend/fuzzing/discovery/inventory.py`
- Create: `backend/fuzzing/discovery/retrieval.py`
- Modify: `backend/agents/context.py`
- Modify: `backend/agents/tools/code_navigation.py`
- Create: `backend/agents/tools/evidence_retrieval.py`
- Create: `backend/tests/test_discovery.py`
- Modify: `backend/tests/test_agents.py`

**Interfaces:**
- Consumes: immutable repository root and contained command execution.
- Produces: `RepositoryInventory.collect(root) -> Inventory`; `EvidenceRetriever.search(question, limit=12) -> list[EvidenceExcerpt]`; agent tools `inspect_build_evidence`, `retrieve_repository_evidence`, and existing bounded navigation tools.

- [ ] **Step 1: Write discovery and hostile-content tests**

```python
def test_inventory_finds_build_inputs_outputs_and_samples(fixture_repository):
    inventory = RepositoryInventory().collect(fixture_repository)
    assert "CMakeLists.txt" in inventory.build_files
    assert "demo" in inventory.executables
    assert inventory.sample_inputs

def test_retrieval_marks_repository_text_as_untrusted(retriever):
    excerpts = retriever.search("input parser")
    assert excerpts[0].provenance == "repository"
    assert excerpts[0].trusted_instructions is False
    assert len(excerpts) <= 12
```

- [ ] **Step 2: Verify discovery tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_discovery.py backend/tests/test_agents.py -q`

Expected: FAIL with missing discovery modules.

- [ ] **Step 3: Implement bounded inventory collection**

Inspect known build manifests, compile commands, executable/library file types, public headers, tests, examples, fixtures, sample inputs, help text, and existing repository-owned fuzz harnesses. Cap every command, file read, result list, and total evidence bytes. Do not execute arbitrary project tests on the host.

- [ ] **Step 4: Implement retrieval without a remote vector store**

Rank exact path/name hits, symbol/build evidence, and `rg` text hits. Return repository-relative path, line range, excerpt, evidence ID, retrieval reason, and untrusted provenance. This is the local RAG boundary used by agents.

- [ ] **Step 5: Extend agent context and tools**

```python
@dataclass(frozen=True)
class AgentContext:
    project_id: int
    commit_sha: str
    repository_root: Path
    generated_assets_root: Path
    evidence: EvidenceRetriever
```

Preserve traversal, `.git`, symlink, line-count, and output-size rejection.

- [ ] **Step 6: Run tests and commit**

Run: `backend/.venv/bin/pytest backend/tests/test_discovery.py backend/tests/test_agents.py -q`

Expected: PASS.

```bash
git add backend/fuzzing/discovery backend/agents/context.py backend/agents/tools backend/tests/test_discovery.py backend/tests/test_agents.py
git commit -m "feat: add actionable target evidence"
```

### Task 9: Agents SDK manager, specialists, bounded tools, and complete traces

**Files:**
- Create: `backend/agents/outputs/target_proposal.py`
- Create: `backend/agents/outputs/campaign_decision.py`
- Create: `backend/agents/outputs/triage_result.py`
- Modify: `backend/agents/manager.py`
- Create: `backend/agents/specialists/system_target.py`
- Create: `backend/agents/specialists/component_target.py`
- Create: `backend/agents/specialists/crash_triage.py`
- Replace: `backend/agents/prompts/manager.py`
- Create: `backend/agents/prompts/system_target.py`
- Create: `backend/agents/prompts/component_target.py`
- Create: `backend/agents/prompts/crash_triage.py`
- Create: `backend/agents/tools/generated_assets.py`
- Create: `backend/agents/tools/contained_operations.py`
- Modify: `backend/agents/tools/agent_dispatch.py`
- Create: `backend/agents/tracing/hooks.py`
- Create: `backend/agents/tracing/local_trace.py`
- Replace: `backend/agents/workflow.py`
- Remove: `backend/agents/repository_analysis.py`
- Remove: `backend/agents/prompts/repository_analysis.py`
- Modify: `backend/tests/test_agents.py`
- Create: `backend/tests/test_agent_tracing.py`

**Interfaces:**
- Consumes: Task 4 event store, Task 7 asset store/contained operations, Task 8 retrieval.
- Produces: `CampaignManager.review(context, evidence, reason) -> CampaignDecision`; specialist tools `prepare_system_target`, `prepare_component_target`, `triage_crash_group`; complete sanitized OpenAI debug events.

- [ ] **Step 1: Write typed delegation and trace tests**

```python
def test_manager_has_specialists_as_tools_and_no_code_navigation_tools():
    manager = build_manager_agent(dispatch_tools())
    assert {tool.name for tool in manager.tools} == {
        "prepare_system_target", "prepare_component_target", "triage_crash_group"
    }

def test_trace_contains_model_tool_usage_and_no_secrets(event_store):
    run_recorded_agent_workflow(event_store, api_key="sk-secret", repository_token="git-secret")
    debug = read_debug(event_store)
    assert_has_fields(debug, "trace_id", "response_id", "agent", "model", "input", "output", "usage")
    assert "sk-secret" not in json.dumps(debug)
    assert "git-secret" not in json.dumps(debug)
```

- [ ] **Step 2: Run agent tests and verify failure**

Run: `backend/.venv/bin/pytest backend/tests/test_agents.py backend/tests/test_agent_tracing.py -q`

Expected: FAIL because the manager still performs generic repository analysis.

- [ ] **Step 3: Add complete structured outputs**

`TargetProposal` contains target name, instance type text, byte path, expected project reach, build command, run command, seeds with provenance, configuration, sanitizer plan, generated asset intents, probe assertions, evidence IDs, and uncertainty. `CampaignDecision` contains decision, motivation, evidence IDs, bounded actions, next review condition, and uncertainty. `TriageResult` contains classification text, description, evidence IDs, uncertainty, priority rationale, and repair intent.

- [ ] **Step 4: Build specialists and expose them through `Agent.as_tool()`**

```python
def dispatch_tools(context: AgentContext) -> list[FunctionTool]:
    return [
        build_system_target_agent("gpt-5.6-luna").as_tool(tool_name="prepare_system_target"),
        build_component_target_agent("gpt-5.6-luna").as_tool(tool_name="prepare_component_target"),
        build_crash_triage_agent("gpt-5.6-luna").as_tool(tool_name="triage_crash_group"),
    ]
```

The real implementation passes typed tool inputs and a shared application context. Each specialist receives only navigation, retrieval, web search, generated-asset patching, and contained operation tools appropriate to its role. Use the Agents SDK hosted web-search tool only for current official documentation and preserve citations.

- [ ] **Step 5: Implement Luna-first validation and one Terra retry**

Run Luna, validate every cited source range and requested artefact/probe deterministically, then construct one Terra specialist only if validation fails. Do not retry a transport or validation failure indefinitely. The manager stays Terra for project-level decisions.

- [ ] **Step 6: Implement local `RunHooks` and trace capture**

Record agent/model start/end, LLM input/output metadata, `new_items`, `raw_responses`, API reasoning summaries when returned, tool call IDs/arguments/results, usage including cache/reasoning tokens, retries, errors, parent relationships, web citations, and generated diffs. Store a concise motivation in Activity and sanitized raw records in Debug. Never label generated prose as hidden chain-of-thought.

- [ ] **Step 7: Run agent tests and an opt-in live delegation smoke**

Run: `backend/.venv/bin/pytest backend/tests/test_agents.py backend/tests/test_agent_tracing.py -q`

Run: `set -a; . ./.env; set +a; BIGEYE_LIVE_OPENAI=1 backend/.venv/bin/pytest backend/tests/test_agent_live.py -q`

Expected: deterministic tests PASS; live test records a Terra manager calling one bounded specialist and redacts the key. Create `backend/tests/test_agent_live.py` with a skip unless `BIGEYE_LIVE_OPENAI=1`.

- [ ] **Step 8: Commit**

```bash
git add backend/agents backend/tests/test_agents.py backend/tests/test_agent_tracing.py backend/tests/test_agent_live.py
git commit -m "feat: add campaign agent collaboration"
```

### Task 10: AFL++ and libFuzzer engine contracts and durable fuzz containers

**Files:**
- Create: `backend/fuzzing/engines/afl/command.py`
- Create: `backend/fuzzing/engines/afl/stats.py`
- Create: `backend/fuzzing/engines/libfuzzer/command.py`
- Create: `backend/fuzzing/engines/libfuzzer/stats.py`
- Create: `backend/fuzzing/docker/fuzz_container.py`
- Modify: `backend/fuzzing/docker/container_runner.py`
- Create: `backend/tests/test_fuzz_engines.py`
- Create: `backend/tests/test_fuzz_container.py`

**Interfaces:**
- Consumes: validated target images and campaign workspace paths.
- Produces: `AflCommand.build(spec) -> ContainerInvocation`; `LibFuzzerCommand.build(spec) -> ContainerInvocation`; `FuzzContainerService.start(campaign, invocation) -> ContainerIdentity`; `stop`, `inspect`, `stream_logs`, and `recover`.

- [ ] **Step 1: Write exact command and isolation tests**

```python
def test_afl_file_input_primary_command():
    invocation = AflCommand.build(afl_spec(input_mode="file", role="main"))
    assert invocation.command[:5] == ["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output"]
    assert "@@" in invocation.command
    assert invocation.network_disabled is True

def test_libfuzzer_mounts_only_campaign_state():
    invocation = LibFuzzerCommand.build(libfuzzer_spec())
    assert invocation.command[0] == "/opt/bigeye/target"
    assert "/campaign/corpus" in invocation.command
    assert invocation.read_only_source is True
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_fuzz_engines.py backend/tests/test_fuzz_container.py -q`

Expected: FAIL with missing engine modules.

- [ ] **Step 3: Implement pure command builders and parsers**

Use data-only specifications with engine, target command, input mode, corpus/output paths, role, sanitizer environment, dictionary/grammar path, timeout, memory limit, and campaign labels. Parse AFL++ `fuzzer_stats` and libFuzzer stderr into execution count/rate, corpus count/size, last new path, crashes, timeouts, and health without interpreting campaign strategy.

- [ ] **Step 4: Implement long-running container ownership**

Create containers with `platform="linux/amd64"`, `network_disabled=True`, no privileged mode, a read-only root filesystem, tmpfs at `/tmp`, bounded CPU/memory/PIDs, and only campaign-specific writable mounts. Do not auto-remove active containers. `stop` sends graceful stop, then kill after a bounded timeout, persists final logs, and removes only the stopped container object.

- [ ] **Step 5: Run tests**

Run: `backend/.venv/bin/pytest backend/tests/test_fuzz_engines.py backend/tests/test_fuzz_container.py backend/tests/test_fuzzing_docker.py -q`

Expected: PASS, including adoption of a matching labelled container and rejection of mismatched commit/image labels.

- [ ] **Step 6: Commit**

```bash
git add backend/fuzzing/engines backend/fuzzing/docker backend/tests/test_fuzz_engines.py backend/tests/test_fuzz_container.py backend/tests/test_fuzzing_docker.py
git commit -m "feat: add isolated fuzz engine runners"
```

### Task 11: Target preparation, probe gates, and bounded repair

**Files:**
- Create: `backend/fuzzing/campaigns/probe.py`
- Create: `backend/fuzzing/campaigns/target_preparation.py`
- Create: `backend/services/campaigns/decision_executor.py`
- Create: `backend/tests/test_target_preparation.py`

**Interfaces:**
- Consumes: target proposals, asset/layer services, container runner, activity log.
- Produces: `TargetPreparationService.prepare(project, proposal) -> PreparedTarget`; `ProbeService.run(prepared_target) -> ProbeEvidence`; `DecisionExecutor.execute(project, decision) -> list[ActionResult]`.

- [ ] **Step 1: Write supervised-startup tests**

```python
def test_probe_rejects_target_that_only_reaches_harness_code():
    evidence = probe_evidence(alive=True, accepts_input=True, project_lines=0, harness_lines=12)
    assert ProbePolicy.accept(evidence).accepted is False
    assert "project code" in ProbePolicy.accept(evidence).reason

def test_failed_luna_asset_gets_only_one_terra_repair(preparation):
    result = run(preparation.prepare(project(), invalid_then_valid_proposal()))
    assert result.agent_attempts == ["gpt-5.6-luna", "gpt-5.6-terra"]
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_target_preparation.py -q`

Expected: FAIL with missing preparation modules.

- [ ] **Step 3: Implement incremental preparation**

Validate the normal build, create only proposed asset versions, build only dependent layers, and retain the last validated layer on failure. Serialize edits by `(project_id, asset_id)` lock. Parallel preparation is allowed only for different targets/configurations.

- [ ] **Step 4: Implement probe evidence and acceptance**

Run an empty/minimum input and at least one real seed. Record exit, liveness, accepted input, deterministic behaviour, project-source coverage, harness/startup coverage, immediate crash, timeout, and sanitizer output. Replay an immediate crash before accepting. Reject zero project reach, constant startup failure, invalid API use, or seed-independent harness crashes.

- [ ] **Step 5: Run tests and commit**

Run: `backend/.venv/bin/pytest backend/tests/test_target_preparation.py backend/tests/test_campaign_assets.py backend/tests/test_incremental_layers.py -q`

Expected: PASS.

```bash
git add backend/fuzzing/campaigns backend/services/campaigns/decision_executor.py backend/tests/test_target_preparation.py
git commit -m "feat: add validated target preparation"
```

### Task 12: Continuous project coordinator and evidence-driven manager wakeups

**Files:**
- Create: `backend/services/campaigns/wake_rules.py`
- Create: `backend/services/campaigns/project_coordinator.py`
- Create: `backend/services/campaigns/coordinator_registry.py`
- Replace: `backend/services/execute_project_backbone.py`
- Replace: `backend/services/run_project_backbone.py`
- Modify: `backend/api/dependencies.py`
- Modify: `backend/api/app.py`
- Create: `backend/tests/test_wake_rules.py`
- Create: `backend/tests/test_project_coordinator.py`

**Interfaces:**
- Consumes: projects/tasks/campaigns, discovery, manager, decision executor, engine monitor, event store.
- Produces: `WakeEvaluator.evaluate(previous, current, now) -> ReviewTrigger | None`; `ProjectCoordinator.run(project_id)`; `CoordinatorRegistry.start`, `settings_changed`, `pause`, `resume`, `recover`, `close`.

- [ ] **Step 1: Write wake-rule and no-polling tests**

```python
def test_time_slot_wakes_manager_without_stopping_campaign():
    trigger = WakeEvaluator().evaluate(previous(), current(review_due=True), NOW)
    assert trigger.reason == "review window expired"
    assert trigger.stop_campaign is False

def test_healthy_campaign_does_not_call_manager_between_conditions(coordinator):
    run(coordinator.tick(project_id=7, snapshot=healthy_growing_snapshot()))
    coordinator.manager.review.assert_not_awaited()
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_wake_rules.py backend/tests/test_project_coordinator.py -q`

Expected: FAIL with missing coordinator modules.

- [ ] **Step 3: Implement deterministic wake rules**

Represent a trigger as `ReviewTrigger(reason: str, evidence_ids: tuple[str, ...], stop_campaign: bool = False)`. Detect initial supervision completion, review deadline, plateau across three consecutive snapshots, irrelevant project coverage, validated corpus opportunity, replayed crash, unhealthy worker, documented configuration hypothesis, system gap, overlap candidate, free slot, and material asset/build change.

- [ ] **Step 4: Implement one coordinator per active project**

Acquire a PostgreSQL advisory lock, reconcile tasks/assets/campaigns/containers, clone and build the toolchain concurrently, discover targets after clone, ask the manager only on triggers, execute validated decisions, and wait on event/time conditions. The loop remains deterministic and cancellable. OpenAI failure leaves healthy fuzzers running.

- [ ] **Step 5: Enforce project worker count and pause/resume**

Increasing the count creates free slots. Decreasing it preserves and stops the manager's lowest-priority strategies until the count is met. Pause gracefully stops all project fuzzers and retains state. Resume validates commit/assets and restarts selected campaigns. There is no cross-project budget.

- [ ] **Step 6: Run coordinator and lifecycle tests**

Run: `backend/.venv/bin/pytest backend/tests/test_wake_rules.py backend/tests/test_project_coordinator.py backend/tests/test_project_backbone.py backend/tests/test_final_gaps.py -q`

Expected: PASS; no test leaves an asyncio task or container handle unobserved.

- [ ] **Step 7: Commit**

```bash
git add backend/services/campaigns backend/services/execute_project_backbone.py backend/services/run_project_backbone.py backend/api backend/tests/test_wake_rules.py backend/tests/test_project_coordinator.py backend/tests/test_project_backbone.py backend/tests/test_final_gaps.py
git commit -m "feat: add continuous campaign coordination"
```

### Task 13: Automated corpus, configuration, sanitizer, and grammar progression

**Files:**
- Create: `backend/fuzzing/corpus/admission.py`
- Create: `backend/fuzzing/corpus/minimisation.py`
- Create: `backend/fuzzing/corpus/synchronisation.py`
- Create: `backend/fuzzing/campaigns/progression.py`
- Create: `backend/fuzzing/campaigns/configuration.py`
- Create: `backend/fuzzing/campaigns/sanitizers.py`
- Create: `backend/tests/test_corpus_automation.py`
- Create: `backend/tests/test_campaign_progression.py`

**Interfaces:**
- Consumes: campaign stats, clean coverage probe, assets, container runner.
- Produces: `CorpusAdmission.validate(candidate, target) -> AdmissionResult`; `CorpusMinimiser.minimise(campaign) -> CorpusResult`; `ConfigurationPlanner.next_candidate(evidence, tried) -> ConfigurationCandidate | None`; `SanitizerPlanner.plan(target, worker_count) -> SanitizerPlan`; `CampaignProgression.next_step(evidence) -> ProgressionAction | None`.

- [ ] **Step 1: Write corpus and progression tests**

```python
def test_seed_is_admitted_only_after_execution_and_useful_evidence():
    result = policy.admit(candidate(provenance="tests/sample.bin"), execution(ok=True, new_lines={12}))
    assert result.admitted is True
    assert result.provenance == "tests/sample.bin"

def test_grammar_never_precedes_healthy_basic_campaign():
    action = CampaignProgression.next_step(evidence(healthy=False, grammar_supported=True))
    assert action is None or action.name != "enable grammar mutator"

def test_configuration_planner_returns_one_evidence_backed_candidate():
    candidate = ConfigurationPlanner.next_candidate(documented_flags(), tried=())
    assert candidate.name == "enable encryption"
    assert candidate.evidence_ids

def test_sanitizer_planner_does_not_enable_every_sanitizer():
    plan = SanitizerPlanner.plan(component_target(concurrent=False), worker_count=2)
    assert plan.primary == ("address", "undefined")
    assert "thread" not in plan.replay_variants
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_corpus_automation.py backend/tests/test_campaign_progression.py -q`

Expected: FAIL with missing corpus/progression modules.

- [ ] **Step 3: Implement automated seed collection and admission**

Collect candidates from tests, examples, fixtures, sample files, and cited agent proposals. Execute each before durable admission, record provenance and first clean delta, and reject invalid or redundant inputs. Never place corpus content in an image layer.

- [ ] **Step 4: Implement engine-native minimisation and compatible sync**

Use `afl-cmin` and `afl-tmin` for AFL++ and libFuzzer merge/minimise for component campaigns. Run at review checkpoints, preserve coverage before replacing a corpus, and sync only campaigns with compatible target/input/configuration contracts.

- [ ] **Step 5: Implement start-simple progression**

Order actions as normal build, ASan/UBSan validation, seed/coverage health, basic fuzzer, then evidence-backed dictionary, CmpLog, configuration, component gap target, specialised sanitizer, or grammar mutator. Keep native AFL++ mutations enabled with `AFL_CUSTOM_MUTATOR_LIBRARY`; do not set `AFL_CUSTOM_MUTATOR_ONLY` initially.

`ConfigurationPlanner` returns at most one documented hypothesis at a time and retains it only for unique clean coverage, unique behaviour, or a distinct crash; it never generates a Cartesian product. `SanitizerPlanner` uses ASan plus UBSan first, MSan only for a fully instrumentable dependency closure, TSan only for concurrent targets, CFI only for compatible C++ LTO targets, and leak output as quality evidence rather than an automatic vulnerability.

- [ ] **Step 6: Run tests and commit**

Run: `backend/.venv/bin/pytest backend/tests/test_corpus_automation.py backend/tests/test_campaign_progression.py backend/tests/test_fuzz_engines.py -q`

Expected: PASS.

```bash
git add backend/fuzzing/corpus backend/fuzzing/campaigns/progression.py backend/tests/test_corpus_automation.py backend/tests/test_campaign_progression.py
git commit -m "feat: automate corpus and campaign progression"
```

### Task 14: Clean LLVM coverage and first-testcase source traceability

**Files:**
- Create: `backend/fuzzing/coverage/llvm_coverage.py`
- Create: `backend/fuzzing/coverage/traceability.py`
- Create: `backend/api/views/coverage.py`
- Create: `backend/api/controllers/coverage.py`
- Modify: `backend/api/app.py`
- Create: `backend/tests/test_clean_coverage.py`
- Create: `backend/tests/test_coverage_api.py`

**Interfaces:**
- Consumes: clean coverage layer, admitted/minimised corpus, coverage repository.
- Produces: `LlvmCoverage.replay(campaign, inputs) -> CoverageSnapshot`; `TraceabilityService.record(snapshot)`, `project_tree`, `source_file`, `line_evidence`; coverage REST endpoints.

- [ ] **Step 1: Write clean-source and first-hit tests**

```python
def test_fuzz_patch_paths_cannot_enter_reported_coverage(coverage_service):
    with pytest.raises(CoverageIntegrityError):
        coverage_service.record(snapshot(build_kind="fuzz-target", lines={"src/a.c": {12}}))

def test_first_testcase_is_stable_per_strategy(traceability):
    traceability.record(hit(line=12, strategy=3, testcase="first"))
    traceability.record(hit(line=12, strategy=3, testcase="later"))
    assert traceability.line(12).first_testcase == "first"
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_clean_coverage.py backend/tests/test_coverage_api.py -q`

Expected: FAIL with missing coverage modules and routes.

- [ ] **Step 3: Implement LLVM coverage replay**

Run admitted representatives individually with unique `LLVM_PROFILE_FILE`, merge with `llvm-profdata-18`, and export JSON through `llvm-cov-18`. Verify image labels identify the clean layer and exact commit. Normalise only repository-relative project source paths; exclude generated harness and system headers from project coverage.

- [ ] **Step 4: Persist first-reaching testcase evidence**

For each newly reached line per strategy, retain the first testcase under the derived campaign coverage path, its SHA-256, replay command, target/configuration asset IDs, and clean image ID. Replaying that retained input must reproduce the line before the evidence row is committed.

- [ ] **Step 5: Add thin query APIs**

Provide project tree summaries, file source plus covered lines, function summaries, and line evidence with strategy and testcase identities. Read source only from the exact immutable checkout and enforce bounded ranges.

- [ ] **Step 6: Run tests and commit**

Run: `backend/.venv/bin/pytest backend/tests/test_clean_coverage.py backend/tests/test_coverage_api.py backend/tests/test_release_persistence.py -q`

Expected: PASS.

```bash
git add backend/fuzzing/coverage backend/api backend/tests/test_clean_coverage.py backend/tests/test_coverage_api.py
git commit -m "feat: add clean source traceability"
```

### Task 15: CPU exposure and reversible overlap retirement

**Files:**
- Create: `backend/fuzzing/coverage/exposure.py`
- Create: `backend/fuzzing/coverage/overlap.py`
- Modify: `backend/repositories/coverage_repository.py`
- Modify: `backend/services/campaigns/project_coordinator.py`
- Create: `backend/tests/test_exposure.py`
- Create: `backend/tests/test_overlap.py`

**Interfaces:**
- Consumes: campaign CPU deltas, clean reachable sets, campaign histories.
- Produces: `ExposureAccountant.apply(campaign_id, cpu_delta, reached_lines)`; `OverlapAnalyzer.compare(campaigns) -> list[RetirementCandidate]`.

- [ ] **Step 1: Write exact metric and retirement tests**

```python
def test_cpu_delta_is_added_to_every_reachable_line_not_divided():
    result = ExposureAccountant.calculate(3600.0, {("a.c", 10), ("a.c", 11)})
    assert result[("a.c", 10)] == 3600.0
    assert result[("a.c", 11)] == 3600.0

def test_subset_requires_two_checkpoints_and_no_unique_crash():
    candidate = analyzer.compare(redundant_for_two_checkpoints(unique_crashes=0))
    assert candidate[0].reversible is True
    assert analyzer.compare(redundant_for_two_checkpoints(unique_crashes=1)) == []
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_exposure.py backend/tests/test_overlap.py -q`

Expected: FAIL with missing exposure and overlap modules.

- [ ] **Step 3: Implement transactional CPU exposure**

At each stats checkpoint, calculate the positive campaign CPU delta and add it to every line in the strategy's current clean reached set. Add that delta once to every reached function independently; do not sum its line values. Name the field and UI copy `cpu_exposure_seconds`; never call it executions or per-line runtime.

- [ ] **Step 4: Implement conservative overlap analysis**

Require a clean-coverage subset at two consecutive checkpoints, no unique crash group, no unique configuration purpose, and no recent marginal line. Return evidence and the retained strategy. The manager reviews the candidate; stopping releases the worker but preserves assets, corpus, evidence, and reason.

- [ ] **Step 5: Run tests and commit**

Run: `backend/.venv/bin/pytest backend/tests/test_exposure.py backend/tests/test_overlap.py backend/tests/test_project_coordinator.py -q`

Expected: PASS.

```bash
git add backend/fuzzing/coverage backend/repositories/coverage_repository.py backend/services/campaigns/project_coordinator.py backend/tests/test_exposure.py backend/tests/test_overlap.py
git commit -m "feat: add coverage exposure and overlap control"
```

### Task 16: Crash quarantine, replay, minimisation, deduplication, and findings

**Files:**
- Create: `backend/fuzzing/crashes/quarantine.py`
- Create: `backend/fuzzing/crashes/replay.py`
- Create: `backend/fuzzing/crashes/minimisation.py`
- Create: `backend/fuzzing/crashes/fingerprint.py`
- Create: `backend/fuzzing/crashes/triage.py`
- Create: `backend/api/views/finding.py`
- Create: `backend/api/controllers/findings.py`
- Modify: `backend/api/app.py`
- Create: `backend/tests/test_crash_pipeline.py`
- Create: `backend/tests/test_findings_api.py`

**Interfaces:**
- Consumes: campaign assets/images, engine minimisers, crash specialist, finding repository.
- Produces: `CrashPipeline.process(observation) -> Finding | None`; findings list/detail/reproducer endpoints.

- [ ] **Step 1: Write controlled-crash tests**

```python
def test_duplicate_crashes_become_one_group_with_occurrence_count(pipeline):
    first = run(pipeline.process(crash(stack="same", input_bytes=b"one")))
    second = run(pipeline.process(crash(stack="same", input_bytes=b"two")))
    assert first.id == second.id
    assert second.occurrence_count == 2

def test_harness_failure_is_not_promoted_as_target_vulnerability(pipeline):
    finding = run(pipeline.process(harness_induced_fixture_crash()))
    assert finding.classification == "harness-induced false positive"
    assert finding.classification != "true vulnerability"
```

- [ ] **Step 2: Verify tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_crash_pipeline.py backend/tests/test_findings_api.py -q`

Expected: FAIL with missing crash modules and findings routes.

- [ ] **Step 3: Implement quarantine through deterministic evidence**

Persist original input and provenance, replay multiple times in the original image, minimise while preserving signal/stack, normalise sanitizer/signal/source/coverage fingerprint, group duplicates, and replay through compatible sanitizer and clean variants. Preserve flaky and unresolved inputs.

- [ ] **Step 4: Add bounded harness-correction experiment**

When setup, lifetime, call order, cleanup, or patch misuse is suspected, request one corrected asset version, rebuild only its target layer, and replay the minimal input. The comparison becomes triage evidence; it never silently overwrites the original asset.

- [ ] **Step 5: Invoke crash specialist after deterministic processing**

Accept only the five approved classification texts. Store evidence, uncertainty, short description, project-relative priority rank and rationale, reproducibility, and occurrence count. A true vulnerability is described for investigation without claiming exploitability unless evidence proves it.

- [ ] **Step 6: Add findings APIs and run tests**

Run: `backend/.venv/bin/pytest backend/tests/test_crash_pipeline.py backend/tests/test_findings_api.py backend/tests/test_agent_tracing.py -q`

Expected: PASS; raw crash observation never appears in the findings list before replay completes.

- [ ] **Step 7: Commit**

```bash
git add backend/fuzzing/crashes backend/api backend/tests/test_crash_pipeline.py backend/tests/test_findings_api.py
git commit -m "feat: add evidence-based crash findings"
```

### Task 17: Overview and Source Assurance UI

**Files:**
- Create: `frontend/src/models/campaign.ts`
- Create: `frontend/src/models/coverage.ts`
- Create: `frontend/src/controllers/useProjectOverview.ts`
- Create: `frontend/src/controllers/useSourceAssurance.ts`
- Create: `frontend/src/views/OverviewView.tsx`
- Create: `frontend/src/views/SourceAssuranceView.tsx`
- Create: `frontend/src/components/coverage/CoverageMap.tsx`
- Create: `frontend/src/components/coverage/SourceTree.tsx`
- Create: `frontend/src/components/coverage/SourceCode.tsx`
- Create: `frontend/src/components/coverage/LineEvidence.tsx`
- Modify: `frontend/src/services/apiClient.ts`
- Modify: `frontend/src/App.tsx`
- Create: `frontend/src/Overview.test.tsx`
- Create: `frontend/src/SourceAssurance.test.tsx`

**Interfaces:**
- Consumes: campaigns and coverage APIs from Tasks 12, 14, and 15.
- Produces: data-backed Overview and line-level Source Assurance views.

- [ ] **Step 1: Write truthful visual and line-filter tests**

```tsx
it('shows current focus and evidence before engine metadata', async () => {
  render(<OverviewView model={overviewModel()} />);
  expect(screen.getByRole('heading', { name: 'Current focus' })).toBeVisible();
  expect(screen.getByText('Parser input path')).toBeVisible();
  expect(screen.queryByText('gpt-5.6-luna')).not.toBeInTheDocument();
});

it('filters the selected line by reaching strategy and exposes its first testcase', async () => {
  render(<SourceAssuranceView model={sourceModel()} />);
  await userEvent.click(screen.getByRole('button', { name: 'Line 42' }));
  expect(screen.getByRole('link', { name: 'Replay first testcase for parser strategy' })).toBeVisible();
  expect(screen.getByText('1.5 CPU exposure hours')).toBeVisible();
});
```

- [ ] **Step 2: Verify tests fail**

Run: `cd frontend && npm test -- --run src/Overview.test.tsx src/SourceAssurance.test.tsx`

Expected: FAIL because views and components are missing.

- [ ] **Step 3: Implement focused controllers and API methods**

Controllers cancel or generation-guard stale requests on project/file/line changes. SSE invalidations refetch only affected campaign or coverage resources. Models use `cpu_exposure_seconds` and convert to readable hours only in presentation.

- [ ] **Step 4: Implement the approved command-centre layout**

Overview contains one primary coverage map, a right-side Current Focus explanation, a concise strategies list, genuine finding count, and pause/resume. The map groups real source modules, labels percentages and exposure, uses red only for active gaps, and has a source-list equivalent.

- [ ] **Step 5: Implement source detail and traceability**

Render contained source text with line numbers, coverage state, CPU exposure, and keyboard-selectable lines. The evidence panel filters by strategy and links to the retained first testcase/replay metadata. Use monospace only in source/evidence code.

- [ ] **Step 6: Run tests, accessibility checks, typecheck, and build**

Run: `cd frontend && npm test && npm run typecheck && npm run build`

Expected: PASS; empty APIs render professional empty states, not invented metrics.

- [ ] **Step 7: Commit**

```bash
git add frontend/src
git commit -m "feat: add source assurance workspace"
```

### Task 18: Findings, Activity, and complete local Debug UI

**Files:**
- Create: `frontend/src/models/finding.ts`
- Create: `frontend/src/models/event.ts`
- Create: `frontend/src/controllers/useFindings.ts`
- Create: `frontend/src/controllers/useActivity.ts`
- Modify: `frontend/src/views/FindingsView.tsx`
- Create: `frontend/src/views/ActivityView.tsx`
- Create: `frontend/src/components/findings/FindingList.tsx`
- Create: `frontend/src/components/findings/FindingDetail.tsx`
- Create: `frontend/src/components/activity/ActivityList.tsx`
- Create: `frontend/src/components/activity/DebugLog.tsx`
- Remove: `frontend/src/views/LogsView.tsx`
- Remove: `frontend/src/views/TasksView.tsx`
- Modify: `frontend/src/services/apiClient.ts`
- Modify: `frontend/src/services/eventStream.ts`
- Modify: `frontend/src/App.tsx`
- Create: `frontend/src/Findings.test.tsx`
- Create: `frontend/src/Activity.test.tsx`

**Interfaces:**
- Consumes: findings APIs and activity/debug JSONL queries.
- Produces: genuine Findings plus Activity/Debug tabs; internal tasks shown only in activity details.

- [ ] **Step 1: Write classification, uncertainty, and debug-filter tests**

```tsx
it('renders one grouped finding with reproducibility and uncertainty', () => {
  render(<FindingsView model={findingsModel()} />);
  expect(screen.getAllByRole('article')).toHaveLength(1);
  expect(screen.getByText('3 occurrences')).toBeVisible();
  expect(screen.getByText('Reproduced')).toBeVisible();
  expect(screen.getByText(/uncertainty/i)).toBeVisible();
});

it('shows structured motivation but never promises chain of thought', () => {
  render(<ActivityView model={activityModel()} />);
  expect(screen.getByText('Why BigEye changed this strategy')).toBeVisible();
  expect(screen.queryByText(/chain.of.thought/i)).not.toBeInTheDocument();
});
```

- [ ] **Step 2: Verify tests fail**

Run: `cd frontend && npm test -- --run src/Findings.test.tsx src/Activity.test.tsx`

Expected: FAIL because real findings/activity views are absent.

- [ ] **Step 3: Implement genuine grouped findings**

Order by project-relative priority rank. Show classification, short description, priority rationale, reproducibility, occurrence count, sanitizer/engine only in details, minimal reproducer download, evidence, and uncertainty. Empty state says no replayed findings yet.

- [ ] **Step 4: Implement readable Activity and expandable Debug**

Activity rows show decision, motivation, change, evidence links, and next review. Debug filters locally paged records by agent/API/tool/build/fuzzer/coverage/error and displays trace hierarchy, sanitized request/response items, tool calls, usage, commands, stdout/stderr, citations, and diffs. Raw JSON is behind a disclosure.

- [ ] **Step 5: Remove Tasks and standalone Logs navigation**

Internal tasks appear inside Activity detail. Preserve task history through API compatibility only until Task 19 removes obsolete frontend methods. Activity and Debug share one primary navigation item with accessible Radix tabs.

- [ ] **Step 6: Run frontend verification and commit**

Run: `cd frontend && npm test && npm run typecheck && npm run build`

Expected: PASS with no obsolete “Crash processing is not implemented” copy.

```bash
git add frontend/src
git commit -m "feat: add findings and campaign activity"
```

### Task 19: Recovery, self-cleaning, release scripts, fixtures, and end-to-end acceptance

**Files:**
- Create: `backend/fuzzing/campaigns/recovery.py`
- Create: `backend/fuzzing/campaigns/cleanup.py`
- Modify: `backend/services/campaigns/coordinator_registry.py`
- Modify: `backend/api/app.py`
- Create: `backend/run.py`
- Create: `backend/tests/fixtures/system_project/CMakeLists.txt`
- Create: `backend/tests/fixtures/system_project/src/main.c`
- Create: `backend/tests/fixtures/system_project/seeds/plain.txt`
- Create: `backend/tests/fixtures/component_project/CMakeLists.txt`
- Create: `backend/tests/fixtures/component_project/include/parser.h`
- Create: `backend/tests/fixtures/component_project/src/parser.c`
- Create: `backend/tests/test_real_campaigns.py`
- Create: `backend/tests/test_recovery_cleanup.py`
- Create: `scripts/setup.sh`
- Create: `scripts/start.sh`
- Create: `scripts/check.sh`
- Create: `playwright.config.ts`
- Create: `tests/e2e/bigeye.spec.ts`
- Modify: `frontend/package.json`
- Modify: `frontend/package-lock.json`
- Modify: `README.md`
- Create: `.github/workflows/ci.yml`
- Modify: `backend/requirements.txt` only if installation changes it

**Interfaces:**
- Consumes: every prior task.
- Produces: recoverable continuous release, first-party real fixtures, one-command start/check, production static frontend, macOS/Linux acceptance evidence.

- [ ] **Step 1: Write restart and cleanup tests**

```python
def test_recovery_adopts_matching_running_container(recovery):
    result = run(recovery.recover(project_id=7, containers=[matching_container()]))
    assert result.adopted_campaign_ids == (3,)
    assert result.restarted_campaign_ids == ()

def test_cleanup_preserves_assets_corpus_findings_and_evidence(cleaner, project_workspace):
    run(cleaner.clean(project_id=7))
    for name in ("assets", "campaigns/3/corpus", "findings", "logs"):
        assert (project_workspace / name).exists()
```

- [ ] **Step 2: Verify recovery tests fail**

Run: `backend/.venv/bin/pytest backend/tests/test_recovery_cleanup.py -q`

Expected: FAIL with missing recovery and cleanup modules.

- [ ] **Step 3: Implement reconciliation and recoverable cleanup**

Match containers by BigEye labels, exact commit, campaign ID, image ID, and asset hashes. Adopt valid running containers, restart stopped healthy campaigns from durable corpora, quarantine mismatches, and preserve pending agent decisions. Remove only labelled stopped containers, verified temporary contexts, unreferenced BigEye image layers after the grace rule, redundant raw corpus entries, and duplicate crash copies whose provenance is persisted.

- [ ] **Step 4: Add first-party system and component fixtures**

Write original minimal C fixture code. The system fixture accepts stdin/file input and two documented configurations, with one deterministic target bug and duplicated crashing inputs. The component fixture exposes a parser contract plus a deliberately incorrect harness variant used to prove harness-induced triage. Do not copy source, Dockerfiles, harnesses, or corpora from another fuzzing project.

- [ ] **Step 5: Add real Docker campaign acceptance tests**

Mark heavy tests `pytest.mark.docker`. Prove a real AFL++ system campaign and libFuzzer component campaign run concurrently, clean coverage replays, corpus minimisation preserves coverage, duplicates collapse, harness-induced failure is distinguished, pause/resume works, and restart adopts or restarts campaigns. Skip only when Docker is unavailable and report the skip reason.

- [ ] **Step 6: Add release scripts without system package installation**

`scripts/setup.sh` verifies Python 3.14, Node, npm, Git, Docker, Compose, and `linux/amd64`; creates `backend/.venv`; installs `backend/requirements.txt`; verifies its `pip freeze` is identical without rewriting it; runs `npm ci`; starts PostgreSQL; and checks health. `scripts/start.sh` exports `.env`, builds the frontend, starts PostgreSQL, and runs `backend.run` on loopback. `scripts/check.sh` runs backend tests, frontend tests/typecheck/build, Docker contract tests, and optional real Docker tests.

- [ ] **Step 7: Serve the production frontend from FastAPI**

Mount `frontend/dist/assets` and return `frontend/dist/index.html` for non-API paths only after verifying the build exists. Keep Vite proxy development working. `backend.run` opens the loopback URL once and starts Uvicorn without reload.

- [ ] **Step 8: Install and write Playwright acceptance**

Run: `cd frontend && npm install --save-dev --save-exact @playwright/test @axe-core/playwright`

Create an end-to-end test that creates a fixture project, reaches Overview, observes a real running strategy and activity decision, opens a covered source line and first testcase, observes one grouped finding, inspects sanitized debug events, pauses, restarts the backend, resumes, and verifies state persists.

- [ ] **Step 9: Refresh frozen dependencies exactly**

Run: `backend/.venv/bin/python -m pip freeze > backend/requirements.txt`

Run: `diff -u backend/requirements.txt <(backend/.venv/bin/python -m pip freeze)`

Expected: no diff.

- [ ] **Step 10: Run the full release gate**

Run: `backend/database/reset.sh && scripts/check.sh`

Run: `cd frontend && npx playwright test`

Expected: all backend, frontend, accessibility, Docker, real campaign, and browser tests PASS; no background process, unlabelled container, or temporary context remains.

- [ ] **Step 11: Verify both supported host paths**

Run the setup/start/smoke sequence locally on macOS Docker Desktop. Add `.github/workflows/ci.yml` with an `ubuntu-24.04` job that installs Python 3.14 and Node, starts Docker/PostgreSQL, runs `scripts/check.sh`, and executes the same fixture journey on Docker Engine. Record the local command output and CI job URL plus image/container architectures in `docs/release-verification.md`. Do not mark the release complete until both show `linux/amd64` and the same acceptance journey passes.

- [ ] **Step 12: Update release documentation**

Document prerequisites, `.env` setup, public/private repository intake, exact revision behaviour, project worker count, pause/resume, coverage meaning, CPU exposure meaning, finding classifications, local logs, security boundary, workspace retention, cleanup, recovery, and troubleshooting. Remove the old claim that BigEye only publishes repository analysis.

- [ ] **Step 13: Commit**

```bash
git add backend frontend scripts tests playwright.config.ts .github/workflows/ci.yml README.md docs/release-verification.md
git commit -m "feat: complete autonomous BigEye release"
```

## Final verification and review

- [ ] Run `git status --short` and confirm only intentional ignored runtime state remains.
- [ ] Run `backend/database/reset.sh && scripts/check.sh` from a clean database.
- [ ] Run `cd frontend && npx playwright test`.
- [ ] Run the opt-in real OpenAI manager-to-specialist smoke with the user's configured key.
- [ ] Run a whole-branch review against `docs/superpowers/specs/2026-07-19-bigeye-autonomous-fuzzing-design.md`.
- [ ] Fix every important review finding and re-run the affected task tests plus the full release gate.
- [ ] Use `superpowers:verification-before-completion` before claiming the product is complete.
- [ ] Use `superpowers:finishing-a-development-branch` only after every release acceptance criterion has evidence.
