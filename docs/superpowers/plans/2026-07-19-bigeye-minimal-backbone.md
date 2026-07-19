# BigEye Minimal Backbone Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development`, with a fresh implementer and reviewer for every task.

**Goal:** Deliver a runnable vertical slice in which a user submits a repository, BigEye persists the project, clones it, prepares a reusable LLVM toolchain image, runs a Terra manager with a repository-analysis worker, and shows genuine tasks and logs.

**Architecture:** React follows frontend MVC; FastAPI follows backend MVC with SQL repositories and business services; PostgreSQL stores only structured state; naturally file-shaped artifacts stay in a contained workspace; OpenAI Agents SDK provides bounded repository analysis; Docker SDK manages the maintained LLVM image and containers.

**Tech stack:** Python 3.14, FastAPI, Uvicorn, asyncpg, OpenAI Agents SDK, Docker SDK for Python, PostgreSQL 18.4, React, TypeScript, Vite, Docker Desktop, LLVM/Clang 18 and libFuzzer.

## Global constraints

- Do not use OSS-Fuzz or OSS-Fuzz-Gen images, code, helpers, formats, or workflows.
- Force `linux/amd64` for every database, image-build, and container-run operation.
- Run only PostgreSQL through Compose. Run FastAPI from `backend/.venv`.
- Manage Python dependencies only with `pip`; after every change run `python -m pip freeze > backend/requirements.txt`.
- Keep one `schema.sql`; do not add migration tooling before the initial release.
- Keep data models minimal. Do not invent fields, enums, statuses, metadata, settings, agent-run, event, or findings tables.
- Keep HTTP controllers thin, views as response schemas, repositories SQL-only, and business behavior in services.
- Do not give agents a host shell, raw Docker client, or unrestricted paths.
- Do not add fake findings, sample metrics, mock runtime records, a chatbot, or project deletion.
- Build capabilities as deterministic code when an agent is unnecessary.
- Support multiple projects concurrently. The user chooses repositories; BigEye does not select projects.
- Keep `workspace/`, `backend/.venv/`, build output, caches, and SDD ledgers out of Git.

## Required structure

```text
compose.yaml
.env.example
.gitignore

frontend/src/
├── models/
├── controllers/
├── views/
│   ├── ProjectsView.tsx
│   ├── TasksView.tsx
│   ├── FindingsView.tsx
│   ├── LogsView.tsx
│   └── SettingsView.tsx
├── components/
└── services/
    ├── apiClient.ts
    └── eventStream.ts

backend/
├── .venv/
├── requirements.txt
├── api/
│   ├── app.py
│   ├── dependencies.py
│   ├── controllers/
│   └── views/
├── models/
│   ├── project.py
│   └── task.py
├── database/
│   ├── connection.py
│   ├── schema.sql
│   └── reset.sh
├── repositories/
│   ├── project_repository.py
│   └── task_repository.py
├── services/
│   ├── create_project.py
│   ├── clone_repository.py
│   ├── run_project_backbone.py
│   └── stream_task_output.py
├── agents/
│   ├── context.py
│   ├── manager.py
│   ├── repository_analysis.py
│   ├── workflow.py
│   ├── prompts/
│   │   ├── manager.py
│   │   └── repository_analysis.py
│   └── tools/
│       ├── code_navigation.py
│       └── agent_dispatch.py
└── fuzzing/
    ├── images/
    │   └── Dockerfile
    ├── docker/
    │   ├── client.py
    │   ├── image_builder.py
    │   ├── image_inspector.py
    │   └── container_runner.py
    └── toolchain/
        ├── builder.py
        ├── verifier.py
        └── service.py
```

## Minimal database

PostgreSQL stores only:

```text
projects
- id
- repository_url
- worker_count
- commit_sha
- created_at
- finished_at
- error

tasks
- id
- project_id
- name
- created_at
- finished_at
- error
```

Task log paths derive from project and task IDs. Large artifacts live under:

```text
workspace/projects/<project-id>/repository/
workspace/projects/<project-id>/analysis/repository.md
workspace/projects/<project-id>/logs/<task-id>.log
```

`compose.yaml` contains PostgreSQL only, using `postgres:18.4-bookworm`, `platform: linux/amd64`, `PGDATA=/var/lib/postgresql/18/docker`, a health check, and data bound to `./workspace/postgres:/var/lib/postgresql`. Because the backend runs on the host, publish PostgreSQL on loopback only, never on a LAN interface.

## User journey

1. Open Projects.
2. Enter a repository URL and fuzzer-worker count.
3. Create the project and open Tasks.
4. Cloning and toolchain preparation start concurrently.
5. Repository analysis starts after cloning.
6. Tasks and raw logs update live.
7. The user may switch among concurrently running projects.
8. Findings stays truthfully empty until crash processing exists.
9. Settings reports actual database, Docker, OpenAI-key presence, and toolchain checks without exposing secrets.

## Agent flow

```text
Project service
  -> Terra manager
      -> repository-analysis worker exposed with Agent.as_tool()
          -> bounded code-navigation function tools
  -> deterministic evidence validation
  -> repository.md
```

- Manager model: `gpt-5.6-terra`.
- First repository-analysis attempt: `gpt-5.6-luna`.
- Retry the worker with Terra once, and only when deterministic source-citation validation fails.
- Tools list contained files, read a bounded source range, search contained source text, and inspect the resolved commit/basic Git metadata.
- Model-supplied paths are relative. Reject traversal, `.git`, escaping symlinks, unbounded reads, a host shell, and direct Docker access.
- Keep each prompt template in its own `.py` file.

## Docker SDK separation

- `client.py`: create and health-check the Docker SDK client.
- `image_builder.py`: stream build output through the low-level Engine build API.
- `image_inspector.py`: return image ID, OS, and architecture.
- `container_runner.py`: run bounded containers and stream output.
- `toolchain/builder.py`: calculate the maintained tag and request its build.
- `toolchain/verifier.py`: verify LLVM, Clang, libFuzzer, ASan, UBSan, and `linux/amd64`.
- `toolchain/service.py`: coordinate project tasks and reuse the image.
- Do not create a generic `docker.py` or `docker_utils.py`.
- Docker MCP is deferred until a concrete MCP server is required.

## API surface

- `POST /api/projects`
- `GET /api/projects`
- `GET /api/projects/{project_id}`
- `GET /api/projects/{project_id}/tasks`
- `GET /api/projects/{project_id}/analysis`
- `GET /api/tasks/{task_id}/log?after=<byte_offset>`
- `GET /api/projects/{project_id}/events`
- `GET /api/settings`

Project creation accepts only `repository_url` and `worker_count`, persists the project and initial tasks, and returns HTTP 202. Server-sent events report genuine task state and file-backed log growth.

### Task 1: Local development and PostgreSQL

**Files:** root development files plus `backend/database/` and focused tests.

- Add `.env.example`, `compose.yaml`, database connection, `schema.sql`, and a reset script.
- Create `backend/.venv` with Python 3.14.
- Install the initial backend dependencies with pip and freeze `backend/requirements.txt`.
- Test configuration, schema shape, foreign keys, and reset scoping.
- Verify PostgreSQL initialization and health when Docker is available.
- Commit: `build: add BigEye development foundation`.

### Task 2: Frontend MVC journey

**Files:** `frontend/` with models, controllers, views, components, services, and focused tests.

- Implement Projects, Tasks, Findings, Logs, and Settings.
- Add repository intake and concurrent-project selection.
- Keep network access in services, state/user actions in controllers, and rendering in views.
- Use no production fixtures or sample records.
- Test view/controller separation, core user interactions, and the production build.
- Commit: `feat: add BigEye frontend journey`.

### Task 3: Backend MVC and project state

**Files:** `backend/models/`, `backend/repositories/`, `backend/services/`, `backend/api/`, and focused tests.

- Add minimal project/task models and PostgreSQL repositories.
- Add Pydantic request/response views and thin HTTP controllers.
- Separate project creation, task creation, contained repository cloning, and log streaming into services.
- Support concurrent projects and resuming unfinished backbone runs.
- Implement the specified API surface without fake data.
- Test SQL repositories, service boundaries, controller boundaries, URL validation, and path containment.
- Commit: `feat: add project backend`.

### Task 4: Agent tools and collaboration

**Files:** `backend/agents/` and focused tests.

- Add an application-owned agent context.
- Add bounded code-navigation and agent-dispatch tools.
- Add separate manager and repository-analysis prompt templates.
- Implement the Terra manager, Luna worker, deterministic citation validation, and one Terra worker retry.
- Write citation-valid `repository.md` only after deterministic validation succeeds.
- Test tool permissions, traversal and symlink rejection, `.git` rejection, bounded reads, dispatch, validation, and retry behavior without requiring a live API call.
- Commit: `feat: add agent capabilities`.

### Task 5: Docker SDK infrastructure

**Files:** `backend/fuzzing/`, `backend/requirements.txt`, and focused tests.

- Install the Docker SDK with pip and refresh the frozen requirements.
- Add the Docker client facade, image builder, inspector, and container runner.
- Add the maintained LLVM image, toolchain builder, verifier, and service.
- Base the maintained image on Ubuntu 24.04 and install LLVM/Clang 18, lld, libFuzzer runtime, ASan/UBSan, CMake, Ninja, Make, and Git without OSS-Fuzz code.
- Force `linux/amd64` for SDK builds and runs.
- Reuse an already verified toolchain image instead of rebuilding it.
- Test SDK parameters, build-log streaming, inspection, image reuse, resource limits, and platform verification.
- Commit: `feat: add Docker SDK infrastructure`.

### Task 6: Vertical-slice integration

**Files:** orchestration services, API/SSE wiring, frontend integration, startup scripts/documentation, and end-to-end tests.

- Connect project submission to clone and toolchain tasks.
- Run cloning and toolchain preparation concurrently.
- Start repository analysis only after cloning completes.
- Connect PostgreSQL task changes and file-backed logs to SSE.
- Recover unfinished backbone runs after backend restart.
- Wire every frontend view to genuine API data.
- Document exact database, backend, frontend, and verification commands.
- Submit a user-selected repository and verify persistence, concurrent projects, resolved commit, SDK operations, reusable image, manager-to-worker call when a key is configured, citation-valid analysis, genuine tasks/logs, and restart recovery.
- Commit: `feat: complete BigEye backbone`.

## Acceptance

The backbone is accepted when PostgreSQL alone runs through Compose; FastAPI runs from `backend/.venv` on Python 3.14; `backend/requirements.txt` matches `pip freeze`; Docker operations use the Python SDK and `linux/amd64`; agents have explicit code-navigation and dispatch tools; the frontend contains the five genuine views; and the complete repository-to-analysis journey works without mock runtime data when the user supplies an OpenAI API key.

## Deferred

- Docker MCP integration until a concrete MCP server is required.
- Generated project-dependency, project-build, and harness-build image layers.
- Write-capable and contained execution agent tools.
- Harness generation, fuzzing, coverage, crash replay, crash triage, and reporting.
- Embedded editor until editable generated files exist.
