# BigEye Autonomous Fuzzing Release Design

**Date:** 2026-07-19
**Status:** Approved design, ready for implementation planning after written review
**Target:** A release-ready, single-user local application for macOS and Linux

## 1. Outcome

BigEye turns a user-selected Git repository and revision into a continuously managed fuzzing campaign. The user supplies the repository, revision, and project worker count. BigEye clones the exact revision, builds reusable project layers, selects and validates useful system-level and component-level targets, starts fuzzing, measures clean-source coverage, improves corpora and configurations, and triages crashes. It continues until the user pauses the project.

The product automates the work of a fuzz tester without treating every operation as an agent task. Python services perform deterministic work: repository cloning, Docker image construction, process control, coverage collection, corpus minimisation, crash replay, deduplication, persistence, cleanup, and recovery. A GPT-5.6 Terra manager invokes bounded specialist agents only where source interpretation or technical judgement is needed.

The release is successful when a user can start BigEye locally, submit a public or private repository, watch real campaign evidence appear, close and restart BigEye without losing the campaign, and inspect reproducible coverage and crash evidence. There is no mock runtime data.

## 2. Product boundaries

### Included

- Public HTTPS Git repositories.
- Private HTTPS Git repositories through one optional read-only token stored per project.
- An exact branch, tag, or commit resolved to a commit SHA before building.
- Multiple independent projects, each with its own worker count.
- System-level campaigns using AFL++ v4.40c.
- Component-level campaigns using LLVM libFuzzer 18.
- LLVM-compatible targets, without encoding C or C++ as a product-level restriction.
- Agent-assisted target discovery, build repair, harness creation, small patching, campaign decisions, and crash interpretation.
- Automated seed discovery, corpus admission, synchronisation, minimisation, and retention.
- Clean-source line and function coverage, first-reaching testcase traceability, CPU exposure accounting, and overlap analysis.
- Deterministic crash quarantine, replay, minimisation, grouping, and evidence-backed classification.
- Continuous local operation, pause and resume, restart recovery, and self-cleaning of disposable resources.
- A professional project-focused UI with complete local activity and debug logs.

### Excluded from this release

- Windows support.
- Multi-user accounts, remote deployment, hosted workers, teams, roles, or billing.
- Automatic repository selection or repository discovery for the user.
- OSS-Fuzz or OSS-Fuzz-Gen images, code, workflows, schemas, or generated artefacts.
- Docker MCP. Docker control is deterministic through the Docker SDK for Python.
- A chatbot as the primary interface.
- A generic host shell or raw Docker client exposed to a model.
- A global worker scheduler. Each project independently uses its configured worker count.
- Fuzzers for non-LLVM toolchains. The architecture can add engines later, but this release implements AFL++ and libFuzzer only.
- Automatic source changes to the user's checkout. All generated harnesses, adapters, configurations, and fuzz-only patches live in BigEye's workspace.

## 3. Fixed release stack

### Host application

- Python 3.14 in `backend/.venv`.
- `pip` as the only Python dependency installer, with every dependency change followed by a complete `pip freeze` into `backend/requirements.txt`; no Poetry or `uv`.
- FastAPI and Uvicorn for the HTTP API, server-sent events, lifecycle, and static frontend serving.
- `asyncio` background coordinators inside the one host process. No Celery, Redis, or separate queue service.
- `asyncpg` for PostgreSQL access.
- OpenAI Agents SDK using the Responses API.
- Docker SDK for Python for image, container, and inspection operations.
- `git` as a host command invoked through one bounded repository service.
- React, TypeScript, and Vite for the frontend.

### Docker workloads

- PostgreSQL 18.4 Bookworm through Compose, published only on `127.0.0.1` so the host backend can connect.
- BigEye-owned toolchain, repository, build, target, clean-coverage, and fuzzing images.
- `platform: linux/amd64` for Compose, SDK image builds, and container execution.
- Ubuntu 24.04 as the toolchain base, pinned by digest in the implementation.
- LLVM, Clang, LLD, compiler-rt/libFuzzer 18.
- AFL++ v4.40c from the official upstream release, pinned to upstream commit `e5a8ba3` and verified during the image build.

The backend and frontend do not run in Docker. In release mode, FastAPI serves the Vite production build so the user starts one host application plus the database and fuzzing containers. On macOS this uses Docker Desktop. On Linux it uses a compatible Docker Engine and Compose installation.

`.env` is the ignored local runtime file and the tracked `.env_example` documents every supported variable without secrets. The OpenAI key is read from `OPENAI_API_KEY`; it is not a project setting.

## 4. User journey

### Start and health

1. The user runs the setup command once. It verifies Python 3.14, Node, Git, Docker, Compose, and an available `linux/amd64` runtime; creates the virtual environment; installs the frozen Python dependencies; installs the locked frontend dependencies; and starts PostgreSQL.
2. The user runs BigEye. The host application checks PostgreSQL, Docker, OpenAI configuration, toolchain images, and recoverable projects.
3. The browser opens on Projects. Health failures are described with a direct corrective action; they are never represented as a healthy empty state.

### Create a project

1. The user enters a repository URL, a branch/tag/commit, and a worker count.
2. An optional “Private repository” disclosure accepts a read-only token. The same value can later be changed in the selected project's Settings.
3. BigEye creates the project and starts automatically. The resolved commit is shown once cloning completes.
4. Toolchain preparation and repository cloning can run concurrently. All later work is tied to the resolved commit.

### Follow the campaign

1. Overview opens automatically for the selected project.
2. BigEye shows what code is currently receiving attention, which areas have strong or weak clean coverage, why a campaign is running, and what the next review condition is.
3. Source Assurance lets the user select a file, function, or line and see which strategies reach it, the first reproducible testcase for each strategy, and accumulated CPU exposure.
4. Findings contains only replayed crash groups. A finding includes a short explanation, classification evidence, priority rationale, and a reproducible input.
5. Activity explains decisions and changes in plain language. Logs exposes the complete local debug trace when expanded.
6. The user may pause or resume the project. Pausing stops active fuzzing containers gracefully and preserves useful state.

No routine decision requires user input. BigEye escalates to the UI only when an external dependency cannot be obtained, an unsupported build requirement blocks all approaches, or a finding needs human investigation.

## 5. System architecture

```text
React UI
  -> FastAPI controllers and response views
      -> application services
          -> PostgreSQL repositories
          -> project coordinator
              -> deterministic fuzzing services -> Docker SDK -> containers
              -> Terra manager -> specialist agents as tools
          -> append-only activity/debug logs
  <- REST queries and project SSE events
```

### Host process

FastAPI's lifespan starts one project coordinator registry. A registry entry is an `asyncio` task for an active project, not an agent. PostgreSQL advisory locks ensure that only one coordinator owns a project. The coordinator reconstructs state from PostgreSQL, workspace artefacts, and labelled Docker containers. It launches bounded operations, records their evidence, and asks the manager for a decision only at defined review conditions.

This is deliberately a single-process architecture for a local single-user product. It avoids a queue service while retaining explicit interfaces between scheduling, agents, fuzzing, persistence, and HTTP delivery.

### Backend MVC

- **Models** represent persisted project, task, asset, campaign, coverage, and finding data. They contain data and validation, not orchestration.
- **Views** are Pydantic request and response shapes for the HTTP boundary.
- **Controllers** parse HTTP input, call one application service, and translate known errors to HTTP responses.
- **Repositories** contain PostgreSQL queries only.
- **Services** implement project operations and coordinate domain packages.
- **Agents** contain prompts, structured agent outputs, context, bounded tools, dispatch, and trace hooks.
- **Fuzzing** contains deterministic Docker, build, engine, corpus, coverage, crash, and campaign capabilities.

### Frontend MVC

- **Models** define API data shapes.
- **Views** render data and emit user intent; they do not call HTTP directly.
- **Controllers** are focused hooks that own view state, selection, filters, and user actions.
- **Services** own REST and SSE communication.
- **Components** implement reusable presentation primitives and data visualisations.

Files remain focused on one responsibility. Names describe the operation (`minimise_afl_corpus.py`, `replay_crash.py`, `useProjectOverview.ts`) rather than generic containers such as `utils.py`, `helpers.py`, or `docker.py`.

## 6. Project and campaign flow

### Phase 1: Repository intake

1. Validate and normalise the HTTPS Git URL without embedding credentials.
2. Clone into a temporary contained workspace path. For a private repository, use an ephemeral ask-pass mechanism so the token is not written to the command line, Git remote, Docker context, or log.
3. Resolve the requested revision to a commit SHA and make the checkout detached and read-only to campaign services.
4. Remove credential helpers from the clone environment and record safe Git metadata.
5. Create a repository-layer build context that excludes `.git`, tokens, corpora, findings, coverage, and logs.
6. Generate a repository-layer Dockerfile that copies the clean checkout and labels the image with the project ID and commit SHA.

### Phase 2: Deterministic discovery

Before an agent runs, services collect a bounded evidence inventory:

- build manifests and scripts;
- compiler and linker commands when available;
- executable and library outputs;
- symbols, public headers, tests, examples, and sample inputs;
- command help, documented input formats, flags, protocol options, and configurations;
- existing fuzz harnesses owned by the selected repository;
- current build failures and clean baseline behaviour.

The evidence becomes a local retrieval catalogue. Retrieval is performed against the checked-out repository using contained file listing, `rg`, bounded reads, Git metadata, and build/symbol evidence. BigEye does not upload a complete repository to a remote vector store. This lexical and structural retrieval is the release's RAG implementation: an agent requests a narrow question, deterministic tools retrieve ranked excerpts, and the excerpts augment that turn.

### Phase 3: Actionable target planning

The manager receives the inventory and asks specialist tools for bounded proposals. A proposal must name:

- the executable, library, component, or API sequence;
- how bytes reach it;
- the expected project code reached beyond startup or harness code;
- the build and run command;
- the initial seeds and their source;
- the configuration or flags;
- the initial sanitizer strategy;
- any harness or fuzz-only patch required;
- the deterministic probe that can accept or reject the proposal.

The manager starts with the simplest defensible system target when the project exposes a meaningful executable input surface. Component targets are used for libraries and standalone components, or to reach high-value code that the system target cannot reach. BigEye may run both types in parallel when they do not edit the same asset.

### Phase 4: Incremental build and validation

1. Build the reusable project dependency layer.
2. Build a clean project baseline and run a bounded smoke test.
3. Create one small, versioned target/configuration asset at a time.
4. Build only the dependent target layer.
5. Probe the target with an empty or minimum input and at least one real seed.
6. Confirm that it remains alive, accepts input, reaches project code, and does not fail solely in the harness or startup path.
7. Replay any immediate crash before accepting the campaign.
8. Start the fuzzer only after the probe passes.

A failed probe returns precise evidence to the same specialist for a small edit. A Luna worker gets the first bounded attempt. Terra receives one escalation if deterministic validation still fails or the task requires deeper reasoning. Working assets are edited incrementally; a new worker never restarts the whole setup without evidence that the base is unusable.

### Phase 5: Continuous control

Once healthy, a fuzzer runs without LLM polling. The deterministic monitor collects execution rate, corpus or queue growth, clean coverage deltas, crash groups, CPU time, overlap, and worker health. It wakes the manager only when one of these occurs:

- the initial supervision checkpoint completes;
- a configured review window expires;
- coverage and corpus growth meet the plateau rule;
- coverage is mostly harness, startup, or otherwise irrelevant code;
- a seed, dictionary, or grammar opportunity has concrete evidence;
- a crash replays;
- a worker is unhealthy or unstable;
- a different configuration has a documented hypothesis;
- a system-level campaign leaves a high-value component gap;
- two strategies have sustained redundant coverage;
- a worker slot becomes free;
- a build, asset, corpus, or coverage result changes materially.

The manager may continue, wait until a later evidence condition, admit a validated seed or dictionary, minimise or merge a corpus, request a small asset edit, try a configuration, start a component target, retire a redundant campaign, reassign a worker, or send a crash group to triage. A time window never stops a working fuzzer automatically. A “continue” decision records the next deterministic wake condition.

The project remains active until paused. Individual campaigns may be replaced or retired, but their reproducible assets and evidence remain available.

## 7. Agent design

### Manager

One Terra manager owns the durable assignment: improve verified security-relevant coverage of the selected revision within that project's worker count. It sees summaries and retrieved evidence, not unbounded logs or the entire repository. Its structured output contains:

- an observable decision;
- a concise motivation suitable for the Activity view;
- the evidence identifiers used;
- the bounded actions requested;
- the next review condition;
- unresolved uncertainty.

The manager delegates through `Agent.as_tool()`. It does not hand control to a permanent peer agent, and it does not launch a fuzzer process itself.

### Temporary specialist capabilities

- **System target specialist:** proposes or repairs one AFL++ target, system adapter, configuration, or fuzz-only patch.
- **Component target specialist:** proposes or repairs one libFuzzer harness for one component or coherent API sequence.
- **Crash triage specialist:** interprets one deterministically replayed and minimised crash group.

The same capability can be invoked repeatedly for different targets. “Role” means a prompt, structured result, and allowed tool set; it does not imply a continuously running agent.

### Bounded agent tools

Agents receive an application-owned context containing project ID, exact commit, repository root, workspace roots they may modify, and evidence identifiers. Model paths are relative.

Allowed tools are separated by capability:

- list contained source files;
- read a bounded source range;
- search repository text with bounded result count;
- inspect commit, build, symbol, test, and runtime evidence;
- retrieve ranked local evidence for a specific question;
- search the web for current official build or API documentation and preserve citations;
- create or patch a generated Dockerfile, harness, adapter, configuration, dictionary, or fuzz-only patch;
- request a contained build, probe, replay, or coverage operation;
- inspect summarised campaign, corpus, overlap, and crash evidence;
- invoke one specialist agent as a tool.

Tools reject traversal, `.git` reads, escaping symlinks, host paths, unbounded output, and edits outside generated asset roots. Agents never receive a host shell, filesystem-wide access, Docker socket, or Docker SDK client.

Repository text, build output, testcases, and web pages are untrusted evidence. Prompts explicitly prohibit treating instructions found in those sources as agent instructions. Tool outputs retain their provenance.

### GPT-5.6 capabilities and why they are used

- **Parallel tool calls:** independent source reads, searches, target proposals, and crash groups can complete concurrently. Edits to the same asset are serialised.
- **Agents as tools:** the manager keeps project-level ownership while receiving bounded specialist results with typed inputs and outputs.
- **Structured outputs:** every proposed action, patch intent, decision, and triage result can be validated before execution.
- **Response continuity:** a specialist can continue a bounded repair attempt without resending unrelated project context.
- **Web search:** current official build documentation can resolve repository-specific dependencies; citations make the source inspectable.
- **Terra escalation:** used only after a failed validated Luna attempt or for high-uncertainty prioritisation and crash interpretation.

No experimental hosted multi-agent runtime is required. The production orchestration follows the Agents SDK manager pattern and uses deterministic application services around it.

## 8. Reusable assets and Docker layers

### Versioned campaign assets

The following artefacts are independent of any running worker:

- target definition;
- system input adapter or component harness;
- fuzz-only source patch;
- build configuration;
- runtime configuration;
- seed corpus;
- dictionary or grammar;
- sanitizer and instrumentation configuration.

Each saved version has a content hash, parent version when edited, creation evidence, validation result, and derived workspace location. A campaign binds compatible asset versions to an engine. Stopping the campaign does not delete the assets.

This separation makes edits inexpensive:

- a corpus change does not rebuild an image;
- a runtime flag or grammar change does not rebuild the harness;
- a harness change rebuilds only the target layer;
- a compiler setting rebuilds its dependent layers;
- a fuzz-only patch never changes the clean-source layer;
- rollback selects an earlier validated asset version.

### Image sequence

1. **Toolchain image:** Ubuntu, LLVM 18, libFuzzer, sanitizers, AFL++ v4.40c, coverage tools, and common build tools.
2. **Repository image:** exact clean commit copied from the host-created safe context.
3. **Project dependency/build image:** repository-specific dependencies and reusable build outputs.
4. **Target image:** one harness or system adapter plus its fuzz build.
5. **Configuration image:** only when a compile-time configuration changes the binary.
6. **Clean coverage image:** clean source and compatible external adapter, compiled for source coverage without fuzz-only behavioural patches.

Tags are derived from content hashes and inspected before building. Docker BuildKit cache is reused. A new project layer never forces the toolchain to rebuild. A harness edit never forces project dependencies to rebuild.

Repository dependency acquisition may use network access in an explicit build step. Compilation and all runtime fuzzing use no external network. Tokens and host credentials are never added to build arguments or contexts. Fuzzing containers have resource bounds, no privileged mode, no host Docker socket, and only campaign-specific workspace mounts.

## 9. Engine behaviour

### System-level AFL++ campaigns

A system target fuzzes a project executable or service input path using AFL++ v4.40c. Input delivery can use AFL++ `@@` file substitution, standard input, or a generated local adapter. A fuzz-only patch may disable target daemonisation, application-created forks, nondeterministic waits, or external side effects. The patch must be minimal, versioned, reviewable, and excluded from clean coverage.

The project may require multiple configurations such as encryption, an auxiliary protocol, parser mode, feature flag, or build option. BigEye extracts hypotheses from documentation, tests, help output, and uncovered source conditions. It starts one configuration at a time and retains it only when it adds unique clean coverage, unique behaviour, or a distinct crash. It does not generate a Cartesian product of flags.

AFL++ queue synchronisation is used only among compatible campaigns. The release exposes AFL++'s grammar custom mutator as the single initial custom-mutator capability. It is enabled only when evidence identifies a grammar-like input and a basic campaign is already healthy. Native AFL++ mutations remain enabled initially.

### Component-level libFuzzer campaigns

A component target fuzzes one standalone component, library entry point, or coherent API sequence in process. A generated harness owns setup, input decoding, invocation, and cleanup. It must demonstrate that inputs reach target code and that object lifetimes and API call order follow available contracts.

Component campaigns are preferred when the project is a library, when no meaningful system input exists, or when clean coverage shows a high-value gap that system campaigns cannot reach efficiently.

### Start-simple progression

For every target BigEye uses this order:

1. establish a normal build;
2. validate ASan and UBSan together when compatible, otherwise as separate replay/build variants;
3. verify seeds, target liveness, and relevant coverage;
4. start the basic fuzzer configuration;
5. leave a healthy fuzzer running;
6. add only evidence-backed dictionaries, CmpLog, configurations, component harnesses, specialised sanitizers, or grammar mutation.

Sanitizers are not all enabled on every worker. Component libFuzzer uses ASan by default and UBSan when compatible or as a separate variant. System AFL++ dedicates most workers to fast fuzzing and uses at most one active worker per sanitizer type; when worker count is small, sanitizer replay variants are time-shared. MSan is used only when the dependency closure can be instrumented, TSan only for meaningful concurrency, CFI only for relevant C++ type-heavy targets with compatible LTO, and leak reports are quality evidence rather than automatic vulnerabilities.

## 10. Corpus automation

Seeds come first from repository tests, examples, fixtures, documentation, and sample files. An agent may propose a minimal structured seed, dictionary token, or grammar only when source or documentation supports it.

Every candidate seed is executed against the target before admission. BigEye records its origin, target, configuration, validation result, and first observed clean coverage. Invalid or redundant candidates do not enter the durable corpus.

For AFL++, BigEye uses `afl-cmin` for coverage-preserving corpus reduction and `afl-tmin` for individual crash or interesting-input reduction. For libFuzzer it uses merge/minimise modes. Minimisation runs at checkpoints rather than continuously, and it never stops the only healthy campaign solely to tidy the corpus. Compatible campaigns may exchange admitted inputs; incompatible configurations retain separate corpora.

The durable corpus is the smallest known set preserving observed behaviour for a target/configuration. Raw queue growth can be cleaned after admitted representatives and provenance are recorded.

## 11. Clean coverage and traceability

Fuzzer-native instrumentation guides execution. It is not the coverage shown to the user. User-facing source coverage is produced by replaying admitted or minimised inputs against a separate clean-source build at the exact commit. Behaviour-changing fuzz patches are excluded. An external input adapter may be used for replay only when it does not alter the target source.

The coverage pipeline uses LLVM source-based coverage. At each evidence checkpoint it:

1. replays newly admitted representatives in the clean coverage container;
2. merges profile data for aggregate file, function, and line coverage;
3. records per-input deltas only for lines not previously attributed to that strategy;
4. stores the first reproducible testcase from each harness/strategy that reaches a line;
5. updates strategy overlap and project-wide summaries.

Source identity is exact commit, repository-relative path, and line number. A line detail can therefore answer:

- whether it has clean coverage;
- which harnesses and configurations reach it;
- the first retained testcase for each reaching strategy;
- the replay command and asset versions;
- accumulated CPU exposure from campaigns known to reach it.

CPU exposure is not an execution count. At a monitoring checkpoint, the CPU seconds consumed since the prior checkpoint are added to every function and line in that campaign's current clean reachable set. The UI labels this metric “CPU exposure” and explains that it means fuzzing time spent by campaigns capable of reaching the code, not time executing that exact line.

### Overlap and reversible retirement

BigEye compares clean line/function sets, unique crash groups, configuration purpose, and recent marginal coverage. A strategy becomes a retirement candidate when its clean coverage remains a subset of another compatible strategy across two evidence checkpoints, it has no unique crash group, and it has no documented configuration purpose. The manager reviews the evidence before a deterministic stop.

Retirement is reversible. Assets, minimised corpus, findings, and reason remain; only the active worker is released. This avoids deleting a useful harness merely because of a temporary plateau.

## 12. Crash processing and findings

Every raw crash enters quarantine. It does not become a finding immediately.

### Deterministic pipeline

1. Preserve the original input, engine output, target/configuration asset versions, commit, container image IDs, sanitizer, command, and stack.
2. Replay in the original campaign environment multiple times to establish reproducibility.
3. Minimise the input while preserving the failure signature.
4. Normalise stack, sanitizer, source location, signal, and relevant coverage into a grouping fingerprint.
5. Collapse duplicates into one crash group while preserving every original occurrence count and input provenance.
6. Replay through compatible sanitizer variants and the clean build or adapter where meaningful.
7. Inspect harness setup, API order, lifetimes, cleanup, and fuzz-only patch behaviour.
8. If harness misuse is suspected, create one bounded corrected asset version and compare the replay result.

Only after this pipeline does the crash triage specialist interpret the evidence.

### Classification

A group is represented as one of the user-required evidence outcomes, stored as plain data rather than a code enum:

- harness-induced false positive;
- improper contract usage;
- true vulnerability;
- flaky or environmental;
- unresolved.

A classification includes evidence, uncertainty, and the experiments that would change it. A rare input is never suppressed as harness-induced without replay, source, or API-contract evidence. Unresolved groups remain visible as unresolved.

A true-vulnerability finding receives a short user-facing description and a project-relative priority rank with its rationale. Ranking considers reproducibility, sanitizer evidence, affected operation, attacker-controlled input path, and reachability; it does not claim exploitability unless evidence supports it. The Findings view presents one group, one minimal reproducer, and one investigation summary rather than one row per duplicate crash.

## 13. Persistence

PostgreSQL stores structured state that must be queried or coordinated. The workspace stores large or naturally file-shaped artefacts.

### PostgreSQL concepts

- **projects:** repository URL, requested revision, resolved commit, worker count, optional project token, and creation/error/pause times.
- **tasks:** user-visible and internal operations with creation/completion/error times.
- **assets:** project ownership, descriptive kind/name, content hash, parent version, validation times and error. The artefact path is derived from its ID.
- **campaigns:** project, target/configuration asset references, engine name, start/stop/error/heartbeat times, CPU seconds, and next review condition.
- **coverage evidence:** commit/path/line, reaching campaign and asset references, first testcase identity, and CPU exposure.
- **findings:** project and crash group identity, classification text, priority rank and rationale, description, replay result, and triage times.

The initial schema remains one `backend/database/schema.sql`. There is no migration framework before the first release. The development reset script drops and recreates only BigEye's schema. No field is added for data that can be derived from identifiers or timestamps, and initial models use no application enum types.

### Workspace layout

```text
workspace/
├── postgres/
└── projects/<project-id>/
    ├── repository/                  # exact clean checkout
    ├── build-contexts/              # generated safe Docker contexts
    ├── layers/                      # generated Dockerfiles and manifests
    ├── assets/<asset-id>/           # harness, adapter, patch, config, dictionary
    ├── campaigns/<campaign-id>/
    │   ├── corpus/
    │   ├── queue/
    │   ├── crashes/
    │   └── coverage/
    ├── findings/<finding-id>/       # original and minimal reproducers
    └── logs/
        ├── activity.jsonl
        └── debug.jsonl
```

All workspace paths are derived from validated IDs and contained under the project root. `workspace/`, `.superpowers/`, virtual environments, build outputs, environment files, and node modules are ignored by Git.

## 14. API and events

The HTTP surface is resource-oriented and thin:

- project create/list/detail;
- per-project settings read/update;
- project pause/resume;
- campaigns and active strategy summaries;
- coverage tree, source file, function, and line evidence;
- findings list/detail and reproducer metadata;
- activity and debug log queries;
- health and capability checks.

Project server-sent events carry small invalidation and append notifications rather than complete state snapshots. The UI refetches the affected resource. Events have monotonically increasing per-project IDs, support `Last-Event-ID`, and reconnect without duplicating visible entries.

Large artefacts are downloaded through bounded project-scoped endpoints. The API never accepts an arbitrary host path.

The requested revision and resolved commit are immutable after cloning because every asset and evidence record depends on them; testing another revision creates another project. Worker count and token are editable. Increasing worker count opens campaign slots. Decreasing it preserves campaign state and stops the manager's lowest-priority active strategies until the new count is met. Settings responses report whether a token exists but never return the stored token.

## 15. UI and interaction design

### Visual direction

The selected design is a restrained project command centre:

- narrow black navigation;
- white main surface;
- red used only for focus, active attention, and critical evidence;
- warm off-white and neutral grey complete the five semantic colours;
- no blue, green, purple, gradients, neon, glass effects, or decorative status colours;
- strong modern sans-serif typography, with one monospace face only for source and logs;
- hairline separators, modest corner radius, almost no shadows, and generous whitespace;
- no dense card grid, nested cards, badge overload, or fake metrics.

Fuzzer, model, sanitizer, LLVM, and Docker names are technical metadata in expanded details. They are never the primary information hierarchy. The primary language is target, strategy, source coverage, current focus, finding, evidence, and next review.

Radix Primitives provide accessible dialogs, tabs, disclosures, tooltips, scroll areas, and focus management. Project-owned CSS variables define the design system. Lucide supplies one consistent line-icon set. The source coverage map uses a small data-backed hierarchy layout rather than a chart dashboard library.

### Views

- **Projects:** repository intake and a concise list of real projects.
- **Overview:** selected-project coverage map, strong and weak areas, current focus and reason, short active strategy list, genuine findings summary, and pause/resume.
- **Source Assurance:** source tree and code view with line coverage, strategy filters, first testcase links, replay evidence, and CPU exposure.
- **Findings:** replayed crash groups ordered by project priority, with classification, uncertainty, minimal reproducer, and evidence.
- **Activity:** readable chronological decisions, reasons, changes, evidence, and next review conditions.
- **Logs:** expandable complete local debug trace with filters for agent, API call, tool, build, fuzzer, coverage, and error.
- **Settings:** selected-project immutable revision and commit, editable worker count, a write-only repository token field whose token is expected to have read-only scope, and actual host/database/Docker/OpenAI/toolchain health.

Activity and Logs may share one navigation item with two tabs, but remain separate information modes. Internal tasks appear in Activity details; “Tasks” is not a primary product view.

### Accessibility

The UI meets WCAG 2.2 AA contrast, keyboard navigation, visible focus, logical headings, and reduced-motion preferences. Colour is never the only signal. Coverage and findings use text, shape, labels, or patterns alongside colour. All charts have a tabular or source-list equivalent and meaningful accessible names.

## 16. Activity, OpenAI, and debug observability

The default Activity stream is written for a fuzz tester:

- what BigEye decided;
- why it decided it;
- what changed;
- what evidence supports the change;
- when or why it will review again.

The debug stream mirrors every local OpenAI workflow and deterministic operation needed to reproduce behaviour. It records:

- workflow, trace, response, parent, and tool-call identifiers;
- manager or specialist name and model;
- sanitized model input and raw response items;
- structured motivation and the API-provided reasoning summary when present;
- `Agent.as_tool()` boundaries, function arguments, bounded results, web citations, and tool errors;
- command, image, and container identifiers plus stdout and stderr;
- start/end times, retry count, latency, error, token use, cached tokens, and reasoning tokens;
- generated patches and diffs;
- sanitized raw JSON for advanced inspection.

Agents SDK `RunHooks`, result `new_items`, `raw_responses`, usage details, and a local trace processor provide these surfaces. OpenAI's built-in tracing may remain enabled, but the append-only local log is authoritative for the product UI.

BigEye never claims to expose hidden chain-of-thought. It shows the agent's required concise structured motivation and only reasoning summaries actually returned by the API. API keys, Git tokens, Authorization headers, credential-bearing URLs, and environment secrets are redacted before persistence. In this single-user local product, source excerpts and prompts may remain in the project-scoped debug log.

`activity.jsonl` and `debug.jsonl` are append-only, have stable event IDs, and are streamed through SSE. PostgreSQL stores only structured project references and query state, not duplicate raw log bodies.

## 17. Failure handling and recovery

- **Clone failure:** preserve the safe error, allow the per-project token or revision to be corrected, and retry without creating a duplicate project.
- **Build failure:** retain build logs and the last valid layer; allow one bounded agent repair at a time; never invalidate unrelated cached layers.
- **Agent failure:** record the API error and usage, retry transient transport failures with bounded backoff, then leave the deterministic operation recoverable. No infinite API retry loop.
- **Invalid agent action:** reject it at the structured boundary and provide validation evidence for one corrected attempt.
- **Fuzzer failure:** preserve queue/corpus/crashes, inspect exit cause, and restart only if the target was previously healthy and the failure is recoverable.
- **Docker restart:** reconcile labelled containers and image IDs with PostgreSQL; adopt still-running containers or restart from durable corpora.
- **Backend restart:** advisory locks and heartbeats identify unfinished projects; coordinators resume after verifying the exact commit and assets.
- **Database unavailable:** stop scheduling new actions, leave isolated fuzzing containers untouched, and reconnect with bounded backoff.
- **OpenAI unavailable:** healthy fuzzers continue. Deterministic collection and crash quarantine continue. Agent-dependent decisions wait.
- **Host sleep or shutdown:** state remains in PostgreSQL and project workspace; work resumes when Docker and BigEye return.

## 18. Self-cleaning policy

BigEye removes only reproducible disposable state automatically:

- temporary clone and build contexts after their image and manifest are verified;
- stopped superseded containers after logs and identifiers are persisted;
- unreferenced failed image layers created by BigEye after a grace period;
- raw corpus entries after minimised admitted representatives preserve their behaviour;
- duplicate crash copies after the original provenance and group occurrence are recorded.

BigEye retains clean repository checkout, asset versions, useful corpora, minimal crash inputs, findings, coverage evidence, decisions, and current logs. Strategy retirement is a reversible state change, not deletion.

## 19. Security boundaries

- The API binds to loopback by default.
- PostgreSQL publishes a loopback-only host port.
- Project tokens are stored locally as permitted for this release, but are redacted from all output and never enter Docker.
- Repository, agent, and testcase paths are resolved and checked against project roots; `.git` and escaping symlinks are inaccessible to agent tools.
- Runtime fuzzing has no external network, no privileged containers, no host Docker socket, read-only source mounts where possible, bounded CPUs/memory/processes, and campaign-specific writable mounts.
- Dependency download is separated from compilation and runtime. Network-enabled build steps receive no Git or OpenAI credentials.
- Generated Dockerfiles and patches pass deterministic policy validation before execution.
- Project code, build scripts, samples, and web pages are treated as untrusted content.
- Destructive cleanup operates only on explicit BigEye labels and resolved project paths.

Running untrusted project builds through a local Docker daemon remains a material local-development risk, especially on Linux. BigEye documents this boundary and never mounts host-sensitive paths into those builds.

## 20. Code organisation target

The implementation extends the existing backbone with these responsibility groups. The detailed plan will name every file and test.

```text
backend/
├── api/{controllers,views}/
├── models/
├── database/
├── repositories/
├── services/
│   ├── projects/
│   ├── campaigns/
│   └── observability/
├── agents/
│   ├── prompts/
│   ├── tools/
│   ├── outputs/
│   └── tracing/
└── fuzzing/
    ├── docker/
    ├── images/
    ├── layers/
    ├── discovery/
    ├── assets/
    ├── engines/{afl,libfuzzer}/
    ├── corpus/
    ├── coverage/
    ├── crashes/
    └── campaigns/

frontend/src/
├── models/
├── controllers/
├── views/
├── components/
│   ├── design-system/
│   ├── coverage/
│   ├── findings/
│   └── activity/
└── services/
```

Packages are introduced only when their first real responsibility is implemented. Existing focused files remain; files that acquire a second responsibility are split during the task that needs it. There is no catch-all utility module and no premature plugin framework.

## 21. Verification strategy

### Automated tests

- Unit tests for path containment, token redaction, content hashing, state derivation, wake rules, sanitizer selection, overlap rules, and crash fingerprints.
- Repository tests against PostgreSQL for projects, assets, campaigns, coverage evidence, findings, advisory ownership, and reset behaviour.
- Docker SDK contract tests for `linux/amd64`, labels, cache reuse, network policy, mounts, limits, log streaming, stop, and recovery.
- Agent tool tests for permissions, bounded output, structured validation, dispatch, trace capture, and prompt-injection resistance.
- Service tests for clone, layer generation, incremental rebuild, probe gates, campaign control, pause/resume, and recovery.
- Engine tests for AFL++ and libFuzzer commands, health parsing, corpus minimisation, and crash collection.
- Coverage tests proving fuzz-only patches do not enter reported coverage and first-reaching testcase evidence replays.
- Crash tests proving replay, minimisation, duplicate collapse, harness-induced comparison, and unresolved preservation.
- React controller/view tests with no production fixtures.
- Accessibility tests, keyboard tests, type checking, and production build.
- Playwright journey tests against the real API with deterministic fake OpenAI responses and Docker services at the boundary.

### Real release fixtures

BigEye includes small first-party fixture repositories written for its tests, not copied from OSS-Fuzz, OSS-Fuzz-Gen, or another fuzzing framework. Together they exercise:

- a system executable with two evidence-backed configurations;
- a component library with a libFuzzer harness;
- clean coverage replay;
- a duplicate crash;
- a deliberately harness-induced failure distinguished from a target failure;
- pause, restart recovery, and reversible campaign retirement.

OpenAI live tests are opt-in and use the user's key. Deterministic tests stub model output at the Agents SDK boundary; they do not replace release smoke tests of the real manager-to-specialist call.

### Release acceptance

The release is accepted only when all of the following are demonstrated on macOS and Linux:

1. setup produces a Python 3.14 virtual environment whose installed packages match `backend/requirements.txt`, and a frontend whose install matches its lockfile;
2. PostgreSQL is the only application service in Compose and runs as `linux/amd64` with a project-local volume;
3. the host API and production frontend start with one documented command;
4. a public repository starts without credentials and a private repository can use its project token without secret leakage;
5. repository, dependency, target, and clean-coverage layers reuse cache correctly;
6. one real Terra manager invokes bounded specialists through `Agent.as_tool()` and every action is deterministically validated;
7. one AFL++ system campaign and one libFuzzer component campaign run in parallel as real containers;
8. healthy fuzzers continue without agent polling and wake the manager on genuine evidence conditions;
9. automated corpus admission and minimisation preserve clean coverage;
10. Source Assurance identifies the first testcase per strategy for a selected line and reports CPU exposure accurately according to its definition;
11. redundant campaign retirement is evidence-based and reversible;
12. a crash is replayed, minimised, deduplicated, and distinguished from a harness-induced failure before appearing as a finding;
13. the UI contains no fake findings, metrics, logs, or runtime state and follows the approved visual hierarchy;
14. Activity explains decisions while Logs contains the sanitized OpenAI/tool/build/fuzzer debug trace without claiming hidden reasoning;
15. pause, backend restart, Docker restart, and database reconnection preserve or recover useful work;
16. the full backend, frontend, Docker, fixture, accessibility, and end-to-end test suites pass.

## 22. Implementation order

The implementation plan will deliver the product as one coherent vertical release in this order:

1. release foundation, schema, workspace contracts, and recovery primitives;
2. professional UI design system and real API view contracts;
3. repository layers, target evidence, reusable assets, and incremental builds;
4. Agents SDK manager, specialists, bounded tools, local RAG, web research, and complete traces;
5. AFL++ system campaigns and libFuzzer component campaigns;
6. continuous coordinator, wake rules, corpus automation, and campaign overlap handling;
7. clean coverage, source traceability, and CPU exposure;
8. crash quarantine, triage, findings, and bounded repair;
9. full UI integration, recovery, self-cleaning, release scripts, and macOS/Linux verification.

Each step leaves a tested vertical capability and preserves the working foundation. Subagent-driven development uses a fresh implementer and reviewer for each task, with a final whole-branch review after every acceptance criterion is exercised.

## 23. Authoritative external references

- [OpenAI Agents SDK: agents as tools and orchestration](https://openai.github.io/openai-agents-python/multi_agent/)
- [OpenAI Agents SDK: results and raw responses](https://openai.github.io/openai-agents-python/results/)
- [OpenAI Agents SDK: lifecycle hooks](https://openai.github.io/openai-agents-python/agents/)
- [OpenAI Agents SDK: tracing](https://openai.github.io/openai-agents-python/tracing/)
- [AFL++ v4.40c official release](https://github.com/AFLplusplus/AFLplusplus/releases/tag/v4.40c)
- [Radix Primitives accessibility](https://www.radix-ui.com/primitives/docs/overview/accessibility)
- [Web Content Accessibility Guidelines 2.2](https://www.w3.org/TR/WCAG22/)
