# BigEye Continuous Agent Completion Design

**Date:** 2026-07-20

**Status:** Written review required before implementation planning

**Target:** Release-ready local application for macOS and Linux

## 1. Purpose and precedence

This specification completes the autonomous loop described in
`2026-07-19-bigeye-autonomous-fuzzing-design.md`. The earlier design remains valid except where
this document explicitly replaces it.

This document replaces four earlier decisions:

1. Fixed system, component, and triage agent classes become dynamically assigned general fuzzing
   workers.
2. Fixed manager review delays become manager-selected, persisted wake deadlines with watchdog
   recovery.
3. User-facing campaign pause and resume controls are removed. The manager owns scheduling.
4. Findings gain on-demand, read-only, containerised reproduction with live terminal output.

The implementation is complete only after a real one-hour libaom campaign and a controlled crash
acceptance campaign exercise the actual agent, Docker, coverage, corpus, triage, ranking, recovery,
and UI paths. Test-defined target commands do not satisfy this acceptance criterion.

## 2. Product contract

The user selects a repository, an exact revision, and a project execution-slot count. The default
count is four. These slots limit concurrent CPU-heavy Docker compilation and fuzzing jobs, not
OpenAI API workers and not a particular engine or target type.

BigEye then operates continuously without routine user decisions. It prioritises code, assigns
fuzzing-engineer workers, creates and repairs targets, builds incremental Docker layers, validates
seeds, schedules campaigns, improves and minimises corpora, tries configurations, measures clean
coverage, removes redundant work, triages crashes, and schedules its own next review.

The manager may allocate all four execution slots to system targets, all four to component targets,
all four to compilation, or any mixture of compiling and fuzzing work. The allocation must be
justified by current evidence rather than a hard-coded engine split. Fuzzer and compiler processes
are ordinary deterministic jobs, not agents.

Agent runs do not consume project execution slots. Independent target analysis, crash triage,
corpus reasoning, coverage interpretation, and draft preparation may run concurrently whenever the
OpenAI API and independent asset boundaries allow it. If one of those tasks later requests a
CPU-heavy compilation or fuzzing operation, that deterministic operation waits for a project slot.

The application is continuous while its host backend is running. Every unfinished project must
always have at least one of the following:

- an active deterministic operation or fuzzing job;
- a pending manager or worker run;
- a persisted future manager wake-up.

There is no silent idle state.

## 3. Agent architecture

### 3.1 Manager

One GPT-5.6 Terra manager owns each project's durable objective and its complete execution-slot
budget. It receives bounded project, build, campaign, coverage, corpus, crash, and resource
evidence. It does not receive an unrestricted repository dump, host shell, or Docker client.

The manager may invoke the same general fuzzing-worker tool several times in one review. Independent
assignments may run concurrently through `Agent.as_tool()` and parallel tool calls. Only the manager
creates worker runs; workers do not recursively create more workers.

The manager's structured decision contains:

- a concise observable decision and motivation;
- cited deterministic evidence identifiers;
- selected application-owned action identifiers;
- a positive next-review delay in seconds;
- a plain-language reason for that deadline;
- unresolved uncertainty.

The delay is bounded between 60 seconds and 3,600 seconds. Early target supervision should normally
choose short delays. Healthy mature campaigns may choose longer delays. The bound prevents a model
from abandoning the project while still allowing it to choose how much evidence it needs.

### 3.2 General fuzzing workers

A fuzzing worker is a fresh agent run with one concrete assignment, for example:

- prioritise a target from current coverage gaps;
- create a system target or component harness;
- repair a build, target, configuration, or seed problem;
- try a compile-time or runtime configuration;
- improve a corpus, dictionary, grammar, or custom mutator;
- investigate a coverage plateau or overlap;
- interpret one deterministically processed crash group.

These are assignment descriptions, not persisted role enums or separate long-lived agent types. The
worker prompt describes the common fuzz-testing discipline. The manager supplies the exact task,
project revision, relevant target and campaign identities, current evidence, and a private draft
asset version.

Workers start with GPT-5.6 Luna. A failed deterministic validation or a genuinely difficult repair
gets one GPT-5.6 Terra escalation using the same assignment and evidence. Transport failures use
bounded retry and do not cause model escalation.

### 3.3 Common worker capabilities

Every worker receives the same project-contained capability surface:

- list, search, and read bounded source and generated files;
- inspect Git metadata, build evidence, symbols, tests, examples, campaign statistics, coverage,
  corpora, crashes, and terminal logs;
- retrieve ranked local repository evidence for a narrow question;
- search current official technical documentation and preserve citations;
- create, replace, or patch generated Dockerfiles, build scripts, fuzz-only source patches,
  harnesses, adapters, configurations, dictionaries, grammars, mutator configuration, and corpus
  inputs;
- build or reuse an incremental image layer;
- run a bounded build, probe, replay, coverage, or corpus-validation operation;
- request a new fuzzing campaign or a change to an existing campaign;
- propose promotion, repair, replacement, unscheduling, or deletion with supporting evidence.

Edits apply only to a worker-owned draft under the BigEye project workspace. The selected repository
checkout stays immutable. Drafts are promoted only after deterministic validation. Parallel drafts
cannot overwrite each other.

Normal Agents SDK agents plus explicit function tools remain the control plane. BigEye does not use
`SandboxAgent`: it is beta and would introduce additional agent-compute containers. Commands run
only through bounded BigEye services inside the project's fuzzing or build containers, preserving
the requirement that the host backend itself runs on the laptop.

## 4. Deterministic pipeline authority

Agents decide what to try; application services establish what happened. Agent capabilities call
focused services rather than a raw Docker socket or general host shell.

The deterministic boundary owns:

- project containment and exact revision identity;
- draft locking, content hashes, validation, promotion, and rollback;
- incremental layer dependency calculation and image reuse;
- Docker isolation and `linux/amd64` enforcement;
- build, probe, fuzzer, replay, coverage, and corpus command execution;
- worker-slot leases and campaign-container identity;
- coverage parsing, branch and line identity, CPU exposure, and overlap calculation;
- crash replay, minimisation, fingerprinting, grouping, and stability evidence;
- database transactions, file publication, cleanup, and recovery.

An agent result never directly proves that a build passed, code was covered, or a crash is a target
bug. Only recorded deterministic evidence can support promotion or publication.

## 5. Continuous scheduling and watchdog

The project coordinator remains an application task, not an agent. It serialises manager decisions
for one project with the existing PostgreSQL advisory lock while allowing the manager to dispatch
independent worker runs concurrently.

After each successful review, the coordinator persists the manager-selected project wake deadline
and its reason. Project-level wake data is necessary even when no campaign exists yet. Campaign
heartbeats continue to describe individual jobs; they are not used as a substitute for the manager
deadline.

The coordinator wakes the manager at the deadline or earlier when any of these changes occur:

- target build or probe completion or failure;
- worker health failure;
- crash replay completion;
- material coverage or corpus growth;
- coverage plateau;
- validated corpus, dictionary, grammar, mutator, or configuration opportunity;
- sustained coverage overlap;
- a free fuzzing slot;
- database, Docker, or generated-asset recovery.

Every manager and worker call has a wall-clock limit in addition to its turn limit. A timed-out call
is cancelled, recorded in the debug log, and retried from preserved evidence. Healthy fuzzers keep
running during agent failures or OpenAI outages. Repeated API failures use bounded backoff, but each
retry remains durably scheduled.

The coordinator checks Docker and manager deadlines at a short monitor interval. An overdue manager
deadline is retried even if the expected event notification was lost. On backend restart, the
registry reconstructs unfinished projects and immediately runs any overdue review.

The release UI exposes no project or campaign pause, resume, stop, or restart controls. Graceful
container stop and restart remain internal lifecycle operations used by the manager, backend
shutdown, corpus publication, repair, and recovery.

## 6. Target, configuration, and corpus lifecycle

Targets, configurations, harnesses, patches, build settings, and corpora remain independent,
content-addressed assets. A small change rebuilds only dependent layers. Working targets are edited
incrementally; a worker does not rebuild an existing solution from scratch unless evidence proves
its base unusable.

The manager may unschedule, replace, or delete work under these rules:

### Never-functional work

A target may be deleted when it has no successful probe, accepted campaign, useful clean coverage,
or finding dependency and deterministic evidence shows that it never functioned. Exact database,
workspace, container, and image identities are resolved before deletion. Shared parent layers are
not deleted.

### Fully overlapping work

A strategy may be deleted when comparable clean-build evidence shows its reached set is fully
subsumed across two consecutive checkpoints, it contributes no unique crash group, and another
healthy strategy retains the equivalent reach. Any finding dependency is first frozen into an
immutable reproduction bundle. The scheduling target and its unreferenced dependent layers may then
be deleted without losing the finding.

### Useful but currently low-value work

A functional strategy that is not fully redundant is unscheduled rather than deleted. Its assets,
corpus, immutable image identities, and evidence remain available for later manager reassignment and
finding reproduction.

Corpus discovery, admission, validation, synchronisation, duplicate removal, and minimisation are
automatic. A worker is invoked only when format or semantic judgement is useful, such as creating a
structured seed, dictionary, grammar, or custom-mutator configuration. There is no manual browser
hex editor in this completion scope.

## 7. Coverage and findings

User-facing coverage always comes from a clean build of the exact project revision. Fuzz-only
behavioural patches are excluded. The release records line, function, and branch identities and
their covered and instrumented totals when LLVM provides them. Missing denominators are displayed as
unavailable, never as zero.

The manager uses clean coverage, recent deltas, CPU exposure, campaign cost, first-testcase
traceability, target overlap, and uncovered reachable evidence to allocate jobs. The underlying
fuzzer remains secondary UI detail.

Every crash enters quarantine before an agent sees it:

1. preserve its exact campaign, image, command, sanitizer, configuration, and input;
2. replay it in the original environment;
3. minimise while preserving the failure signature;
4. compare clean replay and compatible sanitizer variants;
5. fingerprint and group duplicates;
6. assign a worker to inspect the harness contract and source evidence;
7. when misuse is suspected, let the worker create a corrected draft and request a comparison
   replay;
8. publish the selected classification and uncertainty only after evidence validation.

Supported classification text remains: `harness-induced false positive`, `improper contract
usage`, `true vulnerability`, `flaky or environmental`, and `unresolved`.

Findings are ordered by deterministic project-relative priority rank using classification,
reproducibility, recurrence, sanitizer and source evidence. The worker supplies the concise
description, uncertainty, remediation experiment, and priority rationale. BigEye does not invent an
opaque numerical severity score or claim exploitability without evidence.

## 8. Read-only finding reproduction

The Findings detail view contains a **Reproduce** action. It creates a new ephemeral reproduction
run from the finding's immutable bundle:

- exact target or clean image ID;
- exact command and environment;
- exact sanitizer and configuration;
- minimal retained testcase;
- `linux/amd64` platform and the same containment limits used by deterministic replay.

The browser opens an embedded read-only terminal panel. Server-sent events stream bounded stdout and
stderr while preserving line order. The panel is scrollable and shows start time, image identity,
command, exit code, termination reason, and completion time. It accepts no keyboard input and
exposes no shell.

The complete sanitized output is persisted as a reproduction log. The ephemeral container is
removed after completion or timeout. Starting a reproduction does not mutate the corpus, target,
finding, or running campaigns.

## 9. User interface

The existing professional shell remains. The completion adds or changes these product surfaces:

- **Overview:** the most important project metrics, including active jobs, covered and total lines,
  functions and branches when available, recent clean-coverage change, findings, and current manager
  focus.
- **Fuzzing:** a target and configuration table showing purpose, current activity, recent coverage
  change, total clean reach, CPU exposure, last evidence, and whether the manager is running,
  repairing, waiting, or has unscheduled the strategy. Deleted work appears only in Activity and
  Debug logs. Engine names remain secondary technical details.
- **Source:** line, function, and branch inspection with the first retained testcase and campaign
  provenance where available.
- **Findings:** ranked crash groups, evidence-backed classification, uncertainty, minimal input,
  suggested investigation, and the read-only reproduction terminal.
- **Activity:** concise manager and worker decisions.
- **Debug logs:** complete sanitized model, tool, deterministic operation, retry, timeout, and token
  usage records. The UI shows reasoning summaries returned by the API, never hidden chain-of-thought.
- **Settings:** immutable revision, configurable project execution-slot count, project read-only
  Git token, and actual local health. Pause and resume controls are removed.

The footer continues to show one plain-language manager state. When no review is due and all slots
are healthy it may say, for example, `Fuzzing at full speed`. It must be derived from real state.

## 10. Error and recovery behavior

- A failed draft never replaces the last validated target.
- Concurrent workers editing related assets receive independent drafts; promotion revalidates the
  parent identity and rejects stale work.
- One failed worker action does not cancel independent sibling actions.
- A hung model call is timed out and retried without stopping fuzzers.
- A crashed or mismatched container is adopted, restarted, or quarantined only after exact label,
  image, commit, asset, and campaign verification.
- PostgreSQL or Docker interruption leaves durable artefacts intact and creates a visible health
  error. Recovery resumes from persisted identities.
- A reproduction timeout stops only its ephemeral container and retains the partial terminal log.
- Logs redact OpenAI keys, Git tokens, credential-bearing URLs, environment secrets, and temporary
  authentication paths.

## 11. Verification and release acceptance

Implementation follows test-driven development. Unit and integration tests exercise the actual
manager, worker dispatch, draft validation, scheduler, Docker, corpus, coverage, crash, ranking,
reproduction, API, SSE, and React controller/view boundaries.

### Controlled whole-loop acceptance

A small repository owned by BigEye tests the complete product path without supplying target commands
to the agents. It exposes discoverable system and component input surfaces and deterministic cases
for a true target bug, improper contract use, harness-induced failure, and duplicate input.

The acceptance run must prove:

- Terra dispatches at least two independent general workers concurrently;
- workers create the system and component targets and their initial inputs through tools;
- deterministic probes accept useful targets and reject or repair broken drafts;
- AFL++ and libFuzzer run concurrently in real `linux/amd64` containers;
- clean line and branch coverage, CPU exposure, and first-testcase traceability are persisted;
- corpus admission and minimisation occur without user input;
- crashes are replayed, minimised, grouped, classified, ranked, and shown in Findings;
- false-positive and improper-contract classifications are evidence-backed;
- Reproduce streams the selected finding's real container output into the read-only browser
  terminal;
- a short manager deadline, an earlier evidence wake-up, a simulated hung call, and backend restart
  all cause the expected recovery without abandoning the project.

### One-hour real-project acceptance

The real demonstration project is the [official libaom repository at tag
`v3.13.2`](https://aomedia.googlesource.com/aom.git/+/refs/tags/v3.13.2), resolved to commit
`ad44980d7f3c7a2605c25d51ea96946949000841`. BigEye uses no OSS-Fuzz or OSS-Fuzz-Gen image,
Dockerfile, harness, corpus, workflow, code, or generated artefact.

After agent-led preparation, fuzzing runs for one continuous wall-clock hour with the project's
execution-slot count set to four. The observation window begins only after the first validated
fuzzer is active. During the run BigEye must:

- create targets and configurations through real worker-agent tool calls;
- execute both a system-level AFL++ campaign and a component-level libFuzzer campaign;
- demonstrate concurrent manager-assigned work and fill all four slots once four healthy candidates
  exist;
- keep healthy fuzzers running between manager reviews;
- record every manager-selected delay and wake the manager no later than that deadline plus one
  monitor interval;
- show real per-job activity, coverage deltas, accumulated CPU exposure, corpus growth, and logs in
  the UI;
- inspect any crash through the real deterministic and agent triage path, while truthfully reporting
  no finding if no crash occurs;
- finish with an acceptance report containing the exact revision, agent and tool traces, generated
  asset hashes, image IDs, campaign durations, CPU time, line/function/branch coverage where
  available, corpus counts, crash groups, findings, retries, and failures.

The one-hour run is not successful merely because containers remained alive. At least one system
target and one component target must accept inputs, execute project code, and publish clean coverage.
If all four slots cannot be filled, the report must identify the concrete build, probe, resource, or
manager-decision blocker and the release remains incomplete.

## 12. Explicit exclusions

- No user campaign pause, resume, stop, restart, or manual scheduling controls.
- No manual corpus hex editor.
- No raw host shell, unrestricted host file access, or raw Docker client for agents.
- No `SandboxAgent` or additional agent-compute containers.
- No OSS-Fuzz or OSS-Fuzz-Gen assets or code.
- No fake findings, coverage, terminal output, manager activity, or test-defined production target
  commands.
- No Windows support, hosted deployment, or multi-user behavior.
