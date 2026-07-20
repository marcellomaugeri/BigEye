# BigEye

BigEye is a single-user fuzz-testing application that runs locally. Give it an
HTTP(S) Git repository and an exact branch, tag, or revision. BigEye resolves
that revision once, builds reusable `linux/amd64` layers, selects evidence-backed
targets, and manages system-level AFL++ and component-level libFuzzer campaigns.
The product interface shows source assurance, campaign decisions, sanitized
debug evidence, and only replayed and triaged crash groups.

The FastAPI backend and React application run on the host. Docker is used only
for PostgreSQL and isolated build, fuzzing, replay, and coverage work.

## Supported hosts and prerequisites

BigEye supports macOS with Docker Desktop and Linux with Docker Engine plus
Docker Compose v2. Install these prerequisites yourself before setup:

- Python 3.14 as `python3.14`;
- Node.js with npm;
- Git;
- Docker with Compose v2 and a builder that supports `linux/amd64`.

The setup script verifies prerequisites and reports missing tools. It never
installs system packages.

## First setup

From the repository root:

```sh
cp .env_example .env
```

Add `OPENAI_API_KEY` to `.env`. Do not commit that file. PostgreSQL settings in
the template are local development defaults and may be changed before first
startup.

Then run:

```sh
scripts/setup.sh
```

This creates `backend/.venv` with Python 3.14, installs the exact frozen Python
requirements, runs `npm ci`, verifies Docker's `linux/amd64` capability, starts
PostgreSQL, and validates the development schema. It does not rewrite
`backend/requirements.txt` or install host packages.

## Start BigEye

```sh
scripts/start.sh
```

The command loads `.env` without printing it, builds the production frontend,
health-checks PostgreSQL, and serves the product at
`http://127.0.0.1:8000/`. It opens that loopback URL after the API is ready.
For a Linux host without a desktop session or for an automated smoke check:

```sh
scripts/start.sh --no-browser
```

Use `--port PORT` to choose another loopback port. There is no non-loopback bind
option. Press Ctrl-C for a graceful host-backend shutdown. PostgreSQL and
labelled fuzzing containers are intentionally retained so the next start can
recover useful work. Stop PostgreSQL explicitly when desired:

```sh
docker compose stop postgres
```

For frontend development with Vite's API proxy, export the same local
environment before starting the backend and the Vite server in separate
terminals:

```sh
set -a; . ./.env; set +a
```

The release path remains `scripts/start.sh`; the manual development workflow is
only useful when editing the frontend.

## Product workflow

1. Create a project with a public repository URL, revision, and worker count.
   A private repository may also use a project-specific read-only token.
2. BigEye clones the resolved revision and builds a repository layer on the
   maintained LLVM toolchain image.
3. The project manager uses bounded specialist tools to choose and prepare
   system-level or component-level targets. Working dependency, target, and
   coverage layers are reused rather than rebuilt from scratch.
4. Healthy fuzzer processes continue without model polling. Durable coverage,
   corpus, crash, and review evidence wake the manager when action is needed.
5. Crash candidates are replayed, minimized, grouped, and classified as
   harness-induced, improper contract usage, true vulnerability, flaky, or
   unresolved before they appear in Findings.

The requested revision and resolved commit are immutable. Create another
project to test another revision. Worker count and the read-only token remain
editable in the selected project's Settings. The token field is write-only;
the API returns only whether a token is present.

## Understanding the interface

- **Overview** shows the current focus, active strategies, genuine finding
  count, and measured source coverage.
- **Source** shows clean-build line coverage, CPU exposure, reaching strategies,
  and the retained first testcase for reproducibility.
- **Findings** shows replayed crash groups with classification, priority,
  uncertainty, replay evidence, and the minimal reproducer.
- **Activity** explains decisions, motivation, changes, evidence, and the next
  review condition. Its Debug tab contains the sanitized local API, agent, tool,
  build, fuzzer, and coverage trace. It does not expose hidden reasoning.
- **Settings** controls the selected project and reports real local-service
  health.

CPU exposure is cumulative container CPU time attributed to lines reached by a
campaign's clean-coverage replay. It is not wall-clock time and is not a claim
that every input path through a line was tested.

## Data, recovery, and security boundaries

PostgreSQL data is stored in `workspace/postgres`. Repository clones, generated
assets, corpora, reproducers, coverage evidence, and sanitized logs are stored
under `workspace/projects/<project-id>`. The workspace and `.env` are ignored by
Git.

On startup BigEye reconciles unfinished projects and labelled containers with
the stored commit, image, and asset identities. Pause and graceful shutdown
preserve useful corpora and evidence. Cleanup removes only verified temporary or
redundant BigEye-owned data; it does not delete project evidence.

The OpenAI key remains in the host process environment. Repository tokens are
used only for contained Git authentication and are not returned by the API,
placed in Docker layers, frontend bundles, commands, or local logs. Debug
records redact known secret fields and values before persistence.

## Checks

Run the local release gate with:

```sh
scripts/check.sh
```

It verifies the frozen Python environment, Compose configuration, backend tests,
frontend tests, TypeScript, and the production frontend build. Real Docker
campaign tests are deliberately opt-in because they build images and run
fuzzers:

```sh
scripts/check.sh --live-docker
```

## Troubleshooting

- If setup reports that Docker is unavailable, start Docker Desktop or the
  Docker Engine and rerun `scripts/setup.sh`.
- If the schema is incomplete, back up `workspace`, then run
  `backend/database/reset.sh`. That development command recreates only BigEye's
  `public` schema.
- If the frontend build is missing, run `npm --prefix frontend run build`.
- If port 8000 is already in use, stop the existing process or run
  `scripts/start.sh --port 8001`.
- Logs stay under the selected project's workspace and in Activity's Debug tab;
  secrets are not printed by the release scripts.
