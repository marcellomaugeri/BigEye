# Coverage Clarity and History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clarify campaign reach, colour source rows by coverage, and show verified absolute line coverage over time.

**Architecture:** PostgreSQL records a bounded project-level point only when conservative clean line coverage changes. The existing coverage tree API carries that series to a dependency-free SVG chart, while campaign checkpoint copy is renamed to describe the evidence it actually represents.

**Tech Stack:** Python 3.14, asyncpg, FastAPI, Pydantic, React 19, TypeScript, Vitest and CSS.

## Global Constraints

- Do not fabricate historical coverage points.
- Keep detailed replay evidence separate from absolute clean coverage.
- Add no frontend chart dependency.
- Preserve coverage state in accessible source-row names.

---

### Task 1: Source-row visual status

**Files:**
- Modify: `frontend/src/components/coverage/SourceCode.tsx`
- Modify: `frontend/src/app.css`
- Test: `frontend/src/SourceAssurance.test.tsx`

**Interfaces:**
- Consumes: `SourceLine.covered` and `SourceLine.cpu_exposure_seconds`.
- Produces: `coverage-covered` or `coverage-uncovered` button classes with CPU-only visible metadata.

- [ ] Write a failing component test asserting distinct status classes, absent visible coverage and branch copy, retained CPU copy, and accessible coverage state.
- [ ] Run `npm --prefix frontend test -- --run src/SourceAssurance.test.tsx` and confirm the new assertion fails.
- [ ] Apply the status class in `SourceCode.tsx`, remove visible status and branch nodes, and keep the existing accessible label.
- [ ] Add restrained green/red row surfaces and a non-destructive selected outline in `app.css`.
- [ ] Re-run the focused test and confirm it passes.

### Task 2: Truthful campaign metric names

**Files:**
- Modify: `backend/services/campaigns/read_campaigns.py`
- Modify: `backend/api/views/campaign.py`
- Modify: `backend/tests/test_campaign_api.py`
- Modify: `frontend/src/models/campaign.ts`
- Modify: `frontend/src/models/fuzzing.ts`
- Modify: `frontend/src/controllers/useFuzzing.ts`
- Modify: `frontend/src/components/fuzzing/FuzzingTable.tsx`
- Test: `frontend/src/Fuzzing.test.tsx`

**Interfaces:**
- Produces: `recent_line_gain: int | null`, derived as `len(history.checkpoints[-1].recent_marginal_lines)`.
- Retains: `total_reached_lines`, displayed as reproducible campaign lines.

- [ ] Write failing backend and frontend tests for `recent_line_gain`, **Latest gain**, **Reproducible lines**, `No new lines`, and `Not measured yet`.
- [ ] Run the focused Python and Vitest commands and confirm the failures describe the old five-minute contract.
- [ ] Replace `covered_line_delta_5m` with `recent_line_gain` through the response and frontend model boundary.
- [ ] Render the explicit user-facing labels and zero/absent states.
- [ ] Re-run the focused tests and confirm they pass.

### Task 3: Persist and expose absolute coverage history

**Files:**
- Modify: `backend/database/schema.sql`
- Modify: `backend/database/schema_contract.sql`
- Modify: `backend/repositories/coverage_repository.py`
- Modify: `backend/fuzzing/coverage/traceability.py`
- Modify: `backend/api/views/coverage.py`
- Test: `backend/tests/test_clean_coverage.py`
- Test: `backend/tests/test_coverage_api.py`
- Test: `backend/tests/test_development_database.py`

**Interfaces:**
- Produces repository method `coverage_history(project_id: int, commit_sha: str, limit: int = 128) -> tuple[dict, ...]`.
- Adds `history: list[CoverageHistoryPointResponse]` to `CoverageTreeResponse`.

- [ ] Write failing tests requiring a history row only when covered/total lines change, chronological bounded reads, and API validation of `observed_at`, `covered`, `total`, and `percent`.
- [ ] Run the focused backend tests and confirm they fail because history persistence and response fields are absent.
- [ ] Add `coverage_history` with project, commit, observation time, covered lines and total lines; constrain counts to `0 <= covered <= total`.
- [ ] During `upsert_snapshot`, compute conservative project totals and insert only when they differ from the latest point.
- [ ] Read the last 128 points chronologically and include them in `TraceabilityService.project_tree`.
- [ ] Update the development schema contract and re-run the focused backend tests.

### Task 4: Absolute coverage chart

**Files:**
- Create: `frontend/src/components/coverage/CoverageHistoryChart.tsx`
- Modify: `frontend/src/models/coverage.ts`
- Modify: `frontend/src/components/coverage/CoverageMap.tsx`
- Modify: `frontend/src/app.css`
- Test: `frontend/src/Overview.test.tsx`

**Interfaces:**
- Consumes: `CoverageTree.history` points ordered by observation time.
- Produces: an accessible SVG named `Absolute line coverage over time`.

- [ ] Write a failing Overview test requiring the chart, current percentage, and truthful single-baseline presentation.
- [ ] Run `npm --prefix frontend test -- --run src/Overview.test.tsx` and confirm failure because the chart is absent.
- [ ] Implement a native SVG polyline/dot chart with time on the x-axis and absolute line percentage on the y-axis.
- [ ] Place it above the source-area map and add responsive dark-theme CSS.
- [ ] Re-run the focused test and frontend build.

### Task 5: Live database and application verification

**Files:**
- Modify only the local PostgreSQL schema and generated frontend build artefacts ignored by Git.

**Interfaces:**
- Consumes: committed `schema.sql` and the current project 2 summaries.
- Produces: a current truthful baseline followed by real future history points.

- [ ] Stop only the old host backend process if it owns port 8000.
- [ ] Apply the new table DDL to the local PostgreSQL container and insert the current project baseline from conservative source summaries.
- [ ] Run focused backend tests, focused frontend tests, and `npm --prefix frontend run build`.
- [ ] Start `scripts/start.sh --no-browser` and verify the Coverage and campaign endpoints return HTTP 200.
- [ ] Open Overview and confirm the absolute chart, explicit campaign copy, and green/red source rows render from real data.
