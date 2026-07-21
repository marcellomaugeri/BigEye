# Run9 Supervision Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve actionable campaign failures and finalized finding evidence so supervision repairs the missing system target before repeating crash triage, while making artifact polling idempotent and diagnosable.

**Architecture:** Deduplicate one monitor page by durable artifact identity before evidence-result validation, and retain bounded exception messages at the runtime boundary. Build manager evidence from persisted repository/strategy/finding/action-failure facts, deriving target-class gaps symmetrically and prioritising unresolved failed actions over already-final findings.

**Tech Stack:** Python 3.14, asyncio, pytest, Pydantic models, filesystem-backed runtime evidence.

## Global Constraints

- Current strategy inventory plus repository evidence drives gap detection; no fixture-specific rules.
- A missing target class is required only when the repository proves that class's runnable surface.
- Finalized reproducible findings are not re-triaged without new evidence or classification uncertainty.
- Run targeted tests first, then the affected backend suite; the root agent owns the live run.

---

### Task 1: Artifact polling idempotency and diagnostics

**Files:**
- Modify: `backend/services/campaigns/production_evidence.py`
- Modify: `backend/services/campaigns/production_runtime.py`
- Test: `backend/tests/test_production_artifact_adapters.py`
- Test: `backend/tests/test_real_campaigns.py`

**Interfaces:**
- Consumes: `CampaignProgressObservation.artifacts` and caught processing exceptions.
- Produces: one outcome per `(kind, content_sha256)` and bounded non-empty `error` evidence.

- [ ] Add a failing regression with duplicate paths containing identical corpus bytes and assert processing returns one evidence ID.
- [ ] Add a failing runtime regression asserting a plain `ValueError` message is retained in manager and debug evidence.
- [ ] Run the focused tests and confirm the duplicate-ID failure and missing diagnostic.
- [ ] Deduplicate ordered artifacts by kind and content hash before dispatch and format a bounded diagnostic for every exception.
- [ ] Run the focused tests and confirm they pass.

### Task 2: Durable failed-action and symmetric gap evidence

**Files:**
- Modify: `backend/services/campaigns/project_coordinator.py`
- Modify: `backend/services/campaigns/production_runtime.py`
- Test: `backend/tests/test_project_coordinator.py`
- Test: `backend/tests/test_real_campaigns.py`

**Interfaces:**
- Consumes: persisted action outcomes, campaign strategies, repository inventory, and successful corrected action identities.
- Produces: retained unresolved action-failure evidence and `required_next_instance_type` derived from proven missing target surfaces.

- [ ] Add failing tests showing unrelated crash evidence cannot displace a decoder CLI action failure and only a distinct successful correction resolves it.
- [ ] Add failing component-only/system-only/no-surface gap tests using repository inventory evidence.
- [ ] Run focused tests and confirm expected failures.
- [ ] Implement durable action-failure retention/resolution and symmetric repository-backed target-class derivation.
- [ ] Run focused tests and confirm they pass.

### Task 3: Finalized finding evidence and supervision priority

**Files:**
- Modify: `backend/services/campaigns/project_coordinator.py`
- Modify: `backend/agents/prompts/manager.py`
- Test: `backend/tests/test_project_coordinator.py`
- Test: `backend/tests/test_agents.py`
- Test: `backend/tests/test_complete_agent_loop.py`

**Interfaces:**
- Consumes: current finding generation, replay/grouping details, unresolved action failures, and required target class.
- Produces: detailed finalized-finding evidence IDs and a manager decision that repairs the failed system target without repeating triage.

- [ ] Add the exact run9 failing regression: healthy adopted component, finalized true vulnerability, pending bad decoder CLI argv, and proven CLI surface.
- [ ] Assert the next decision selects a distinct corrected system target, preserves component execution, and emits no triage action.
- [ ] Run the regression and confirm failure for replay-only prioritisation.
- [ ] Add detailed retained replay evidence to finalized finding summaries and enforce failed-action/missing-class precedence in prompt and validation.
- [ ] Run targeted tests, then affected backend tests, and request the root agent's live run10.
