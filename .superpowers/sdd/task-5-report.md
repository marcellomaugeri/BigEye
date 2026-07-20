# Task 5 report: Exact clean coverage inventories

## Scope delivered

- LLVM export parsing now retains instrumented zero-count lines, functions, and branch outcomes from bounded real-shaped data. Missing or malformed branch inventories remain unavailable (`null`) rather than becoming `0/0`.
- Every retained inventory is bound to the exact clean image, project commit, coverage asset, and checkout source SHA-256. First-testcase traceability remains limited to reproducibly covered lines.
- PostgreSQL stores exact per-source denominators and branch identities. Snapshot updates union covered branch state, preserve immutable denominators, and reject conflicting commit, source hash, or total identities.
- Project aggregates union comparable identities and calculate source CPU exposure as the maximum per campaign within each source followed by the sum across campaigns. Campaign CPU remains the persisted campaign counter.
- Coverage responses expose nullable line/function/branch `{covered,total,percent}` measurements and branch state on source lines. Campaign responses derive `running`, `waiting`, `stopped`, or `failed` activity without persisting another state/type field.
- A five-minute line delta remains `null`: existing checkpoints do not persist observation timestamps, so presenting their order or generic marginal set as exactly five minutes would fabricate a measurement.

## TDD evidence

- RED: the initial focused run reported `112 passed, 6 failed`; failures proved the missing zero-count parser contract, branch inventory, nullable API summary, branch source state, and per-campaign source exposure maximum.
- GREEN: the exact five-file Task 5 suite reports `135 passed, 1 warning`.

## PostgreSQL 18.4 contract

- Started a disposable `postgres:18.4-bookworm` container on `linux/amd64` with an in-memory PostgreSQL 18 data root.
- Applied `backend/database/schema.sql` with `ON_ERROR_STOP=1`.
- Computed catalog signature `c3d5e2de08a85200e145b9d6a126b63b` from PostgreSQL's real relation, column, constraint, and index catalog.
- Applied `backend/database/schema_contract.sql` successfully (`DO`).
- Removed the disposable container after verification.

## Verification

- `backend/.venv/bin/python -m pytest backend/tests/test_clean_coverage.py backend/tests/test_coverage_api.py backend/tests/test_exposure.py backend/tests/test_campaign_api.py backend/tests/test_development_database.py -q`: `135 passed, 1 warning in 1.57s`.
- Target production modules compile with `python -m py_compile`.
- `git diff --check`: passed.
- No broad backend suite or heavy-job scheduling test was run or changed.
