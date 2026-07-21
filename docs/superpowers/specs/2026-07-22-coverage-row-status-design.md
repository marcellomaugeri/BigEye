# Coverage Row Status Design

## Objective

Make source coverage immediately scannable without repeating status text on every line.

## Interface

- Give each source-code row a restrained green background when the line is covered.
- Give each source-code row a restrained red background when the line is uncovered.
- Keep only the line number, source text and CPU exposure visible in the row.
- Remove visible `covered`, `uncovered` and branch-count text.
- Preserve covered or uncovered state in the row's accessible name.
- Indicate the selected row with an outline that does not replace its coverage colour.

## Scope

This change affects only source rows in the Coverage view. It does not change stored coverage evidence, API contracts, the overview coverage table or coverage calculations.

## Verification

Frontend tests will verify that covered and uncovered rows receive distinct status classes, that CPU exposure remains visible, that coverage and branch labels are absent visually, and that accessible names retain the line's coverage state.
