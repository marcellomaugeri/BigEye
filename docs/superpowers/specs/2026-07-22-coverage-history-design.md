# Coverage History and Metric Clarity Design

## Objective

Separate absolute project coverage from per-campaign reproducibility evidence and make both understandable without specialist interpretation.

## Campaign table

- Replace **5m change** with **Latest gain** because checkpoints do not contain a wall-clock five-minute window.
- Latest gain is the number of newly reached lines in the most recent clean checkpoint.
- Replace **Total reach** with **Reproducible lines**. This is the number of distinct source lines for which that campaign has retained replay evidence.
- Display `No new lines` for a zero latest gain and `Not measured yet` before the first checkpoint.

## Absolute coverage history

- Persist a project-level line-coverage point whenever a clean snapshot changes the conservative absolute covered-line count.
- Each point stores only project ID, immutable commit, observation time, covered lines and total lines.
- Expose at most the latest 128 points with the existing coverage tree response.
- Render a native SVG line chart in Overview without adding a charting dependency.
- Show a truthful current baseline when history starts; do not manufacture earlier points.

## Coverage source rows

The approved requirements in `2026-07-22-coverage-row-status-design.md` remain unchanged.

## Failure handling

- Coverage history is bounded and validated so invalid percentages cannot reach the browser.
- A missing history displays the current absolute coverage value without inventing a trend.
- The existing detailed replay evidence remains separate and unchanged.
