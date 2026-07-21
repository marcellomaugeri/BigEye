# BigEye README Information Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the BigEye README into a concise professional product, setup and evidence narrative.

**Architecture:** Modify only `README.md`. Reorder existing evidence-backed material, simplify the campaign lifecycle and GPT-5.6 explanation, and remove repository-internal sections that are not useful to a first-time reader.

**Tech Stack:** GitHub-flavoured Markdown, HTML image markup and Mermaid.

## Global Constraints

- Use UK English.
- Do not invent campaign results or add future screenshots.
- Keep the existing comparison values and personal note.
- Do not alter source code or the running campaign.

---

### Task 1: Restructure the README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `docs/assets/logo.png`, existing screenshots and `docs/release-verification.md`.
- Produces: one self-contained GitHub README with stable heading anchors.

- [ ] **Step 1: Replace the header presentation**

Render the slogan as a blockquote and add a centred 180-pixel `docs/assets/logo.png` immediately below it.

- [ ] **Step 2: Add the linked contents list and reorder sections**

Place Demo and Getting started before capabilities and architecture. Move Platform comparison after the campaign and GPT-5.6 explanations. Remove Testing, Project structure, and Data and security boundaries.

- [ ] **Step 3: Rewrite the campaign lifecycle**

Replace the current agent-first flow with the eight evidence stages in `docs/superpowers/specs/2026-07-21-readme-information-design.md`. Keep the Mermaid diagram limited to those stages.

- [ ] **Step 4: Rewrite the GPT-5.6 section**

Use `## How GPT-5.6 and Codex were used`, `### For development`, and `### In the project`. Include the separate brainstorming chat, intention document, up to 200 clarification questions, 18-hour first pass, and concise Superpowers skill bullets.

- [ ] **Step 5: Shorten setup and explain campaign startup**

Keep only the required commands and inputs. Put `docs/assets/new-project.jpg` with Start a campaign, and state why initial repository understanding, dual compilation and deterministic probes can take time.

- [ ] **Step 6: Verify Markdown structure**

Run:

```sh
git diff --check -- README.md
rg -n '^#{1,3} ' README.md
rg -n 'Testing|Project structure|Data and security boundaries' README.md
```

Expected: no whitespace errors; the intended headings appear once; removed headings return no matches.

- [ ] **Step 7: Commit the documentation change when requested**

```sh
git add README.md docs/superpowers/specs/2026-07-21-readme-information-design.md docs/superpowers/plans/2026-07-21-readme-information.md
git commit -m "docs: refine BigEye project narrative"
```
