# BigEye Release README and Submission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a clean BigEye branch with a judge-ready README, selected screenshots and an accurate Devpost draft.

**Architecture:** Documentation is derived from the checked-in implementation and observed release evidence. Runtime artefacts remain ignored, while four selected screenshots are copied to a public documentation directory. Devpost receives the same factual narrative as the repository without submitting the entry.

**Tech Stack:** Markdown, Git, Devpost Hackathons plugin, existing FastAPI/React/Docker project checks.

## Global Constraints

- Use UK English and ASCII apostrophes.
- Preserve the current implementation and unrelated user changes.
- Do not publish `.env`, `workspace/`, virtual environments, dependency directories, caches, raw logs or test reports.
- Do not claim the final browser-driven release rerun passed when it remains pending.
- Do not submit the Devpost entry.

---

### Task 1: Public documentation assets and README

**Files:**
- Create: `docs/assets/bigeye-intro.png`
- Create: `docs/assets/projects.png`
- Create: `docs/assets/new-project.jpg`
- Create: `docs/assets/replayed-finding.png`
- Modify: `README.md`

**Interfaces:**
- Consumes: observed screenshots and current project behaviour.
- Produces: a self-contained public project page with installation and testing guidance.

- [ ] **Step 1: Promote only the four reviewed screenshots**

Copy the selected images from ignored evidence folders into `docs/assets/` with the exact names above.

- [ ] **Step 2: Rewrite the README**

Use the design's judge-first order. Include the demo placeholder, screenshot captions, autonomous loop, model/tool boundary, Codex contribution, platform comparison, installation, testing, architecture, security, limitations and personal note.

- [ ] **Step 3: Check Markdown paths and UK English**

Run:

```sh
test -f docs/assets/bigeye-intro.png
test -f docs/assets/projects.png
test -f docs/assets/new-project.jpg
test -f docs/assets/replayed-finding.png
rg -n 'docs/assets/' README.md
```

Expected: every referenced local image exists and no placeholder exists except the explicitly labelled video URL placeholder.

### Task 2: Devpost draft

**Files:**
- Modify externally: Devpost project `1345306`

**Interfaces:**
- Consumes: final README narrative and live Build Week criteria.
- Produces: updated BigEye tagline and project description in `submission_draft` state.

- [ ] **Step 1: Update the editable project fields**

Set a concise tagline and complete project write-up through `update_project`; leave the video URL unset.

- [ ] **Step 2: Read the project back**

Call `get_project` and verify the name remains `BigEye`, the description is non-empty and the state remains `submission_draft`.

### Task 3: Source-only publication

**Files:**
- Review: all tracked and untracked files reported by `git status --short`

**Interfaces:**
- Consumes: the complete working tree.
- Produces: one intentional commit pushed to `origin/codex/bigeye-backbone`.

- [ ] **Step 1: Audit artefacts and credentials**

Run tracked-file, ignored-file, size and secret-pattern checks without printing `.env`. Confirm runtime data remains ignored.

- [ ] **Step 2: Run focused validation**

Run the documentation path checks, targeted backend release/agent tests, frontend tests, TypeScript check and production build. Do not rerun the entire 1,000-plus-test suite.

- [ ] **Step 3: Inspect the final diff**

Review `git diff --check`, `git status --short`, the staged file list and staged diff summary before committing.

- [ ] **Step 4: Commit and push**

Commit the intentional release source with:

```sh
git commit -m "feat: complete autonomous fuzzing MVP"
git push -u origin codex/bigeye-backbone
```

Expected: the remote branch advances to the new commit. Do not create a pull request because `gh` is not installed.
