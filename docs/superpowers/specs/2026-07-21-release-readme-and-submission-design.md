# BigEye release README and submission design

## Purpose

Prepare BigEye for public review without changing its product behaviour. The public material must let a judge understand the problem, see the working product, install it, test it, and identify how Codex and GPT-5.6 contributed.

## README narrative

Use a judge-first hybrid structure:

1. Lead with the concrete problem and BigEye's answer.
2. Place the demo-video placeholder and strongest product screenshots near the top.
3. Explain the autonomous campaign loop, verified capabilities, and human-visible evidence.
4. Document how GPT-5.6 Terra, GPT-5.6 Luna, `Agent.as_tool()`, Codex, deterministic services and fuzzer processes divide responsibility.
5. Keep the existing competitor matrix, supported platforms, setup, runtime, security and verification material.
6. State current evidence and limitations honestly. Do not convert a partially observed release gate into a completed claim.
7. Close with the requested personal note, after the technical case.

The prose uses UK English, concrete terminology and short sections. It avoids unsupported novelty, vulnerability and release-readiness claims.

## Visual evidence

Promote only useful screenshots from ignored test evidence into `docs/assets/`:

- the first-load BigEye identity screen;
- the empty Projects screen that shows the clean entry point;
- the New project modal that shows repository, revision and worker controls;
- the evidence-backed Findings screen showing grouping, deterministic replay, priority and the minimal reproducer.

Do not publish screenshots that show obsolete navigation, failed local services, hidden internal paths or test failures.

## Devpost draft

Update the existing BigEye draft's tagline and description directly through the Devpost plugin. Structure the write-up around the problem, what BigEye does, how it was built, technical implementation, Codex and GPT-5.6 usage, challenges, achievements, lessons, next steps and the personal note. Leave the project unsubmitted.

The required submission-only fields remain for the user to review and complete: individual submitter type, Italy, Developer Tools, public repository URL, `/feedback` session ID, public YouTube video under three minutes, and developer-tool testing instructions. Do not invoke the submission action without explicit confirmation.

## Repository publication

Audit ignored runtime data, credentials, caches, generated builds, reports and oversized files. Stage source, tests, documentation, selected screenshots and CI configuration explicitly. Run focused release checks, commit on `codex/bigeye-backbone`, and push that branch to `origin`.

The absent GitHub CLI blocks automatic pull-request creation but not the requested branch push. No pull request is created unless the user later requests one after installing and authenticating `gh`.
