# BigEye README Information Design

## Goal

Make the README read like a restrained professional open-source product page: identify the product and proof quickly, let a new user run it without reading architecture, and explain the campaign loop and GPT-5.6 usage precisely.

## Header

Keep `# BigEye`, render the slogan as a Markdown blockquote, and place the existing transparent `docs/assets/logo.png` below it in a centred HTML image at 180 pixels wide. Do not add badges, decorative separators, or a large hero banner.

## Order

1. Header, quoted slogan, logo, category, user and market gap.
2. A short linked contents list.
3. Component and whole-system campaigns.
4. Validation at a glance.
5. Demo and project-creation screenshot.
6. Concise Getting started and Start a campaign instructions.
7. What BigEye does.
8. How BigEye manages a campaign.
9. How GPT-5.6 and Codex were used.
10. Platform comparison.
11. Supported platforms and prerequisites.
12. Licence and personal note.

Remove Testing, Project structure, and Data and security boundaries from the README. Detailed verification remains linked from `docs/release-verification.md`; implementation structure remains discoverable in the repository itself.

## Campaign explanation

Replace the current implementation-first architecture narrative with an explicit lifecycle:

1. Resolve and clone an immutable revision.
2. Build reusable project layers.
3. Let the manager assign bounded target preparation work.
4. Deterministically compile and probe proposed targets.
5. Start validated AFL++ or libFuzzer campaigns.
6. Replay the corpus against clean coverage binaries.
7. Wake the manager only for failures, plateaux, new reach, crashes, overlap, or its chosen review deadline.
8. Replay, minimise, group, classify and prioritise crashes before presenting findings.

Keep one Mermaid flow containing only those product stages. Put model names, SDK details and tool permissions in the later GPT-5.6 section, not in the primary product flow.

## GPT-5.6 and Codex

Use the heading `How GPT-5.6 and Codex were used`, divided into `For development` and `In the project`.

`For development` briefly records that the project began with brainstorming in a separate chat; the initial intention was supplied in a document; Codex asked up to 200 explicit clarification questions; the first implementation pass ran for 18 continuous hours with GPT-5.6 Sol at Extra High reasoning effort; and the Superpowers Writing Plans, Test-Driven Development, and Subagent-Driven Development skills structured planning, behaviour verification, implementation and review.

`In the project` briefly explains Terra as the campaign manager, Luna as the bounded first-pass worker, `Agent.as_tool()` as the delegation boundary, parallel worker calls for independent work, and deterministic application services for builds, fuzzing, coverage, corpus processing and crash handling.

## Getting started and screenshots

Keep setup to the self-explanatory commands: clone, copy `.env_example`, add `OPENAI_API_KEY`, run `scripts/setup.sh`, and run `scripts/start.sh`. Retain the Linux `--no-browser` variant without extended commentary.

Show the New project screenshot next to the campaign-start instructions. State that the first useful campaign can take time because BigEye must understand the repository, compile the selected project and clean coverage variants, and probe targets before fuzzing. Do not add further screenshots until the external campaign has real running-job, coverage and finding evidence.

## Style

Use UK English, short paragraphs, descriptive headings and bullets for skills. Keep technical claims evidence-bounded. Use `whole-system` consistently in user-facing prose while retaining literal code or model names where required.
