# Manager Activity Footer Design

## Objective

Keep one concise, truthful line visible at the bottom of BigEye so the user can
understand what the campaign manager or fuzzing infrastructure is doing without
opening Activity.

## Behaviour

- The footer is visible throughout the selected project's interface.
- While the manager is running, it says that the manager is reviewing campaign
  evidence.
- While healthy campaign instances are running and the manager is idle, it says
  `Fuzzing at full speed!`.
- Project preparation, pause, runtime error, inactive campaign, and unavailable
  live-data states use short factual messages.
- The latest structured manager decision may be shown briefly after it is
  recorded, using the existing sanitized Activity text.
- The footer is one visually truncated line. Its full text remains available to
  assistive technology and as the element title.
- Selecting the footer opens Activity for the selected project.
- Updates arrive through the existing project SSE invalidations. No rotating
  promotional copy, hidden chain-of-thought, or invented manager activity is
  displayed.

## Data and boundaries

`useManagerActivity` owns data loading and message selection. It reads only the
latest bounded Activity and Debug pages plus the current campaign list. A
`ManagerActivityFooter` component renders the resulting message and navigation
action. `App` composes the controller and component without embedding message
rules.

Manager execution is detected from the existing sanitized `agent.start`,
`agent.end`, and `workflow.error` records for `Campaign manager`. Healthy
fuzzing is derived from campaign stop/error/heartbeat data and the project pause
flag. No persisted status enum or new database field is added.

## Failure handling

If live data cannot be loaded, the footer says that manager activity is
temporarily unavailable. A project with no campaign activity says that BigEye
is preparing or waiting for the first manager decision. The footer never claims
that fuzzing is active without a fresh campaign heartbeat.

## Verification

Component and controller tests cover manager work, healthy fuzzing, waiting,
paused, error and unavailable states, SSE refetching, project switching,
single-line rendering, and Activity navigation. The full frontend test,
typecheck and production build commands must pass.
