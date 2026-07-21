# BigEye Demo Readiness Design

## Objective

Make the current release journey demonstrable without changing BigEye's product
workflow: show one polished five-second first-visit introduction, then prove the
current Projects modal through the complete browser, manager, Docker, campaign,
coverage, crash-triage, restart, and accessibility acceptance journey.

## First-visit introduction

The application displays a full-viewport introduction before its normal shell
only when `localStorage` does not contain `bigeye.intro.seen.v1`. The surface
uses the existing black, white and red design tokens. A centred, replaceable
`BigEye` logo slot sits above one accessible progress indicator. There is no
marketing copy, navigation or fake operational status.

The introduction lasts 5,000 milliseconds. The key is written only when the
timer completes, so closing the page early does not suppress the next complete
introduction. Storage failures do not stop the application: the introduction
still completes and the main interface loads. Reduced-motion users see the
same five-second state without animated movement.

The demo can replay the introduction with:

```js
localStorage.removeItem('bigeye.intro.seen.v1'); location.reload();
```

## Release acceptance

The browser acceptance test follows the current interface. On an empty
database it expects the Projects heading and `+ New project` action, waits for
the first-visit introduction to finish, opens the modal, completes the form,
and continues through the existing real journey. It does not reintroduce the
removed empty project picker or inline intake form.

## Verification

Unit tests use fake timers to prove first visit, exactly five seconds, storage
persistence, subsequent-load bypass, storage failure and Activity/UI
composition. The complete Playwright acceptance remains real: no mocked API,
campaign, coverage, finding, model trace or Docker state. The normal release
gate and the three opt-in live Docker campaign tests must also pass.
