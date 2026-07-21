# Manager Activity Footer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a persistent one-line footer that truthfully reports current manager or fuzzing activity and opens the Activity view.

**Architecture:** A focused React controller reads bounded existing Activity, Debug and campaign data, subscribes to the current project's SSE invalidations, and derives one presentation message. A rendering-only footer component displays that message while `App` owns navigation.

**Tech Stack:** React 19, TypeScript, Vitest, Testing Library, existing BigEye HTTP and SSE services.

## Global Constraints

- Do not add a backend status enum, database field, polling loop, mock runtime data, or rotating promotional messages.
- Use only sanitized existing manager traces and deterministic campaign evidence.
- Keep the footer to one visible line and retain keyboard and screen-reader access.
- Display `Fuzzing at full speed!` only when at least one unstopped, error-free campaign has a fresh heartbeat and the project is not paused.

---

### Task 1: Manager activity presentation model

**Files:**
- Create: `frontend/src/controllers/useManagerActivity.ts`
- Create: `frontend/src/components/activity/ManagerActivityFooter.tsx`
- Test: `frontend/src/ManagerActivityFooter.test.tsx`

**Interfaces:**
- Consumes: `BigEyeApi.getProjectLog`, `BigEyeApi.listCampaigns`, `ProjectEventStream.subscribe`, and the selected `Project`.
- Produces: `ManagerActivityModel` with `message: string | null`, `loading: boolean`, and `unavailable: boolean`; `ManagerActivityFooter` with `message` and `onOpenActivity` props.

- [x] **Step 1: Write failing tests**

The focused tests assert the concrete message contract and navigation action:

```tsx
expect(managerActivityMessage({
  project, campaigns, activityEvents: [activity], debugEvents: [managerStart],
  loading: false, unavailable: false, now,
})).toBe('Manager is reviewing campaign evidence...');

render(<ManagerActivityFooter
  message="Fuzzing at full speed!"
  onOpenActivity={onOpenActivity}
/>);
await user.click(screen.getByRole('button', {
  name: 'Open Activity: Fuzzing at full speed!',
}));
expect(onOpenActivity).toHaveBeenCalledOnce();
```

- [x] **Step 2: Verify the tests fail**

Run: `cd frontend && npm test -- --run src/ManagerActivityFooter.test.tsx`

Expected: FAIL because the controller and component do not exist.

- [x] **Step 3: Implement the minimum controller and component**

The controller reads one Activity record, 64 bounded Debug records and the
campaign list, while the rendering component receives only presentation props:

```tsx
export interface ManagerActivityModel {
  message: string | null;
  loading: boolean;
  unavailable: boolean;
}

export function ManagerActivityFooter({ message, onOpenActivity }: {
  message: string | null;
  onOpenActivity: () => void;
}) {
  if (message === null) return null;
  return <footer aria-label="Current manager activity">
    <button onClick={onOpenActivity} type="button">
      <span aria-live="polite">{message}</span>
    </button>
  </footer>;
}
```

- [x] **Step 4: Verify focused tests pass**

Run: `cd frontend && npm test -- --run src/ManagerActivityFooter.test.tsx`

Expected: PASS.

### Task 2: Persistent application composition

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/app.css`
- Modify: `frontend/src/App.test.tsx`

**Interfaces:**
- Consumes: `useManagerActivity` and `ManagerActivityFooter` from Task 1.
- Produces: a persistent, one-line footer whose action navigates to `#activity`.

- [x] **Step 1: Write a failing application test**

```tsx
const status = await screen.findByRole('button', {
  name: 'Open Activity: Manager is reviewing campaign evidence...',
});
await user.click(status);
expect(await screen.findByRole('heading', { name: 'Activity' })).toBeVisible();
```

- [x] **Step 2: Verify the application test fails**

Run: `cd frontend && npm test -- --run src/App.test.tsx`

Expected: FAIL because `App` does not render the footer.

- [x] **Step 3: Compose and style the footer**

```tsx
const managerActivity = useManagerActivity(apiClient, eventStream, projects.selectedProject);

<ManagerActivityFooter
  message={managerActivity.message}
  onOpenActivity={() => navigate('activity')}
/>
```

The fixed footer reserves content space, uses `text-overflow: ellipsis`, and
changes its left edge from the desktop sidebar width to zero below 48 rem.

- [x] **Step 4: Run complete frontend verification**

Run: `cd frontend && npm test && npm run typecheck && npm run build`

Expected: PASS with no TypeScript, test, or production-build errors.
