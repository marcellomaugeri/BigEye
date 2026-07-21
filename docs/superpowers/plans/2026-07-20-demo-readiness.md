# BigEye Demo Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a five-second first-visit introduction and make the complete real browser acceptance journey match the current Projects modal.

**Architecture:** A focused `useFirstVisitIntro` controller owns storage and time, while a rendering-only `FirstVisitIntro` component owns the full-screen surface. `App` composes both. The checked-in Playwright journey uses current accessible UI contracts and retains all existing real backend, OpenAI and Docker assertions.

**Tech Stack:** React 19, TypeScript, Vitest, Testing Library, Playwright, existing FastAPI/Docker release fixture.

## Global Constraints

- The introduction lasts exactly 5,000 milliseconds and appears only while `bigeye.intro.seen.v1` is absent.
- Use the existing black, white and red CSS tokens and no external image or runtime dependency.
- Do not expose fake progress, operational claims, hidden reasoning, or a backend cookie.
- Do not weaken, mock, skip or delete any browser acceptance assertion beyond replacing obsolete UI selectors with current UI selectors.

---

### Task 1: First-visit introduction

**Files:**
- Create: `frontend/src/controllers/useFirstVisitIntro.ts`
- Create: `frontend/src/components/FirstVisitIntro.tsx`
- Create: `frontend/src/FirstVisitIntro.test.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/app.css`

**Interfaces:**
- Consumes: `window.localStorage`, `window.setTimeout`, and the existing application shell.
- Produces: `useFirstVisitIntro(): boolean` and `FirstVisitIntro({ visible }: { visible: boolean })`.

- [ ] **Step 1: Write the failing timer and persistence tests**

```tsx
vi.useFakeTimers();
window.localStorage.removeItem('bigeye.intro.seen.v1');
const { result } = renderHook(() => useFirstVisitIntro());
expect(result.current).toBe(true);
act(() => vi.advanceTimersByTime(4_999));
expect(result.current).toBe(true);
act(() => vi.advanceTimersByTime(1));
expect(result.current).toBe(false);
expect(window.localStorage.getItem('bigeye.intro.seen.v1')).toBe('1');
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `cd frontend && npm test -- --run src/FirstVisitIntro.test.tsx`

Expected: FAIL because the controller and component do not exist.

- [ ] **Step 3: Implement the focused controller and component**

```tsx
export function useFirstVisitIntro(): boolean {
  const [visible, setVisible] = useState(() => readIntroKey() !== '1');
  useEffect(() => {
    if (!visible) return;
    const timer = window.setTimeout(() => {
      writeIntroKey('1');
      setVisible(false);
    }, 5_000);
    return () => window.clearTimeout(timer);
  }, [visible]);
  return visible;
}
```

- [ ] **Step 4: Compose it above the existing shell and run focused tests**

Run: `cd frontend && npm test -- --run src/FirstVisitIntro.test.tsx src/App.test.tsx`

Expected: PASS.

### Task 2: Current browser release journey

**Files:**
- Modify: `tests/e2e/bigeye.spec.ts`
- Modify: `backend/tests/test_release_acceptance_contract.py`

**Interfaces:**
- Consumes: the current `Projects`, `New project`, modal form and introduction accessibility contracts.
- Produces: the same real end-to-end acceptance evidence with no obsolete empty-picker expectation.

- [ ] **Step 1: Preserve the observed failing acceptance result**

Run: `npm --prefix frontend run e2e`

Expected before the fix: FAIL at the obsolete `getByLabel('Current project')` empty-state assertion.

- [ ] **Step 2: Update only the obsolete opening interaction**

```tsx
await page.goto(frontendUrl);
await expect(page.getByRole('status', { name: 'BigEye is starting' })).toBeHidden();
await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
await page.getByRole('button', { name: 'New project' }).click();
await expect(page.getByRole('dialog', { name: 'New project' })).toBeVisible();
```

- [ ] **Step 3: Update the static contract for the current journey**

Require `BigEye is starting`, `Projects`, `New project`, and the modal dialog;
remove only the stale `getByLabel('Current project')` empty-state requirement.

- [ ] **Step 4: Run the complete acceptance journey**

Run: `npm --prefix frontend run e2e`

Expected: all four Playwright tests pass, including the real project journey.

### Task 3: Release verification

**Files:**
- Modify only if evidence changed: `docs/release-verification.md`

**Interfaces:**
- Consumes: all checked-in release gates.
- Produces: observed macOS evidence for the exact working tree.

- [ ] **Step 1: Run the normal release gate**

Run: `scripts/check.sh`

Expected: backend, frontend, typecheck, build and dependency checks pass.

- [ ] **Step 2: Run the real Docker gate**

Run: `scripts/check.sh --live-docker`

Expected: all three real `linux/amd64` campaign tests pass.

- [ ] **Step 3: Inspect the running app and acceptance cleanup**

Confirm the first-visit surface, five-second transition, current Projects view,
no serious browser console error, healthy PostgreSQL, and no acceptance-owned
campaign container or database left behind.
