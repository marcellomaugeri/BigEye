import { expect, test, type APIRequestContext, type Page } from '../../frontend/node_modules/@playwright/test/index.js';

const BASE_URL = (process.env.BIGEYE_E2E_BASE_URL ?? 'http://127.0.0.1:8000').replace(/\/$/, '');
const LIBAOM_REPOSITORY = 'https://aomedia.googlesource.com/aom';
const LIBAOM_REVISION = 'ad44980d7f3c7a2605c25d51ea96946949000841';

type Project = {
  id: string;
  repository_url: string;
  requested_revision: string;
  commit_sha: string | null;
  error: string | null;
};

type Campaign = {
  id: number;
  engine: string;
  stopped_at: string | null;
  last_heartbeat_at: string | null;
  cpu_exposure_seconds: number;
  error: string | null;
};

async function api<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${BASE_URL}${path}`);
  expect(response.ok(), `GET ${path} returned ${response.status()}`).toBe(true);
  return await response.json() as T;
}

async function openView(page: Page, name: string): Promise<void> {
  const heading = name === 'Source' ? 'Source assurance' : name;
  await page.getByRole('navigation', { name: 'Main navigation' })
    .getByRole('link', { name, exact: true }).click();
  await expect(page.getByRole('heading', { name: heading }).first()).toBeVisible();
}

test('observes the live libaom hour without controlling the campaign', async ({ page, request }) => {
  const projects = await api<Project[]>(request, '/api/projects');
  const project = projects.find((candidate) => (
    candidate.repository_url === LIBAOM_REPOSITORY
    && candidate.requested_revision === LIBAOM_REVISION
    && candidate.commit_sha === LIBAOM_REVISION
    && candidate.error === null
  ));
  expect(project, 'Run scripts/run_libaom_acceptance.py before the UI observer.').toBeDefined();

  const initial = await api<{ campaigns: Campaign[] }>(
    request, `/api/projects/${project!.id}/campaigns`,
  );
  const active = initial.campaigns.filter((campaign) => (
    campaign.stopped_at === null && campaign.error === null
    && campaign.last_heartbeat_at !== null
  ));
  expect(active.length).toBeGreaterThan(0);
  const initialById = new Map(active.map((campaign) => [campaign.id, campaign]));

  const coverage = await api<{
    commit_sha: string;
    summary: {
      lines: { covered: number; total: number } | null;
      branches: { covered: number; total: number } | null;
    };
  }>(request, `/api/projects/${project!.id}/coverage/tree`);
  expect(coverage.commit_sha).toBe(LIBAOM_REVISION);
  expect(coverage.summary.lines?.covered).toBeGreaterThan(0);
  expect(coverage.summary.branches?.covered).toBeGreaterThan(0);

  await page.addInitScript(() => window.localStorage.setItem('bigeye.intro.seen.v1', '1'));
  await page.goto(`${BASE_URL}/#projects`);
  await page.getByRole('list', { name: 'Projects' }).getByRole('button')
    .filter({ hasText: LIBAOM_REPOSITORY }).filter({ hasText: LIBAOM_REVISION }).click();

  await openView(page, 'Overview');
  await expect(page.getByText(/active heavy jobs?/).first()).toBeVisible();
  await openView(page, 'Fuzzing');
  await expect(page.getByRole('table', { name: 'Autonomous fuzzing campaigns' })).toBeVisible();
  await openView(page, 'Source');
  await expect(page.getByRole('list', { name: 'Source assurance files' })).toBeVisible();
  await openView(page, 'Findings');
  await openView(page, 'Activity');
  await expect(page.getByRole('contentinfo', { name: 'Current manager activity' })).toBeVisible();

  const activity = await api<{ events: object[] }>(
    request, `/api/projects/${project!.id}/logs/activity?before=-1&limit=100`,
  );
  expect(activity.events.length).toBeGreaterThan(0);

  await expect.poll(async () => {
    const current = await api<{ campaigns: Campaign[] }>(
      request, `/api/projects/${project!.id}/campaigns`,
    );
    return current.campaigns.some((campaign) => {
      const before = initialById.get(campaign.id);
      return before !== undefined && campaign.stopped_at === null && campaign.error === null
        && (campaign.cpu_exposure_seconds > before.cpu_exposure_seconds
          || campaign.last_heartbeat_at !== before.last_heartbeat_at);
    });
  }, { timeout: 120_000, intervals: [5_000, 10_000] }).toBe(true);
});
