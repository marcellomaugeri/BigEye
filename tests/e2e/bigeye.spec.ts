import AxeBuilder from '../../frontend/node_modules/@axe-core/playwright/dist/index.js';
import { expect, test, type Page } from '../../frontend/node_modules/@playwright/test/index.js';
import { createHash, randomBytes } from 'node:crypto';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { chmodSync, closeSync, cpSync, existsSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:net';
import { join, resolve } from 'node:path';

import { acceptanceCleanupDecision } from './acceptanceCleanup.js';

const ROOT = resolve(__dirname, '../..');
const E2E_ROOT = join(ROOT, 'workspace/e2e');
const SERVICE_ROOT = join(E2E_ROOT, 'services');
const SCREENSHOT_ROOT = join(E2E_ROOT, 'screenshots');
const RUNTIME_ROOT = join(ROOT, 'workspace/e2e/runtime');
const FIXTURE_SOURCE = join(ROOT, 'backend/tests/fixtures/whole_loop_project');
const ACCEPTANCE_DATABASE = `bigeye_acceptance_${process.pid}_${randomBytes(8).toString('hex')}`;
const SERVICE_TIMEOUT = 120_000;
const CAMPAIGN_TIMEOUT = 18 * 60_000;

type Project = {
  id: string;
  commit_sha: string | null;
  error: string | null;
};

type Campaign = {
  id: number;
  stopped_at: string | null;
  last_heartbeat_at: string | null;
  cpu_exposure_seconds: number;
  error: string | null;
};
type CoverageFile = { path: string; covered_lines: number; cpu_exposure_seconds: number };
type CoverageMeasurement = { covered: number; total: number; percent: number };
type Finding = {
  id: string;
  classification: string;
  priority_rank: number | null;
  priority_reason: string | null;
  description: string;
  occurrence_count: number;
  reproducible: boolean;
};
type ReplayVariant = {
  variant: string;
  crashed: boolean;
  signal: string | null;
  sanitizer: string | null;
  source_location: string | null;
  image_id: string;
  error: string | null;
};
type FindingDetail = Finding & {
  uncertainty: string;
  evidence_ids: string[];
  replay: {
    attempts: number;
    matching: number;
    compatible_variants: ReplayVariant[];
    clean_variant: ReplayVariant | null;
  };
};
type DebugEvent = {
  id: number;
  created_at: string;
  payload: {
    event?: string;
    agent?: string;
    model?: string;
    tool?: string;
    tool_call_id?: string;
  };
};

let backend: ChildProcess | null = null;
let repositoryServer: ChildProcess | null = null;
let projectId: string | null = null;
let acceptanceCommit: string | null = null;
let backendUrl = '';
let frontendUrl = '';
let repositoryUrl = '';
let databasePrepared = false;

function run(
  command: string, args: string[], cwd = ROOT, environment: NodeJS.ProcessEnv = process.env,
): string {
  const result = spawnSync(command, args, { cwd, encoding: 'utf-8', env: environment });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout.trim();
}

function service(
  command: string, args: string[], name: string, cwd = ROOT,
  environment: NodeJS.ProcessEnv = process.env,
): ChildProcess {
  mkdirSync(SERVICE_ROOT, { recursive: true, mode: 0o700 });
  const output = openSync(join(SERVICE_ROOT, `${name}.log`), 'a', 0o600);
  try {
    return spawn(command, args, {
      cwd,
      env: environment,
      detached: true,
      stdio: ['ignore', output, output],
    });
  } finally {
    closeSync(output);
  }
}

async function stop(child: ChildProcess | null): Promise<void> {
  const running = () => child !== null && child.exitCode === null && child.signalCode === null;
  if (!running() || child?.pid === undefined) return;
  const signalGroup = (signal: NodeJS.Signals) => {
    try {
      process.kill(-child.pid!, signal);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
    }
  };
  signalGroup('SIGTERM');
  await Promise.race([
    new Promise<void>((resolveExit) => child.once('exit', () => resolveExit())),
    new Promise<void>((resolveTimeout) => setTimeout(resolveTimeout, 10_000)),
  ]);
  if (running()) {
    signalGroup('SIGKILL');
    await Promise.race([
      new Promise<void>((resolveExit) => child.once('exit', () => resolveExit())),
      new Promise<void>((resolveTimeout) => setTimeout(resolveTimeout, 2_000)),
    ]);
  }
  if (running()) throw new Error(`Owned process group ${child.pid} did not stop.`);
}

async function availablePort(): Promise<number> {
  return await new Promise<number>((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close();
        reject(new Error('Could not allocate a loopback port.'));
        return;
      }
      server.close((error) => error ? reject(error) : resolvePort(address.port));
    });
  });
}

async function waitForOwnedHttp(
  child: ChildProcess, url: string, validate: (response: Response) => Promise<boolean>,
  timeout = SERVICE_TIMEOUT,
): Promise<void> {
  await expect.poll(async () => {
    if (child.exitCode !== null) throw new Error(`Owned service exited before ${url} was ready.`);
    try {
      return await validate(await fetch(url));
    } catch {
      return false;
    }
  }, { timeout, intervals: [100, 250, 500, 1_000] }).toBe(true);
}

async function api<T>(path: string): Promise<T> {
  const response = await fetch(`${backendUrl}${path}`);
  if (!response.ok) throw new Error(`GET ${path} returned ${response.status}`);
  return await response.json() as T;
}

function environmentValue(name: string, fallback: string): string {
  if (process.env[name]) return process.env[name]!;
  const envFile = readFileSync(join(ROOT, '.env'), 'utf-8');
  const line = envFile.split(/\r?\n/).find((candidate) => candidate.startsWith(`${name}=`));
  return line?.slice(name.length + 1) || fallback;
}

function composeArgs(...args: string[]): string[] {
  return ['compose', '-f', join(ROOT, 'compose.yaml'), ...args];
}

function prepareAcceptanceDatabase(): string {
  const user = environmentValue('POSTGRES_USER', 'bigeye');
  const password = environmentValue('POSTGRES_PASSWORD', 'bigeye');
  const port = environmentValue('BIGEYE_POSTGRES_PORT', '5433');
  run('docker', composeArgs('up', '-d', '--wait', 'postgres'));
  run('docker', composeArgs(
    'exec', '-T', 'postgres', 'psql', '-U', user, '-d', 'postgres', '--set', 'ON_ERROR_STOP=1',
    '--command', `CREATE DATABASE ${ACCEPTANCE_DATABASE};`,
  ));
  databasePrepared = true;
  run('docker', composeArgs(
    'exec', '-T', 'postgres', 'psql', '-U', user, '-d', ACCEPTANCE_DATABASE,
    '--set', 'ON_ERROR_STOP=1', '--file', '/docker-entrypoint-initdb.d/schema.sql',
  ));
  return `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}`
    + `@127.0.0.1:${port}/${ACCEPTANCE_DATABASE}`;
}

function dropAcceptanceDatabase(): void {
  if (!databasePrepared) return;
  const user = environmentValue('POSTGRES_USER', 'bigeye');
  run('docker', composeArgs(
    'exec', '-T', 'postgres', 'psql', '-U', user, '-d', 'postgres', '--set', 'ON_ERROR_STOP=1',
    '--command', `DROP DATABASE IF EXISTS ${ACCEPTANCE_DATABASE} WITH (FORCE);`,
  ));
  databasePrepared = false;
}

function acceptanceDatabaseScalar(sql: string): string {
  const user = environmentValue('POSTGRES_USER', 'bigeye');
  return run('docker', composeArgs(
    'exec', '-T', 'postgres', 'psql', '-U', user, '-d', ACCEPTANCE_DATABASE,
    '--set', 'ON_ERROR_STOP=1', '--quiet', '--tuples-only', '--no-align', '--command', sql,
  ));
}

function exactRunningCampaignContainers(campaignId: number): string[] {
  if (projectId === null || acceptanceCommit === null) {
    throw new Error('Acceptance project identity is unavailable for container inspection.');
  }
  const containers = run('docker', [
    'ps', '-q', '--filter', 'label=com.bigeye.managed=fuzz-campaign',
    '--filter', `label=com.bigeye.commit-sha=${acceptanceCommit}`,
    '--filter', `label=com.bigeye.project-id=${projectId}`,
    '--filter', `label=com.bigeye.campaign-id=${campaignId}`,
  ]).split('\n').filter(Boolean);
  for (const container of containers) {
    const inspections = JSON.parse(run('docker', ['inspect', container])) as unknown;
    if (!Array.isArray(inspections) || inspections.length !== 1) {
      throw new Error(`Container ${container} did not have one exact Docker inspection.`);
    }
    const decision = acceptanceCleanupDecision(inspections[0], {
      runtimeRoot: RUNTIME_ROOT,
      commitSha: acceptanceCommit,
      projectId,
    });
    const state = (inspections[0] as { State?: { Running?: unknown; Status?: unknown } }).State;
    if (!decision.removable || state?.Running !== true || state.Status !== 'running') {
      throw new Error(`Container ${container} is not an exact running acceptance campaign.`);
    }
  }
  return containers;
}

function makeTreeDeletable(root: string): void {
  if (!existsSync(root)) return;
  const details = lstatSync(root);
  if (details.isSymbolicLink() || !details.isDirectory()) return;
  chmodSync(root, 0o700);
  for (const name of readdirSync(root)) {
    const candidate = join(root, name);
    const child = lstatSync(candidate);
    if (child.isDirectory() && !child.isSymbolicLink()) makeTreeDeletable(candidate);
  }
}

function prepareRepository(): string {
  const source = join(SERVICE_ROOT, 'whole-loop-project');
  const served = join(SERVICE_ROOT, 'repositories');
  const bare = join(served, 'whole-loop-project.git');
  makeTreeDeletable(RUNTIME_ROOT);
  for (const path of [SERVICE_ROOT, SCREENSHOT_ROOT, RUNTIME_ROOT]) {
    rmSync(path, { recursive: true, force: true });
  }
  mkdirSync(source, { recursive: true, mode: 0o700 });
  mkdirSync(served, { recursive: true, mode: 0o700 });
  mkdirSync(RUNTIME_ROOT, { recursive: true, mode: 0o700 });
  cpSync(FIXTURE_SOURCE, source, { recursive: true, errorOnExist: true });
  run('git', ['init', '--initial-branch=main'], source);
  run('git', ['config', 'user.name', 'BigEye acceptance'], source);
  run('git', ['config', 'user.email', 'acceptance@bigeye.invalid'], source);
  run('git', ['add', '.'], source);
  run('git', ['commit', '-m', 'release acceptance fixture'], source);
  const trackedFiles = run('git', ['ls-tree', '-r', '--name-only', 'HEAD'], source).split('\n');
  for (const forbidden of ['Dockerfile', 'harness', 'dictionary', 'corpus']) {
    expect(trackedFiles.some((path) => path.toLowerCase().includes(forbidden.toLowerCase()))).toBe(false);
  }
  const commit = run('git', ['rev-parse', 'HEAD'], source);
  run('git', ['clone', '--bare', source, bare]);
  run('git', ['--git-dir', bare, 'update-server-info']);
  return commit;
}

function startBackend(port: number, databaseUrl: string): ChildProcess {
  const configuredOpenAIKey = environmentValue('OPENAI_API_KEY', '');
  if (!configuredOpenAIKey) throw new Error('OPENAI_API_KEY is required for release acceptance.');
  return service(
    'backend/.venv/bin/python',
    ['-m', 'backend.run', '--no-browser', '--port', String(port)],
    'backend', ROOT,
    {
      ...process.env,
      OPENAI_API_KEY: configuredOpenAIKey,
      DATABASE_URL: databaseUrl,
      BIGEYE_WORKSPACE: RUNTIME_ROOT,
    },
  );
}

async function assertNoSeriousAccessibilityViolations(page: Page): Promise<void> {
  const result = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  expect(result.violations, JSON.stringify(result.violations, null, 2)).toEqual([]);
}

async function openPrimaryView(page: Page, name: string): Promise<void> {
  const heading = name === 'Source' ? 'Source assurance' : name;
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name, exact: true }).click();
  await expect(page.getByRole('heading', { name: heading }).first()).toBeVisible();
  await assertNoSeriousAccessibilityViolations(page);
}

function regularFileDigests(root: string): string[] {
  if (!existsSync(root)) return [];
  const values: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path).sort()) {
      const candidate = join(path, name);
      const details = statSync(candidate);
      if (details.isDirectory()) visit(candidate);
      if (details.isFile()) {
        const relative = candidate.slice(root.length + 1);
        values.push(`${relative}:${createHash('sha256').update(readFileSync(candidate)).digest('hex')}`);
      }
    }
  };
  visit(root);
  return values;
}

test.describe.serial('BigEye autonomous release acceptance', () => {
  test.afterAll(async () => {
    const cleanupFailures: unknown[] = [];
    const attempt = async (action: () => void | Promise<void>) => {
      try {
        await action();
      } catch (error) {
        cleanupFailures.push(error);
      }
    };
    const backendForShutdown = backend;
    let backendStopped = false;
    await attempt(async () => {
      await stop(backendForShutdown);
      backend = null;
      backendStopped = true;
    });
    if (backendStopped && acceptanceCommit !== null) {
      let containers: string[] = [];
      await attempt(() => {
        containers = run('docker', [
          'ps', '-aq', '--filter', 'label=com.bigeye.managed=fuzz-campaign',
          '--filter', `label=com.bigeye.commit-sha=${acceptanceCommit}`,
        ]).split('\n').filter(Boolean);
      });
      for (const container of containers) {
        await attempt(() => {
          const inspections = JSON.parse(run('docker', ['inspect', container])) as unknown;
          if (!Array.isArray(inspections) || inspections.length !== 1) {
            throw new Error(`Refusing to remove ${container}: Docker inspection was not singular.`);
          }
          const decision = acceptanceCleanupDecision(inspections[0], {
            runtimeRoot: RUNTIME_ROOT,
            commitSha: acceptanceCommit!,
            projectId,
          });
          if (!decision.removable) {
            throw new Error(`Refusing to remove ${container}: ${decision.reason}.`);
          }
          run('docker', ['rm', '-f', container]);
        });
      }
      await attempt(() => {
        const remainingContainers = run('docker', [
          'ps', '-aq', '--filter', 'label=com.bigeye.managed=fuzz-campaign',
          '--filter', `label=com.bigeye.commit-sha=${acceptanceCommit}`,
        ]).split('\n').filter(Boolean);
        if (remainingContainers.length !== 0) {
          throw new Error(`Acceptance campaign containers remain: ${remainingContainers.join(', ')}.`);
        }
      });
    } else if (!backendStopped && acceptanceCommit !== null) {
      cleanupFailures.push(new Error(
        'BigEye is refusing Docker cleanup because the backend did not stop.',
      ));
    }
    await attempt(() => stop(repositoryServer));
    await attempt(() => { dropAcceptanceDatabase(); });
    if (cleanupFailures.length > 0) {
      throw new AggregateError(cleanupFailures, 'BigEye acceptance cleanup failed.');
    }
  });

  test('runs the complete real project, evidence, restart and accessibility journey', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    acceptanceCommit = prepareRepository();
    const exactCommit = acceptanceCommit;
    const [backendPort, repositoryPort] = await Promise.all([availablePort(), availablePort()]);
    backendUrl = `http://127.0.0.1:${backendPort}`;
    frontendUrl = backendUrl;
    repositoryUrl = `http://127.0.0.1:${repositoryPort}/whole-loop-project.git`;
    const databaseUrl = prepareAcceptanceDatabase();

    repositoryServer = service(
      'python3.14', ['-m', 'http.server', String(repositoryPort), '--bind', '127.0.0.1', '--directory', join(SERVICE_ROOT, 'repositories')],
      'repository',
    );
    backend = startBackend(backendPort, databaseUrl);
    await Promise.all([
      waitForOwnedHttp(repositoryServer, `${repositoryUrl}/HEAD`, async (response) => (
        response.status === 200 && (await response.text()).includes('refs/heads/main')
      )),
      waitForOwnedHttp(backend, `${backendUrl}/api/projects`, async (response) => (
        response.status === 200 && JSON.stringify(await response.json()) === '[]'
      )),
    ]);

    await page.setViewportSize({ width: 1440, height: 1000 });
    mkdirSync(SCREENSHOT_ROOT, { recursive: true, mode: 0o700 });
    await page.goto(frontendUrl);
    const intro = page.getByRole('status', { name: 'BigEye is starting' });
    await expect(intro).toBeVisible();
    await expect(page.getByLabel('BigEye logo placeholder')).toBeVisible();
    await expect(page.getByRole('progressbar', { name: 'Loading BigEye' })).toBeVisible();
    await page.screenshot({ path: join(SCREENSHOT_ROOT, 'first-visit-intro.png'), fullPage: true });
    await expect(intro).toBeHidden();
    expect(await page.evaluate(() => window.localStorage.getItem('bigeye.intro.seen.v1'))).toBe('1');

    await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
    await expect(page.locator('.project-picker')).toHaveCount(0);
    const newProject = page.getByRole('button', { name: 'New project' });
    await expect(newProject).toBeVisible();
    await page.screenshot({ path: join(SCREENSHOT_ROOT, 'before-project-desktop.png'), fullPage: true });
    await assertNoSeriousAccessibilityViolations(page);

    await newProject.click();
    await expect(page.getByRole('dialog', { name: 'New project' })).toBeVisible();

    const privateRepository = page.getByRole('button', { name: 'Private repository', exact: true });
    await privateRepository.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByLabel('Read-only access token')).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(page.getByLabel('Read-only access token')).toBeHidden();

    await page.getByLabel('Repository URL').fill(repositoryUrl);
    await page.getByLabel('Revision').fill(exactCommit);
    await page.getByLabel('Worker count').fill('4');
    await page.getByRole('button', { name: 'Start project' }).click();
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    const projects = await api<Project[]>('/api/projects');
    expect(projects).toHaveLength(1);
    projectId = projects[0].id;

    await expect.poll(async () => (await api<Project>(`/api/projects/${projectId}`)).commit_sha, {
      timeout: CAMPAIGN_TIMEOUT, intervals: [500, 1_000, 2_000],
    }).toBe(exactCommit);
    await expect.poll(async () => (await api<Project>(`/api/projects/${projectId}`)).error, {
      timeout: CAMPAIGN_TIMEOUT, intervals: [500, 1_000],
    }).toBeNull();

    await expect.poll(async () => {
      const activity = await api<{ events: Array<{ payload: Record<string, unknown> }> }>(
        `/api/projects/${projectId}/logs/activity?before=-1&limit=100`,
      );
      return activity.events.some((event) => (
        event.payload.decision === 'target preparation accepted'
        && typeof event.payload.motivation === 'string'
      ));
    }, { timeout: CAMPAIGN_TIMEOUT, intervals: [1_000, 2_000, 5_000] }).toBe(true);

    let campaigns: Campaign[] = [];
    await expect.poll(async () => {
      const value = await api<{ campaigns: Campaign[] }>(`/api/projects/${projectId}/campaigns`);
      campaigns = value.campaigns;
      const healthy = campaigns.filter((campaign) => campaign.stopped_at === null && campaign.error === null);
      const engines = new Set(healthy.map((campaign) => campaign.engine));
      return healthy.length <= 4 && engines.has('afl') && engines.has('libfuzzer');
    }, { timeout: CAMPAIGN_TIMEOUT, intervals: [1_000, 2_000, 5_000] }).toBe(true);
    const activeFuzzingCampaign = campaigns.find(
      (campaign) => campaign.engine === 'afl' && campaign.stopped_at === null && campaign.error === null,
    );
    expect(activeFuzzingCampaign).toBeDefined();
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Current focus' })).toBeVisible();
    await expect(page.getByText(/Last observed|Configured/).first()).toBeVisible();
    await openPrimaryView(page, 'Fuzzing');
    const fuzzingTable = page.getByRole('table', { name: 'Autonomous fuzzing campaigns' });
    await expect(fuzzingTable).toBeVisible();
    await expect(fuzzingTable.getByRole('row')).toHaveCount(campaigns.length + 1);
    await openPrimaryView(page, 'Overview');

    let coverageFiles: CoverageFile[] = [];
    let lineCoverage: CoverageMeasurement | null = null;
    let branchCoverage: CoverageMeasurement | null = null;
    await expect.poll(async () => {
      const coverage = await api<{
        files: CoverageFile[];
        summary: { lines: CoverageMeasurement | null; branches: CoverageMeasurement | null };
      }>(`/api/projects/${projectId}/coverage/tree`);
      coverageFiles = coverage.files;
      lineCoverage = coverage.summary.lines;
      branchCoverage = coverage.summary.branches;
      return coverageFiles.some((file) => (
        file.covered_lines > 0 && file.cpu_exposure_seconds > 0
      )) && lineCoverage !== null && lineCoverage.covered > 0
        && branchCoverage !== null && branchCoverage.covered > 0;
    }, { timeout: CAMPAIGN_TIMEOUT, intervals: [1_000, 2_000, 5_000] }).toBe(true);
    expect(lineCoverage!.total).toBeGreaterThanOrEqual(lineCoverage!.covered);
    expect(branchCoverage!.total).toBeGreaterThanOrEqual(branchCoverage!.covered);

    const ownedAflCrashRoot = join(
      RUNTIME_ROOT, 'projects', projectId, 'campaigns', String(activeFuzzingCampaign!.id),
      'output', 'main', 'crashes',
    );
    let ownedAflCrashArtifacts: string[] = [];
    await expect.poll(() => {
      ownedAflCrashArtifacts = regularFileDigests(ownedAflCrashRoot).filter(
        (value) => !value.startsWith('README.txt:'),
      );
      return new Set(ownedAflCrashArtifacts.map(
        (value) => value.slice(value.lastIndexOf(':') + 1),
      )).size;
    }, { timeout: CAMPAIGN_TIMEOUT, intervals: [1_000, 2_000, 5_000] }).toBeGreaterThanOrEqual(2);

    let findings: Finding[] = [];
    await expect.poll(async () => {
      const value = await api<{ items: Finding[] }>(`/api/projects/${projectId}/findings`);
      findings = value.items;
      return findings.length === 1
        && findings[0].reproducible
        && findings[0].occurrence_count >= 2
        && findings[0].classification === 'true vulnerability'
        && findings[0].priority_rank === 1;
    }, { timeout: CAMPAIGN_TIMEOUT, intervals: [1_000, 2_000, 5_000] }).toBe(true);
    const groupedFinding = findings[0];
    expect(groupedFinding.priority_reason).toContain('true vulnerability');
    expect(groupedFinding.priority_reason).toContain('reproducible');
    expect(groupedFinding.priority_reason).toContain(`observed ${groupedFinding.occurrence_count}`);
    expect(groupedFinding.description.trim().length).toBeGreaterThan(0);
    const findingDetail = await api<FindingDetail>(
      `/api/projects/${projectId}/findings/${groupedFinding.id}`,
    );
    expect(findingDetail.classification).toBe(groupedFinding.classification);
    expect(findingDetail.priority_rank).toBe(groupedFinding.priority_rank);
    expect(findingDetail.description).toBe(groupedFinding.description);
    expect(findingDetail.uncertainty.trim().length).toBeGreaterThan(0);
    expect(findingDetail.replay.attempts).toBeGreaterThanOrEqual(2);
    expect(findingDetail.replay.matching).toBe(findingDetail.replay.attempts);
    for (const variant of findingDetail.replay.compatible_variants) {
      expect(variant.image_id).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(variant.error).toBeNull();
    }
    expect(findingDetail.replay.clean_variant).not.toBeNull();
    expect(findingDetail.replay.clean_variant?.image_id).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(findingDetail.evidence_ids.some((identifier) => (
      identifier.startsWith('replay:original:')
    ))).toBe(true);
    expect(findingDetail.evidence_ids.includes('replay:clean')).toBe(true);

    const configuredOpenAIKey = environmentValue('OPENAI_API_KEY', '');
    expect(configuredOpenAIKey.length).toBeGreaterThan(0);
    let debugPage = await api<{ events: DebugEvent[]; next_offset: number; has_more: boolean }>(
      `/api/projects/${projectId}/logs/debug?before=-1&limit=1000`,
    );
    const debugEvents = [...debugPage.events];
    for (let pageCount = 1; debugPage.has_more && pageCount < 20; pageCount += 1) {
      debugPage = await api<{ events: DebugEvent[]; next_offset: number; has_more: boolean }>(
        `/api/projects/${projectId}/logs/debug?before=${debugPage.next_offset}&limit=1000`,
      );
      debugEvents.push(...debugPage.events);
    }
    expect(debugPage.has_more).toBe(false);
    const lifecycle = new Set(debugEvents.map((event) => event.payload.event));
    for (const expected of ['agent.start', 'agent.end', 'model.start', 'model.end', 'tool.start', 'tool.end']) {
      expect(lifecycle.has(expected)).toBe(true);
    }
    expect(debugEvents.some((event) => event.payload.agent && event.payload.model)).toBe(true);
    expect(debugEvents.some((event) => event.payload.tool)).toBe(true);
    expect(JSON.stringify(debugEvents).includes(configuredOpenAIKey)).toBe(false);
    const orderedDebugEvents = [...debugEvents].sort((left, right) => left.id - right.id);
    const activeWorkerCalls = new Set<string>();
    let workerStarts = 0;
    let maximumConcurrentWorkerCalls = 0;
    for (const event of orderedDebugEvents) {
      const callId = event.payload.tool_call_id;
      if (event.payload.tool !== 'run_fuzzing_worker' || !callId) continue;
      if (event.payload.event === 'tool.start') {
        workerStarts += 1;
        activeWorkerCalls.add(callId);
        maximumConcurrentWorkerCalls = Math.max(
          maximumConcurrentWorkerCalls, activeWorkerCalls.size,
        );
      } else if (event.payload.event === 'tool.end') {
        activeWorkerCalls.delete(callId);
      }
    }
    expect(workerStarts).toBeGreaterThanOrEqual(2);
    expect(maximumConcurrentWorkerCalls).toBeGreaterThanOrEqual(2);

    await openPrimaryView(page, 'Activity');
    await expect(page.getByRole('heading', { name: 'Why BigEye changed this strategy' }).first()).toBeVisible();
    const activityTab = page.getByRole('tab', { name: 'Activity', exact: true });
    await activityTab.focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.getByRole('tab', { name: 'Debug', exact: true })).toBeFocused();
    await expect(page.getByRole('heading', { name: 'Advanced local debug evidence' })).toBeVisible();
    await expect(page.getByText('Raw sanitized JSON').first()).toBeVisible();

    await openPrimaryView(page, 'Source');
    const coveredFile = coverageFiles.find((file) => (
      file.covered_lines > 0 && file.cpu_exposure_seconds > 0
    ))!;
    expect(coveredFile.cpu_exposure_seconds > 0).toBe(true);
    await page.getByRole('button', { name: coveredFile.path, exact: true }).click();
    const coveredLine = page.getByRole('button', { name: /Line \d+, covered,/ }).first();
    await coveredLine.click();
    const coveredLineLabel = await coveredLine.getAttribute('aria-label');
    const coveredLineMatch = /^Line ([1-9]\d*), covered,/.exec(coveredLineLabel ?? '');
    expect(coveredLineMatch).not.toBeNull();
    const coveredLineNumber = Number(coveredLineMatch![1]);
    const lineQuery = new URLSearchParams({ path: coveredFile.path });
    const lineEvidence = await api<{
      evidence: Array<{ strategy_asset_id: number; cpu_exposure_seconds: number }>;
    }>(`/api/projects/${projectId}/coverage/lines/${coveredLineNumber}?${lineQuery}`);
    expect(lineEvidence.evidence.length).toBeGreaterThan(0);
    expect(lineEvidence.evidence.every((item) => item.cpu_exposure_seconds >= 0)).toBe(true);
    expect(lineEvidence.evidence.some((item) => item.cpu_exposure_seconds > 0)).toBe(true);

    const strategyFilter = page.getByRole('combobox', { name: 'Reaching strategy' });
    await expect(strategyFilter).toBeVisible();
    const strategyOptions = strategyFilter.locator('option');
    expect(await strategyOptions.count()).toBeGreaterThan(1);
    const strategyValue = await strategyOptions.nth(1).getAttribute('value');
    const strategyLabel = (await strategyOptions.nth(1).textContent())?.trim() ?? '';
    expect(strategyValue).not.toBeNull();
    expect(strategyLabel.length).toBeGreaterThan(0);
    await strategyFilter.selectOption(strategyValue!);
    await expect(strategyFilter).toHaveValue(strategyValue!);
    const testcase = page.getByRole('link', {
      name: `Download first testcase for ${strategyLabel}`,
    }).first();
    await expect(testcase).toBeVisible();
    const testcaseHref = await testcase.getAttribute('href');
    expect(testcaseHref).not.toBeNull();
    const testcaseResponse = await page.request.get(new URL(testcaseHref!, page.url()).toString());
    expect(testcaseResponse.ok()).toBe(true);
    expect((await testcaseResponse.body()).byteLength).toBeGreaterThan(0);

    await openPrimaryView(page, 'Findings');
    await expect(page.getByRole('navigation', { name: 'Replayed findings' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Download minimal reproducer' })).toBeVisible();
    await expect(page.getByText(`${findings[0].occurrence_count} occurrence`, { exact: false })).toBeVisible();
    await page.getByRole('button', { name: 'Reproduce finding' }).click();
    const reproduction = page.getByRole('log', { name: 'Finding reproduction output' });
    await expect(reproduction).toBeVisible();
    await expect(reproduction).toContainText('AddressSanitizer', { timeout: SERVICE_TIMEOUT });
    await expect(reproduction).toContainText('decoder.c:36');
    await expect(reproduction).toContainText('/finding/input');
    await expect(reproduction).toContainText(
      /(?:Completed: exited \(exit [1-9]\d*\)|Reproduced: AddressSanitizer crash reproduced; emulator cleanup timed out)/,
    );
    await expect(reproduction).not.toContainText('cannot open input');
    expect((await reproduction.textContent())?.trim().length).toBeGreaterThan(9);
    expect(run('docker', [
      'ps', '-aq', '--filter', 'label=com.bigeye.managed=finding-reproduction',
      '--filter', `label=com.bigeye.project_id=${projectId}`,
      '--filter', `label=com.bigeye.finding_id=${findings[0].id}`,
    ])).toBe('');

    await openPrimaryView(page, 'Settings');
    await expect(page.getByLabel('Commit')).toHaveValue(exactCommit);
    await openPrimaryView(page, 'Projects');
    await openPrimaryView(page, 'Overview');

    expect(projectId).toMatch(/^[1-9]\d*$/);
    const persistedDeadline = acceptanceDatabaseScalar(
      `SELECT manager_wake_at IS NOT NULL AND manager_wake_reason IS NOT NULL FROM projects WHERE id = ${projectId};`,
    );
    expect(persistedDeadline).toBe('t');

    const allowedColours = new Set([
      'rgb(16, 16, 16)', 'rgb(255, 255, 255)', 'rgb(200, 30, 42)',
      'rgb(245, 242, 237)', 'rgb(95, 95, 95)', 'rgba(0, 0, 0, 0)',
    ]);
    const observedColours = await page.locator('body *').evaluateAll((elements) => (
      [...new Set(elements.flatMap((element) => {
        const style = getComputedStyle(element);
        return [style.color, style.backgroundColor, style.borderTopColor, style.borderRightColor, style.borderBottomColor, style.borderLeftColor];
      }))]
    ));
    expect(observedColours.filter((colour) => !allowedColours.has(colour))).toEqual([]);
    expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
    const transitionSeconds = await page.locator('.work-surface').evaluate((element) => (
      Number.parseFloat(getComputedStyle(element).transitionDuration)
    ));
    expect(transitionSeconds).toBeLessThanOrEqual(0.00001);
    await expect(page.getByRole('table', { name: 'Source coverage list' })).toBeVisible();
    await page.screenshot({ path: join(SCREENSHOT_ROOT, 'after-evidence-desktop.png'), fullPage: true });

    await openPrimaryView(page, 'Settings');
    const campaignStateBeforeRestart = await api<{ campaigns: Campaign[] }>(
      `/api/projects/${projectId}/campaigns`,
    );
    const campaignBeforeRestart = campaignStateBeforeRestart.campaigns.find((campaign) => (
      campaign.stopped_at === null && campaign.error === null
    ))!;
    expect(campaignBeforeRestart).toBeDefined();
    expect(campaignBeforeRestart.last_heartbeat_at).not.toBeNull();
    const heartbeatBeforeRestart = campaignBeforeRestart.last_heartbeat_at;
    const cpuBeforeRestart = campaignBeforeRestart.cpu_exposure_seconds;

    const activeCampaign = campaignBeforeRestart;
    const corpus = join(RUNTIME_ROOT, 'projects', projectId, 'campaigns', String(activeCampaign.id), 'corpus');
    const corpusBeforeRestart = regularFileDigests(corpus);
    expect(corpusBeforeRestart.length).toBeGreaterThan(0);
    const findingsBeforeRestart = (await api<{ items: Finding[] }>(`/api/projects/${projectId}/findings`)).items;
    const coverageBeforeRestart = (await api<{ files: CoverageFile[] }>(`/api/projects/${projectId}/coverage/tree`)).files;
    const managerStartsBeforeRestart = debugEvents.filter((event) => (
      event.payload.event === 'model.start' && event.payload.agent === 'Campaign manager'
    )).length;
    expect(acceptanceDatabaseScalar(
      `UPDATE projects SET manager_wake_at = NOW() - INTERVAL '1 second', manager_wake_reason = 'forced overdue acceptance wake' WHERE id = ${projectId} RETURNING manager_wake_at < NOW();`,
    )).toBe('t');

    await stop(backend);
    backend = null;
    backend = startBackend(backendPort, databaseUrl);
    await waitForOwnedHttp(backend, `${backendUrl}/api/projects/${projectId}`, async (response) => response.status === 200);
    await page.reload();
    expect((await api<Project>(`/api/projects/${projectId}`)).commit_sha).toBe(exactCommit);
    expect(regularFileDigests(corpus)).toEqual(corpusBeforeRestart);
    expect((await api<{ items: Finding[] }>(`/api/projects/${projectId}/findings`)).items).toEqual(findingsBeforeRestart);
    const coverageAfterRestart = (
      await api<{ files: CoverageFile[] }>(`/api/projects/${projectId}/coverage/tree`)
    ).files;
    for (const before of coverageBeforeRestart) {
      const after = coverageAfterRestart.find((file) => file.path === before.path);
      expect(after).toBeDefined();
      expect(after!.covered_lines).toBeGreaterThanOrEqual(before.covered_lines);
      expect(after!.cpu_exposure_seconds).toBeGreaterThanOrEqual(before.cpu_exposure_seconds);
    }
    await expect.poll(async () => {
      const current = await api<{ events: DebugEvent[] }>(
        `/api/projects/${projectId}/logs/debug?before=-1&limit=1000`,
      );
      return current.events.filter((event) => (
        event.payload.event === 'model.start' && event.payload.agent === 'Campaign manager'
      )).length;
    }, { timeout: CAMPAIGN_TIMEOUT, intervals: [1_000, 2_000, 5_000] }).toBeGreaterThan(
      managerStartsBeforeRestart,
    );

    await expect.poll(async () => {
      const resumedProject = await api<Project>(`/api/projects/${projectId}`);
      const resumedCampaigns = (
        await api<{ campaigns: Campaign[] }>(`/api/projects/${projectId}/campaigns`)
      ).campaigns;
      const resumedCampaign = resumedCampaigns.find((campaign) => (
        campaign.stopped_at === null && campaign.error === null
      ));
      if (resumedProject.error !== null || resumedCampaign === undefined) return false;
      const heartbeatAdvanced = resumedCampaign.last_heartbeat_at !== null && (
        heartbeatBeforeRestart === null
        || Date.parse(resumedCampaign.last_heartbeat_at) > Date.parse(heartbeatBeforeRestart)
      );
      const cpuAdvanced = resumedCampaign.cpu_exposure_seconds > cpuBeforeRestart;
      const exactContainers = exactRunningCampaignContainers(resumedCampaign.id);
      return resumedCampaigns.some((campaign) => campaign.id === resumedCampaign.id)
        && exactContainers.length === 1
        && (heartbeatAdvanced || cpuAdvanced);
    }, { timeout: CAMPAIGN_TIMEOUT, intervals: [1_000, 2_000, 5_000] }).toBe(true);

    await page.setViewportSize({ width: 390, height: 844 });
    for (const view of ['Overview', 'Fuzzing', 'Findings']) {
      await openPrimaryView(page, view);
      expect(await page.evaluate(() => (
        document.documentElement.scrollWidth <= document.documentElement.clientWidth
      ))).toBe(true);
    }
    const managerFooter = page.locator('.manager-activity-footer button');
    await expect(managerFooter).toHaveCSS('white-space', 'nowrap');
    await expect(managerFooter).toHaveCSS('overflow', 'hidden');
    await expect(managerFooter).toHaveCSS('text-overflow', 'ellipsis');
    await page.screenshot({ path: join(SCREENSHOT_ROOT, 'after-restart-mobile.png'), fullPage: true });
  });
});
