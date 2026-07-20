import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { useProjectOverview, type ProjectOverviewModel } from './controllers/useProjectOverview';
import type { Project } from './models/project';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from './services/eventStream';
import { OverviewView } from './views/OverviewView';

const project: Project = {
  id: '7', repository_url: 'https://github.com/acme/parser.git', requested_revision: 'stable',
  worker_count: 2, commit_sha: 'a'.repeat(40), token_present: false,
  created_at: '2026-07-20T08:00:00Z', paused_at: null, error: null
};

const campaigns = {
  project_id: 7,
  project_paused: false,
  campaigns: [{
    id: 4, target_asset_id: 31, target_name: 'Parser input path',
    configuration_asset_id: 32, configuration_name: 'Encrypted mode', engine: 'AFL++',
    started_at: '2026-07-20T08:00:00Z', stopped_at: null,
    last_heartbeat_at: '2026-07-20T09:00:00Z', cpu_exposure_seconds: 5400,
    next_review_after: '2026-07-20T10:00:00Z',
    next_review_reason: 'Coverage is still increasing in the parser.', error: null,
    configuration_purpose: 'Exercise encrypted parser input.', retirement_reason: null,
    reached_line_count: 16, unique_line_count: 12, overlapping_line_count: 4,
  }],
  assets: [{ id: 33, kind: 'strategy', name: 'Parser strategy', parent_id: 31 }]
};

const coverage = {
  project_id: 7, commit_sha: 'a'.repeat(40),
  files: [
    { path: 'src/parser/message.c', covered_lines: 12, cpu_exposure_seconds: 5400 },
    { path: 'src/parser/token.c', covered_lines: 4, cpu_exposure_seconds: 1800 },
    { path: 'src/io/socket.c', covered_lines: 3, cpu_exposure_seconds: 900 }
  ],
  pagination: { limit: 1000, offset: 0, total: 3 }
};

function viewModel(overrides: Partial<ProjectOverviewModel> = {}): ProjectOverviewModel {
  return {
    project, campaigns, coverage, findingCount: 2, findingsHaveMore: false,
    loading: false, pauseChanging: false, error: null,
    onTogglePause: vi.fn(), ...overrides
  };
}

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn(), listProjects: vi.fn().mockResolvedValue([project]),
    getProject: vi.fn().mockResolvedValue(project), getProjectSettings: vi.fn(),
    updateProjectSettings: vi.fn(), pauseProject: vi.fn().mockResolvedValue({ ...project, paused_at: '2026-07-20T09:00:00Z' }),
    resumeProject: vi.fn().mockResolvedValue(project), listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(), getSettings: vi.fn(), listCampaigns: vi.fn().mockResolvedValue(campaigns),
    getCoverageTree: vi.fn().mockResolvedValue(coverage), getSourceFile: vi.fn(), getLineEvidence: vi.fn(),
    retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [{ id: '1' }, { id: '2' }], next_cursor: null }),
    getFinding: vi.fn(), findingReproducerUrl: vi.fn(), getProjectLog: vi.fn(),
    ...overrides
  } as BigEyeApi;
}

function eventStream(): ProjectEventStream {
  return { subscribe: vi.fn().mockReturnValue(() => undefined) };
}

describe('Overview', () => {
  afterEach(() => { window.history.replaceState(null, '', '/'); });

  it('prioritises current focus and truthful covered-line evidence over technical metadata', async () => {
    const user = userEvent.setup();
    render(<OverviewView model={viewModel()} />);

    expect(screen.getByRole('heading', { name: 'Current focus' })).toBeVisible();
    const currentFocus = screen.getByRole('heading', { name: 'Current focus' }).closest('section')!;
    expect(within(currentFocus).getByText('Parser input path')).toBeVisible();
    expect(screen.getByText('Coverage is still increasing in the parser.')).toBeVisible();
    expect(within(currentFocus).getByText(/Last observed/)).toBeVisible();
    expect(screen.queryByText(/running/i)).not.toBeInTheDocument();
    expect(screen.getByText('2 replayed findings')).toBeVisible();
    expect(screen.getByText('12 covered lines')).toBeVisible();
    expect(screen.getByText('1.5 CPU exposure hours')).toBeVisible();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
    expect(screen.queryByText(/gpt-5.6|luna|terra/i)).not.toBeInTheDocument();

    const table = screen.getByRole('table', { name: 'Source coverage list' });
    expect(within(table).getByText('src/parser/message.c')).toBeVisible();
    await user.click(screen.getByText('Technical details'));
    expect(screen.getByText('AFL++')).toBeVisible();
  });

  it('shows persisted campaign evidence and retirement rationale without inferring running state', () => {
    const modelCampaigns = {
      ...campaigns,
      campaigns: [
        ...campaigns.campaigns,
        { ...campaigns.campaigns[0], id: 5, target_name: 'Stopped decoder', configuration_name: 'Legacy mode', stopped_at: '2026-07-20T09:10:00Z', retirement_reason: 'Its clean reach remained a subset.' },
        { ...campaigns.campaigns[0], id: 6, target_name: 'Broken socket', configuration_name: null, error: 'failed' },
      ],
      assets: [
        ...campaigns.assets,
        { id: 34, kind: 'strategy', name: 'Inactive orphan strategy', parent_id: 31 },
      ],
    };

    render(<OverviewView model={viewModel({ campaigns: modelCampaigns })} />);

    const evidence = screen.getByRole('heading', { name: 'Campaign evidence' }).closest('section')!;
    const parserEvidence = within(evidence).getByText('Parser input path').closest('li')!;
    expect(within(parserEvidence).getByText('Encrypted mode')).toBeVisible();
    expect(within(parserEvidence).getByText('12 unique lines')).toBeVisible();
    expect(within(parserEvidence).getByText('4 overlapping lines')).toBeVisible();
    expect(within(evidence).getByText('Stopped decoder')).toBeVisible();
    expect(within(evidence).getByText('Its clean reach remained a subset.')).toBeVisible();
    expect(within(evidence).getByText('Broken socket')).toBeVisible();
    expect(within(evidence).queryByText('Inactive orphan strategy')).not.toBeInTheDocument();
    expect(within(evidence).queryByText(/running/i)).not.toBeInTheDocument();
  });

  it('uses the server-backed project pause fact instead of labelling configured campaigns as running', () => {
    render(<OverviewView model={viewModel({
      project: { ...project, paused_at: '2026-07-20T09:30:00Z' },
      campaigns: { ...campaigns, project_paused: true },
    })} />);

    expect(screen.getAllByText('Paused').length).toBeGreaterThan(0);
    expect(screen.queryByText(/running/i)).not.toBeInTheDocument();
  });

  it('treats absent clean coverage as an empty map without reporting an outage', async () => {
    const emptyCoverage = { ...coverage, files: [], pagination: { ...coverage.pagination, total: 0 } };
    const api = apiDouble({ getCoverageTree: vi.fn().mockResolvedValue(emptyCoverage) });
    const { result } = renderHook(() => useProjectOverview(api, eventStream(), project, true, vi.fn()));

    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.coverage).toEqual(emptyCoverage);
    expect(result.current.error).toBeNull();
  });

  it('preserves the Source route without a selected project', async () => {
    window.history.replaceState(null, '', '/#source?path=src%2Fparser.c&line=742');
    render(<App api={apiDouble({ listProjects: vi.fn().mockResolvedValue([]) })} events={eventStream()} />);

    expect(await screen.findByRole('heading', { name: 'Source assurance' })).toBeVisible();
    expect(screen.getByText('Select or create a project to inspect source assurance.')).toBeVisible();
    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
  });

  it('keeps Overview usable and translates an unavailable backend without raw HTTP codes', async () => {
    window.history.replaceState(null, '', '/#overview');
    render(<App api={apiDouble({
      listProjects: vi.fn().mockRejectedValue(new Error('Request failed (500).'))
    })} events={eventStream()} />);

    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeVisible();
    expect(screen.getByText('BigEye local services are temporarily unavailable.')).toBeVisible();
    expect(screen.queryByText(/500|Request failed/i)).not.toBeInTheDocument();
  });

  it('never renders arbitrary client error text', async () => {
    window.history.replaceState(null, '', '/#overview');
    render(<App api={apiDouble({
      listProjects: vi.fn().mockRejectedValue(new Error('secret at /Users/private/key.txt'))
    })} events={eventStream()} />);

    expect(await screen.findByText('BigEye local services are temporarily unavailable.')).toBeVisible();
    expect(screen.queryByText(/secret|\/Users\/private/i)).not.toBeInTheDocument();
  });

  it('generation-guards stale project responses', async () => {
    let resolveStale!: (value: typeof campaigns) => void;
    const staleCampaigns = new Promise<typeof campaigns>((resolve) => { resolveStale = resolve; });
    const second = { ...project, id: '8', repository_url: 'https://github.com/acme/second.git' };
    const secondCampaigns = { ...campaigns, project_id: 8, campaigns: [{ ...campaigns.campaigns[0], id: 8, target_name: 'Second parser' }] };
    const api = apiDouble({
      listCampaigns: vi.fn((projectId: string) => projectId === '7' ? staleCampaigns : Promise.resolve(secondCampaigns)),
      getCoverageTree: vi.fn().mockResolvedValue(coverage),
      listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null })
    });
    const { result, rerender } = renderHook(
      ({ selected }) => useProjectOverview(api, eventStream(), selected, true, vi.fn()),
      { initialProps: { selected: project } }
    );

    rerender({ selected: second });
    await waitFor(() => expect(result.current.campaigns?.project_id).toBe(8));
    resolveStale(campaigns);
    await act(async () => { await staleCampaigns; });

    expect(result.current.campaigns?.project_id).toBe(8);
    expect(result.current.campaigns?.campaigns[0].target_name).toBe('Second parser');
  });

  it('refetches only the resource named by SSE invalidation', async () => {
    let invalidate!: (name: ProjectInvalidation) => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, onEvent) => { invalidate = onEvent; return () => undefined; })
    };
    const api = apiDouble();
    renderHook(() => useProjectOverview(api, events, project, true, vi.fn()));
    await waitFor(() => expect(api.listCampaigns).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(api.getCoverageTree).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(api.listFindings).toHaveBeenCalledTimes(1));

    act(() => invalidate('campaigns'));

    await waitFor(() => expect(api.listCampaigns).toHaveBeenCalledTimes(2));
    expect(api.getCoverageTree).toHaveBeenCalledTimes(1);
    expect(api.listFindings).toHaveBeenCalledTimes(1);
  });
});
