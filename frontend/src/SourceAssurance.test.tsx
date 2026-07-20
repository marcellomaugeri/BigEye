import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { useSourceAssurance, type SourceAssuranceModel } from './controllers/useSourceAssurance';
import type { Project } from './models/project';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream } from './services/eventStream';
import { SourceAssuranceView } from './views/SourceAssuranceView';

const project: Project = {
  id: '7', repository_url: 'https://github.com/acme/parser.git', requested_revision: 'stable',
  worker_count: 2, commit_sha: 'a'.repeat(40), token_present: false,
  created_at: '2026-07-20T08:00:00Z', paused_at: null, error: null
};

const campaigns = {
  project_id: 7, campaigns: [{
    id: 4, target_asset_id: 31, target_name: 'Parser input path', configuration_asset_id: null,
    configuration_name: null, engine: 'component engine', started_at: '2026-07-20T08:00:00Z',
    stopped_at: null, last_heartbeat_at: null, cpu_exposure_seconds: 5400,
    next_review_after: null, next_review_reason: 'Review after coverage plateaus.', error: null
  }],
  assets: [
    { id: 33, kind: 'strategy', name: 'Parser strategy', parent_id: 31 },
    { id: 34, kind: 'strategy', name: 'Socket strategy', parent_id: 31 }
  ]
};

const tree = {
  project_id: 7, commit_sha: 'a'.repeat(40),
  files: [{ path: 'src/parser.c', covered_lines: 1, cpu_exposure_seconds: 5400 }],
  pagination: { limit: 1000, offset: 0, total: 1 }
};

const source = {
  project_id: 7, commit_sha: 'a'.repeat(40), path: 'src/parser.c', start_line: 41, end_line: 43,
  lines: [
    { number: 41, text: 'int parse(const char *data) {', covered: true, strategy_count: 1, cpu_exposure_seconds: 1200 },
    { number: 42, text: '  return decode(data);', covered: true, strategy_count: 2, cpu_exposure_seconds: 5400 },
    { number: 43, text: '}', covered: false, strategy_count: 0, cpu_exposure_seconds: 0 }
  ]
};

const lineEvidence = {
  evidence: [
    { campaign_id: 4, strategy_asset_id: 33, testcase_sha256: 'b'.repeat(64), replay_command: ['/target', '{input}'], target_asset_id: 31, configuration_asset_id: null, clean_image_id: `sha256:${'c'.repeat(64)}`, cpu_exposure_seconds: 5400 },
    { campaign_id: 4, strategy_asset_id: 34, testcase_sha256: 'd'.repeat(64), replay_command: ['/socket-target', '{input}'], target_asset_id: 31, configuration_asset_id: null, clean_image_id: `sha256:${'e'.repeat(64)}`, cpu_exposure_seconds: 1800 }
  ],
  pagination: { limit: 500, offset: 0, total: 2 }
};

function model(overrides: Partial<SourceAssuranceModel> = {}): SourceAssuranceModel {
  return {
    project, tree, source, campaigns, evidence: lineEvidence,
    selectedPath: 'src/parser.c', selectedLine: 42, strategyFilter: '33',
    loading: false, error: null, onSelectPath: vi.fn(), onSelectLine: vi.fn(),
    onStrategyFilter: vi.fn(), testcaseUrl: (item) => `/retained/${item.testcase_sha256}`, ...overrides
  };
}

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn(), listProjects: vi.fn(), getProject: vi.fn(), getProjectSettings: vi.fn(),
    updateProjectSettings: vi.fn(), pauseProject: vi.fn(), resumeProject: vi.fn(), listTasks: vi.fn(),
    getTaskLog: vi.fn(), getSettings: vi.fn(), listCampaigns: vi.fn().mockResolvedValue(campaigns),
    getCoverageTree: vi.fn().mockResolvedValue(tree), getSourceFile: vi.fn().mockResolvedValue(source),
    getLineEvidence: vi.fn().mockResolvedValue(lineEvidence),
    retainedTestcaseUrl: vi.fn().mockReturnValue('/retained/testcase'),
    listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null }), ...overrides
  } as BigEyeApi;
}

const events: ProjectEventStream = { subscribe: vi.fn().mockReturnValue(() => undefined) };

describe('Source assurance', () => {
  it('shows selectable source lines, strategy-filtered first testcase evidence and CPU exposure', async () => {
    const user = userEvent.setup();
    const onSelectLine = vi.fn();
    render(<SourceAssuranceView model={model({ onSelectLine })} />);

    const sourceRegion = screen.getByRole('region', { name: 'Source code' });
    const selected = within(sourceRegion).getByRole('button', { name: /Line 42.*covered.*1.5 CPU exposure hours/i });
    selected.focus();
    await user.keyboard('{Enter}');
    expect(onSelectLine).toHaveBeenCalledWith(42);
    expect(within(sourceRegion).getByText('uncovered')).toBeVisible();

    expect(screen.getByRole('combobox', { name: 'Reaching strategy' })).toHaveValue('33');
    const testcaseLink = screen.getByRole('link', { name: 'Download first testcase for Parser strategy' });
    expect(testcaseLink).toHaveAttribute('href', `/retained/${'b'.repeat(64)}`);
    expect(testcaseLink).toHaveAttribute('download');
    expect(screen.queryByRole('link', { name: 'Download first testcase for Socket strategy' })).not.toBeInTheDocument();
    expect(screen.getByText('1.5 CPU exposure hours')).toBeVisible();
    expect(screen.getByText('b'.repeat(64))).toBeVisible();
    expect(screen.getByText('/target {input}')).toBeVisible();
    expect(screen.queryByRole('button', { name: /run replay/i })).not.toBeInTheDocument();
  });

  it('generation-guards stale line evidence after keyboard selection changes', async () => {
    let resolveLine41!: (value: typeof lineEvidence) => void;
    const stale = new Promise<typeof lineEvidence>((resolve) => { resolveLine41 = resolve; });
    const line42 = { ...lineEvidence, evidence: [{ ...lineEvidence.evidence[0], testcase_sha256: 'f'.repeat(64) }] };
    const api = apiDouble({
      getLineEvidence: vi.fn((_projectId: string, _path: string, line: number) => line === 41 ? stale : Promise.resolve(line42))
    });
    const { result } = renderHook(() => useSourceAssurance(api, events, project, true));

    await waitFor(() => expect(result.current.source?.path).toBe('src/parser.c'));
    act(() => result.current.onSelectLine(41));
    act(() => result.current.onSelectLine(42));
    await waitFor(() => expect(result.current.evidence?.evidence[0].testcase_sha256).toBe('f'.repeat(64)));
    resolveLine41(lineEvidence);
    await act(async () => { await stale; });

    expect(result.current.selectedLine).toBe(42);
    expect(result.current.evidence?.evidence[0].testcase_sha256).toBe('f'.repeat(64));
  });

  it('selects the first covered line and never requests evidence for an uncovered line', async () => {
    const getLineEvidence = vi.fn().mockResolvedValue(lineEvidence);
    const api = apiDouble({ getLineEvidence });
    const { result } = renderHook(() => useSourceAssurance(api, events, project, true));

    await waitFor(() => expect(result.current.source?.path).toBe('src/parser.c'));
    await waitFor(() => expect(result.current.selectedLine).toBe(41));
    expect(getLineEvidence).toHaveBeenCalledWith('7', 'src/parser.c', 41);

    act(() => result.current.onSelectLine(43));
    await waitFor(() => expect(result.current.selectedLine).toBe(43));
    expect(result.current.evidence).toBeNull();
    expect(getLineEvidence).toHaveBeenCalledTimes(1);
  });

  it('treats absent clean coverage as a truthful empty state rather than an outage', async () => {
    const emptyTree = { ...tree, files: [], pagination: { ...tree.pagination, total: 0 } };
    const api = apiDouble({ getCoverageTree: vi.fn().mockResolvedValue(emptyTree) });
    const { result } = renderHook(() => useSourceAssurance(api, events, project, true));

    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.tree).toEqual(emptyTree);
    expect(result.current.error).toBeNull();
  });

  it('exposes an accessible source list equivalent', () => {
    render(<SourceAssuranceView model={model()} />);

    expect(screen.getByRole('navigation', { name: 'Project source files' })).toBeVisible();
    expect(screen.getByRole('list', { name: 'Source assurance files' })).toBeVisible();
    expect(screen.getByRole('region', { name: 'Selected line evidence' })).toBeVisible();
  });
});
