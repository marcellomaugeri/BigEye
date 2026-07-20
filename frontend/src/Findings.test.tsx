import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { useFindings, type FindingsModel } from './controllers/useFindings';
import type { FindingDetail, FindingSummary } from './models/finding';
import type { Project } from './models/project';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from './services/eventStream';
import { FindingsView } from './views/FindingsView';

const project: Project = {
  id: '7', repository_url: 'https://github.com/acme/parser.git', requested_revision: 'stable',
  worker_count: 2, commit_sha: 'a'.repeat(40), token_present: false,
  created_at: '2026-07-20T08:00:00Z', paused_at: null, error: null,
};

const finding: FindingSummary = {
  id: '9', project_id: '7', classification: 'true vulnerability', priority_rank: 1,
  priority_reason: 'Attacker-controlled parser input reaches a memory error.',
  description: 'Out-of-bounds read while decoding a length field.', reproducible: true,
  occurrence_count: 3, created_at: '2026-07-20T09:00:00Z', triaged_at: '2026-07-20T09:10:00Z',
};

const detail: FindingDetail = {
  ...finding,
  uncertainty: 'Impact beyond the reproduced parser path has not been established.',
  evidence_ids: ['crash:sha256:abc', 'coverage:src/parser.c:42'],
  reproducer: { sha256: 'b'.repeat(64), size: 128 },
  replay: {
    attempts: 3, matching: 3,
    compatible_variants: [{
      variant: 'instrumented target', crashed: true, signal: 'SIGSEGV', sanitizer: 'AddressSanitizer',
      source_location: 'src/parser.c:42', image_id: `sha256:${'c'.repeat(64)}`, error: null,
    }],
    clean_variant: {
      variant: 'clean target', crashed: true, signal: 'SIGSEGV', sanitizer: null,
      source_location: 'src/parser.c:42', image_id: `sha256:${'d'.repeat(64)}`, error: null,
    },
  },
  minimisation: { accepted: true, original_size: 512, minimal_size: 128 },
  correction: null,
  repair_intent: null,
  evidence_events: [{
    evidence_id: 'coverage:src/parser.c:42', stream: 'activity', event_id: 812,
  }],
};

function model(overrides: Partial<FindingsModel> = {}): FindingsModel {
  return {
    project, findings: [finding], selectedFindingId: '9', selectedFinding: detail,
    reproducerUrl: '/api/projects/7/findings/9/reproducer', nextCursor: null,
    loading: false, detailLoading: false, error: null, liveError: null,
    onSelectFinding: vi.fn(), onLoadMore: vi.fn(), ...overrides,
  };
}

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn(), listProjects: vi.fn().mockResolvedValue([project]),
    getProject: vi.fn().mockResolvedValue(project), getProjectSettings: vi.fn(), updateProjectSettings: vi.fn(),
    pauseProject: vi.fn(), resumeProject: vi.fn(), listTasks: vi.fn().mockResolvedValue([]), getTaskLog: vi.fn(),
    getSettings: vi.fn(), listCampaigns: vi.fn().mockResolvedValue({ project_id: 7, project_paused: false, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 7, commit_sha: project.commit_sha!, files: [], pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(), getLineEvidence: vi.fn(),
    retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [finding], next_cursor: null }),
    getFinding: vi.fn().mockResolvedValue(detail),
    findingReproducerUrl: vi.fn().mockReturnValue('/api/projects/7/findings/9/reproducer'),
    getProjectLog: vi.fn().mockResolvedValue({ events: [], next_offset: -1, has_more: false }),
    getProjectEvent: vi.fn(),
    ...overrides,
  } as BigEyeApi;
}

const idleEvents: ProjectEventStream = { subscribe: vi.fn().mockReturnValue(() => undefined) };

describe('Findings', () => {
  afterEach(() => { window.history.replaceState(null, '', '/'); });

  it('renders one grouped finding with reproducibility, rationale and uncertainty', () => {
    render(<FindingsView model={model()} />);

    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(screen.getByText('3 occurrences')).toBeVisible();
    expect(screen.getByText('Reproduced')).toBeVisible();
    expect(screen.getByText('True vulnerability')).toBeVisible();
    expect(screen.getByText(finding.priority_reason!)).toBeVisible();
    expect(screen.getByText(/uncertainty/i)).toBeVisible();
    expect(screen.getByText(detail.uncertainty)).toBeVisible();
  });

  it('keeps sanitizer and image metadata secondary while exposing a minimal reproducer download', async () => {
    const user = userEvent.setup();
    render(<FindingsView model={model()} />);

    expect(screen.getByRole('link', { name: 'Download minimal reproducer' })).toHaveAttribute(
      'href', '/api/projects/7/findings/9/reproducer',
    );
    expect(screen.getByText('b'.repeat(64))).toBeVisible();
    const sanitizer = screen.getByText('AddressSanitizer');
    expect(sanitizer).not.toBeVisible();
    await user.click(screen.getByText('Technical evidence'));
    expect(sanitizer).toBeVisible();
    expect(screen.getByText(`sha256:${'c'.repeat(64)}`)).toBeVisible();
  });

  it('links exact source evidence and preserves generic evidence identifiers', () => {
    render(<FindingsView model={model()} />);

    expect(screen.getByRole('link', { name: 'coverage:src/parser.c:42' })).toHaveAttribute(
      'href', '#activity?stream=activity&event=812&evidence=coverage%3Asrc%2Fparser.c%3A42',
    );
    expect(screen.queryByRole('link', { name: 'crash:sha256:abc' })).not.toBeInTheDocument();
    expect(screen.getByText('crash:sha256:abc')).toBeVisible();
  });

  it('deep-links a validated replay source location rather than guessing from an evidence ID', async () => {
    const user = userEvent.setup();
    render(<FindingsView model={model()} />);

    await user.click(screen.getByText('Technical evidence'));
    for (const link of screen.getAllByRole('link', { name: 'src/parser.c:42' })) {
      expect(link).toHaveAttribute('href', '#source?path=src%2Fparser.c&line=42');
    }
  });

  it('keeps the Findings route reachable without a selected project', async () => {
    window.history.replaceState(null, '', '/#findings');
    render(<App api={apiDouble({ listProjects: vi.fn().mockResolvedValue([]) })} events={idleEvents} />);

    expect(await screen.findByRole('heading', { name: 'Findings' })).toBeVisible();
    expect(screen.getByText('Select or create a project to review replayed findings.')).toBeVisible();
  });

  it('shows an intentional empty state only after a genuine empty response', () => {
    render(<FindingsView model={model({ findings: [], selectedFindingId: null, selectedFinding: null, reproducerUrl: null })} />);

    expect(screen.getByText('No replayed findings yet.')).toBeVisible();
    expect(screen.queryByText(/not implemented/i)).not.toBeInTheDocument();
  });

  it('does not misreport an unavailable finding query as a genuine empty result', () => {
    render(<FindingsView model={model({
      findings: [], selectedFindingId: null, selectedFinding: null, reproducerUrl: null,
      error: 'Replayed findings are temporarily unavailable.',
    })} />);

    expect(screen.getByText('Replayed findings are temporarily unavailable.')).toBeVisible();
    expect(screen.queryByText('No replayed findings yet.')).not.toBeInTheDocument();
  });

  it('generation-guards a stale selected-finding response', async () => {
    let resolveNine!: (value: FindingDetail) => void;
    const stale = new Promise<FindingDetail>((resolve) => { resolveNine = resolve; });
    const second = { ...finding, id: '10', description: 'Second grouped finding.' };
    const secondDetail = { ...detail, ...second, uncertainty: 'Second uncertainty.' };
    const api = apiDouble({
      listFindings: vi.fn().mockResolvedValue({ items: [finding, second], next_cursor: null }),
      getFinding: vi.fn((_projectId: string, findingId: string) => findingId === '9' ? stale : Promise.resolve(secondDetail)),
    });
    const { result } = renderHook(() => useFindings(api, idleEvents, project, true));

    await waitFor(() => expect(result.current.selectedFindingId).toBe('9'));
    act(() => result.current.onSelectFinding('10'));
    await waitFor(() => expect(result.current.selectedFinding?.id).toBe('10'));
    resolveNine(detail);
    await act(async () => { await stale; });

    expect(result.current.selectedFinding?.id).toBe('10');
  });

  it('refetches only findings for a findings invalidation', async () => {
    let invalidate!: (name: ProjectInvalidation) => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, onEvent) => { invalidate = onEvent; return () => undefined; }),
    };
    const api = apiDouble();
    renderHook(() => useFindings(api, events, project, true));
    await waitFor(() => expect(api.listFindings).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(api.getFinding).toHaveBeenCalledTimes(1));

    act(() => invalidate('activity'));
    expect(api.listFindings).toHaveBeenCalledTimes(1);
    act(() => invalidate('findings'));
    await waitFor(() => expect(api.listFindings).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(api.getFinding).toHaveBeenCalledTimes(2));
  });

  it('retains and refetches an explicitly selected older finding after a first-page invalidation', async () => {
    let invalidate!: (name: ProjectInvalidation) => void;
    const older = { ...finding, id: '10', description: 'Older selected group.' };
    const olderDetail = { ...detail, ...older };
    const newest = { ...finding, id: '11', description: 'New first page group.' };
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, onEvent) => { invalidate = onEvent; return () => undefined; }),
    };
    const listFindings = vi.fn()
      .mockResolvedValueOnce({ items: [finding, older], next_cursor: null })
      .mockResolvedValueOnce({ items: [newest], next_cursor: null });
    const getFinding = vi.fn((_projectId: string, id: string) => Promise.resolve(
      id === older.id ? olderDetail : detail,
    ));
    const api = apiDouble({ listFindings, getFinding });
    const { result } = renderHook(() => useFindings(
      api, events, project, true,
    ));
    await waitFor(() => expect(result.current.selectedFindingId).toBe(finding.id));
    act(() => result.current.onSelectFinding(older.id));
    await waitFor(() => expect(result.current.selectedFinding?.id).toBe(older.id));

    act(() => invalidate('findings'));

    await waitFor(() => expect(listFindings).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(getFinding).toHaveBeenCalledWith(project.id, older.id));
    expect(result.current.selectedFindingId).toBe(older.id);
    expect(result.current.selectedFinding?.id).toBe(older.id);
  });

  it('ignores a stale load-more rejection after switching projects', async () => {
    let rejectOlder!: (reason: unknown) => void;
    const olderPage = new Promise<never>((_resolve, reject) => { rejectOlder = reject; });
    const secondProject = { ...project, id: '8', repository_url: 'https://example.test/second.git' };
    const listFindings = vi.fn((projectId: string, cursor?: string) => {
      if (projectId === project.id && cursor) return olderPage;
      return Promise.resolve({ items: projectId === project.id ? [finding] : [], next_cursor: projectId === project.id ? 'older' : null });
    });
    const api = apiDouble({ listFindings });
    const { result, rerender } = renderHook(
      ({ selected }) => useFindings(api, idleEvents, selected, true),
      { initialProps: { selected: project } },
    );
    await waitFor(() => expect(result.current.nextCursor).toBe('older'));
    act(() => result.current.onLoadMore());
    rerender({ selected: secondProject });
    await waitFor(() => expect(listFindings).toHaveBeenCalledWith(secondProject.id, undefined));
    rejectOlder(new Error('stale project failure'));
    await act(async () => { await Promise.resolve(); });

    expect(result.current.error).toBeNull();
  });

  it('preserves the backend priority order across pages', async () => {
    const second = { ...finding, id: '10', priority_rank: 2, created_at: '2026-07-20T11:00:00Z' };
    const third = { ...finding, id: '11', priority_rank: 3, created_at: '2026-07-20T12:00:00Z' };
    const api = apiDouble({
      listFindings: vi.fn()
        .mockResolvedValueOnce({ items: [finding, second], next_cursor: 'older' })
        .mockResolvedValueOnce({ items: [third], next_cursor: null }),
    });
    const { result } = renderHook(() => useFindings(api, idleEvents, project, true));
    await waitFor(() => expect(result.current.nextCursor).toBe('older'));

    act(() => result.current.onLoadMore());
    await waitFor(() => expect(result.current.findings).toHaveLength(3));
    expect(result.current.findings.map((item) => item.id)).toEqual(['9', '10', '11']);
  });

  it('surfaces findings live-update loss without discarding retained findings', async () => {
    let reportLiveError!: (message: string) => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, _onEvent, onError) => {
        reportLiveError = onError!;
        return () => undefined;
      }),
    };
    const api = apiDouble();
    const { result } = renderHook(() => useFindings(api, events, project, true));
    await waitFor(() => expect(result.current.findings).toEqual([finding]));

    act(() => reportLiveError('Live updates are temporarily unavailable.'));

    expect(result.current.liveError).toBe('Live updates are temporarily unavailable.');
    expect(result.current.findings).toEqual([finding]);
  });
});
