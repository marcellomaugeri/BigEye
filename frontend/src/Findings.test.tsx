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
};

function model(overrides: Partial<FindingsModel> = {}): FindingsModel {
  return {
    project, findings: [finding], selectedFindingId: '9', selectedFinding: detail,
    reproducerUrl: '/api/projects/7/findings/9/reproducer', nextCursor: null,
    loading: false, detailLoading: false, error: null,
    onSelectFinding: vi.fn(), onLoadMore: vi.fn(), ...overrides,
  };
}

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn(), listProjects: vi.fn().mockResolvedValue([project]),
    getProject: vi.fn().mockResolvedValue(project), getProjectSettings: vi.fn(), updateProjectSettings: vi.fn(),
    pauseProject: vi.fn(), resumeProject: vi.fn(), listTasks: vi.fn().mockResolvedValue([]), getTaskLog: vi.fn(),
    getSettings: vi.fn(), listCampaigns: vi.fn().mockResolvedValue({ project_id: 7, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 7, commit_sha: project.commit_sha!, files: [], pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(), getLineEvidence: vi.fn(),
    retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [finding], next_cursor: null }),
    getFinding: vi.fn().mockResolvedValue(detail),
    findingReproducerUrl: vi.fn().mockReturnValue('/api/projects/7/findings/9/reproducer'),
    getProjectLog: vi.fn().mockResolvedValue({ events: [], next_offset: -1 }),
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
    const sanitizer = screen.getByText('AddressSanitizer');
    expect(sanitizer).not.toBeVisible();
    await user.click(screen.getByText('Technical evidence'));
    expect(sanitizer).toBeVisible();
    expect(screen.getByText(`sha256:${'c'.repeat(64)}`)).toBeVisible();
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

    act(() => invalidate('activity'));
    expect(api.listFindings).toHaveBeenCalledTimes(1);
    act(() => invalidate('findings'));
    await waitFor(() => expect(api.listFindings).toHaveBeenCalledTimes(2));
  });
});
