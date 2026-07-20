import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { useActivity, type ActivityModel } from './controllers/useActivity';
import type { ProjectEvent } from './models/event';
import type { Project } from './models/project';
import type { BigEyeApi } from './services/apiClient';
import { EventStream, type ProjectEventStream, type ProjectInvalidation } from './services/eventStream';
import { ActivityView } from './views/ActivityView';

const project: Project = {
  id: '7', repository_url: 'https://github.com/acme/parser.git', requested_revision: 'stable',
  worker_count: 2, commit_sha: 'a'.repeat(40), token_present: false,
  created_at: '2026-07-20T08:00:00Z', paused_at: null, error: null,
};

const activity: ProjectEvent = {
  id: 10, created_at: '2026-07-20T09:00:00Z', stream: 'activity',
  payload: {
    decision: 'Continue the parser strategy',
    motivation: 'Coverage is still increasing in project code.',
    change: 'Admitted one replay-verified seed.',
    evidence_ids: ['coverage:src/parser.c:42'],
    next_review_condition: 'Review after the next coverage plateau.',
    task_id: 12, state: 'completed',
  },
};

const modelDebug: ProjectEvent = {
  id: 20, created_at: '2026-07-20T09:01:00Z', stream: 'debug',
  payload: {
    event: 'model.end', trace_id: 'trace_abc', parent_id: null,
    agent: 'Campaign manager', model: 'gpt-5.6-terra', request_id: 'req_1', response_id: 'resp_1',
    input: { items: [{ role: 'user', content: 'Review the campaign.' }] },
    output: [{ type: 'message', content: 'Continue.' }],
    usage: { requests: 1, input_tokens: 120, output_tokens: 30, total_tokens: 150, cached_tokens: 80, reasoning_tokens: 12 },
    reasoning_summaries: ['Coverage is increasing.'], web_citations: ['https://example.com/reference'],
    command: ['ninja', '-C', 'build'], stdout: 'build complete', stderr: '',
    diff: '--- a/harness.cc\n+++ b/harness.cc', container_id: 'container-123',
  },
};

const toolDebug: ProjectEvent = {
  id: 21, created_at: '2026-07-20T09:02:00Z', stream: 'debug',
  payload: {
    event: 'tool.end', trace_id: 'trace_abc', parent_id: 'call_parent', tool: 'read_source',
    tool_call_id: 'call_1', arguments: { path: 'src/parser.c' }, result: { lines: 20 },
  },
};

function model(overrides: Partial<ActivityModel> = {}): ActivityModel {
  return {
    project, activityEvents: [activity], debugEvents: [modelDebug, toolDebug],
    activeTab: 'activity', debugFilter: 'all', loading: false,
    activityError: null, debugError: null, liveError: null,
    focusedEvidenceId: null, focusedEventId: null,
    activityHasMore: false, debugHasMore: false,
    onTabChange: vi.fn(), onDebugFilter: vi.fn(), onLoadMoreActivity: vi.fn(), onLoadMoreDebug: vi.fn(),
    ...overrides,
  };
}

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn(), listProjects: vi.fn().mockResolvedValue([project]), getProject: vi.fn().mockResolvedValue(project),
    getProjectSettings: vi.fn(), updateProjectSettings: vi.fn(), pauseProject: vi.fn(), resumeProject: vi.fn(),
    listTasks: vi.fn().mockResolvedValue([]), getTaskLog: vi.fn(), getSettings: vi.fn(),
    listCampaigns: vi.fn().mockResolvedValue({ project_id: 7, project_paused: false, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 7, commit_sha: project.commit_sha!, files: [], pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(), getLineEvidence: vi.fn(), listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null }),
    retainedTestcaseUrl: vi.fn(),
    getFinding: vi.fn(), findingReproducerUrl: vi.fn(),
    getProjectLog: vi.fn((_projectId: string, stream: 'activity' | 'debug') => Promise.resolve(
      stream === 'activity' ? { events: [activity], next_offset: 10, has_more: false } : { events: [modelDebug, toolDebug], next_offset: 21, has_more: false },
    )),
    getProjectEvent: vi.fn(),
    ...overrides,
  } as BigEyeApi;
}

const idleEvents: ProjectEventStream = { subscribe: vi.fn().mockReturnValue(() => undefined) };

describe('Activity and Debug', () => {
  afterEach(() => { window.history.replaceState(null, '', '/'); });

  it('reports EventSource recovery only after the connection reopens', () => {
    class FakeEventSource {
      static latest: FakeEventSource;
      onerror: (() => void) | null = null;
      onopen: (() => void) | null = null;
      constructor(readonly url: string) { FakeEventSource.latest = this; }
      addEventListener() { /* invalidations are irrelevant to this connection test */ }
      close() { /* no-op */ }
    }
    vi.stubGlobal('EventSource', FakeEventSource);
    const onError = vi.fn();
    const onOpen = vi.fn();

    new EventStream().subscribe(project.id, vi.fn(), onError, onOpen);
    FakeEventSource.latest.onerror?.();
    FakeEventSource.latest.onopen?.();

    expect(onError).toHaveBeenCalledWith('Live updates are temporarily unavailable.');
    expect(onOpen).toHaveBeenCalledOnce();
    vi.unstubAllGlobals();
  });

  it('shows structured motivation and next review without claiming hidden chain of thought', () => {
    render(<ActivityView model={model()} />);

    expect(screen.getByText('Why BigEye changed this strategy')).toBeVisible();
    expect(screen.getByText('Coverage is still increasing in project code.')).toBeVisible();
    expect(screen.getByText('Admitted one replay-verified seed.')).toBeVisible();
    expect(screen.getByText('Review after the next coverage plateau.')).toBeVisible();
    expect(screen.getByRole('link', { name: 'coverage:src/parser.c:42' })).toBeVisible();
    expect(screen.queryByText(/chain.of.thought/i)).not.toBeInTheDocument();
  });

  it('uses keyboard-accessible Activity and Debug tabs', async () => {
    const user = userEvent.setup();
    const onTabChange = vi.fn();
    const { rerender } = render(<ActivityView model={model({ onTabChange })} />);
    const tablist = screen.getByRole('tablist', { name: 'Project activity views' });
    const debugTab = within(tablist).getByRole('tab', { name: 'Debug' });

    debugTab.focus();
    await user.keyboard('{Enter}');
    expect(onTabChange).toHaveBeenCalledWith('debug');
    rerender(<ActivityView model={model({ activeTab: 'debug', onTabChange })} />);
    expect(screen.getByRole('tabpanel', { name: 'Debug' })).toBeVisible();
  });

  it('progressively discloses complete sanitized debug records and raw JSON', async () => {
    const user = userEvent.setup();
    render(<ActivityView model={model({ activeTab: 'debug' })} />);

    expect(screen.getByText('Advanced local debug evidence')).toBeVisible();
    expect(screen.getByText('model.end')).toBeVisible();
    expect(screen.getByText('120 input tokens')).toBeVisible();
    expect(screen.getByText('80 cached tokens')).toBeVisible();
    expect(screen.getByText('12 reasoning tokens')).toBeVisible();
    expect(screen.getByText('ninja -C build')).toBeVisible();
    expect(screen.getByText('build complete')).toBeVisible();
    expect(screen.getByText('https://example.com/reference')).toBeVisible();
    expect(screen.getByText(/\+\+\+ b\/harness.cc/)).toBeVisible();
    const modelName = screen.getByText('gpt-5.6-terra');
    expect(modelName).not.toBeVisible();
    await user.click(screen.getAllByText('Technical metadata')[0]);
    expect(modelName).toBeVisible();
    expect(screen.getByText('resp_1')).toBeVisible();

    const raw = screen.getAllByText('Raw sanitized JSON')[0];
    await user.click(raw);
    expect(screen.getByText(/"trace_id": "trace_abc"/)).toBeVisible();
    expect(screen.queryByText(/hidden chain.of.thought/i)).not.toBeInTheDocument();
  });

  it('filters the locally loaded debug page by tool activity', () => {
    render(<ActivityView model={model({ activeTab: 'debug', debugFilter: 'tool' })} />);

    expect(screen.getByText('tool.end')).toBeVisible();
    expect(screen.queryByText('model.end')).not.toBeInTheDocument();
  });

  it('categorises model requests as API activity', () => {
    render(<ActivityView model={model({ activeTab: 'debug', debugFilter: 'api' })} />);

    expect(screen.getByText('model.end')).toBeVisible();
    expect(screen.queryByText('tool.end')).not.toBeInTheDocument();
  });

  it('renders activity records newest first without reversing the server page', () => {
    const older = { ...activity, id: 9, payload: { ...activity.payload, decision: 'Older decision' } };
    const newer = { ...activity, id: 11, payload: { ...activity.payload, decision: 'Newer decision' } };
    render(<ActivityView model={model({ activityEvents: [newer, older] })} />);

    expect([...document.querySelectorAll('.activity-list h2')].map((node) => node.textContent)).toEqual([
      'Newer decision', 'Older decision',
    ]);
  });

  it('selects and marks the stream record addressed by the evidence query', async () => {
    const debugEvidence = {
      ...modelDebug,
      payload: { ...modelDebug.payload, evidence_ids: ['replay:clean'] },
    };
    const duplicateEvidence = { ...debugEvidence, id: 19 };
    window.history.replaceState(null, '', '/#activity?stream=debug&event=20&evidence=replay%3Aclean');
    const getProjectEvent = vi.fn().mockResolvedValue(debugEvidence);
    const api = apiDouble({
      getProjectLog: vi.fn((_projectId: string, stream: 'activity' | 'debug') => Promise.resolve(
        stream === 'activity'
          ? { events: [activity], next_offset: 0, has_more: false }
          : { events: [duplicateEvidence], next_offset: 0, has_more: false },
      )),
      getProjectEvent,
    });
    const { result } = renderHook(() => useActivity(api, idleEvents, project, true));

    await waitFor(() => expect(result.current.activeTab).toBe('debug'));
    expect(result.current.focusedEvidenceId).toBe('replay:clean');
    expect(result.current.focusedEventId).toBe(20);
    expect(getProjectEvent).toHaveBeenCalledWith(project.id, 'debug', 20);
    expect(result.current.debugEvents.map((event) => event.id)).toEqual([debugEvidence.id, duplicateEvidence.id]);

    render(<ActivityView model={model({
      activeTab: 'debug', debugEvents: [duplicateEvidence, debugEvidence],
      focusedEvidenceId: 'replay:clean', focusedEventId: 20,
    })} />);
    const records = screen.getAllByText('model.end').map((node) => node.closest('article'));
    expect(records[0]).not.toHaveAttribute('data-evidence-focus');
    expect(records[1]).toHaveAttribute('data-evidence-focus', 'true');
    expect(records[1]).toHaveFocus();
  });

  it('keeps the Activity route reachable without a selected project', async () => {
    window.history.replaceState(null, '', '/#activity');
    render(<App api={apiDouble({ listProjects: vi.fn().mockResolvedValue([]) })} events={idleEvents} />);

    expect(await screen.findByRole('heading', { name: 'Activity' })).toBeVisible();
    expect(screen.getByText('Select or create a project to review campaign activity.')).toBeVisible();
  });

  it('does not describe unavailable activity as a genuinely empty history', () => {
    render(<ActivityView model={model({
      activityEvents: [], debugEvents: [], activityError: 'Campaign activity is temporarily unavailable.',
    })} />);

    expect(screen.getByText('Campaign activity is temporarily unavailable.')).toBeVisible();
    expect(screen.queryByText('No campaign decisions have been recorded yet.')).not.toBeInTheDocument();
  });

  it('keeps stream failures independent and surfaces live update failures', async () => {
    let reportLiveError!: (message: string) => void;
    let reportLiveRecovery!: () => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, _onEvent, onError, onOpen) => {
        reportLiveError = onError!;
        reportLiveRecovery = onOpen!;
        return () => undefined;
      }),
    };
    const api = apiDouble({
      getProjectLog: vi.fn((_projectId: string, stream: 'activity' | 'debug') => stream === 'activity'
        ? Promise.reject(new Error('unavailable'))
        : Promise.resolve({ events: [modelDebug], next_offset: 20, has_more: false })),
    });
    const { result } = renderHook(() => useActivity(api, events, project, true));

    await waitFor(() => expect(result.current.activityError).toBe('Campaign activity is temporarily unavailable.'));
    expect(result.current.debugError).toBeNull();
    expect(result.current.debugEvents).toEqual([modelDebug]);
    act(() => reportLiveError('Live updates are temporarily unavailable.'));
    expect(result.current.liveError).toBe('Live updates are temporarily unavailable.');
    act(() => reportLiveRecovery());
    expect(result.current.liveError).toBeNull();
  });

  it('uses the truthful server cursor and has-more flag when loading older records', async () => {
    const older = { ...activity, id: 5 };
    const getProjectLog = vi.fn((_projectId: string, stream: 'activity' | 'debug', before: number) => {
      if (stream === 'debug') return Promise.resolve({ events: [], next_offset: 0, has_more: false });
      return Promise.resolve(before === -1
        ? { events: [activity], next_offset: 10, has_more: true }
        : { events: [older], next_offset: 0, has_more: false });
    });
    const api = apiDouble({ getProjectLog });
    const { result } = renderHook(() => useActivity(api, idleEvents, project, true));
    await waitFor(() => expect(result.current.activityHasMore).toBe(true));

    act(() => result.current.onLoadMoreActivity());
    await waitFor(() => expect(result.current.activityEvents).toEqual([activity, older]));
    expect(getProjectLog).toHaveBeenCalledWith('7', 'activity', 10, 100);
    expect(result.current.activityHasMore).toBe(false);
  });

  it('ignores a stale older-log rejection after switching projects', async () => {
    let rejectOlder!: (reason: unknown) => void;
    const olderPage = new Promise<never>((_resolve, reject) => { rejectOlder = reject; });
    const secondProject = { ...project, id: '8', repository_url: 'https://example.test/second.git' };
    const getProjectLog = vi.fn((projectId: string, stream: 'activity' | 'debug', before: number) => {
      if (projectId === project.id && stream === 'activity' && before === 10) return olderPage;
      const isInitialActivity = projectId === project.id && stream === 'activity' && before === -1;
      return Promise.resolve({
        events: isInitialActivity ? [activity] : [],
        next_offset: isInitialActivity ? 10 : 0,
        has_more: isInitialActivity,
      });
    });
    const api = apiDouble({ getProjectLog });
    const { result, rerender } = renderHook(
      ({ selected }) => useActivity(api, idleEvents, selected, true),
      { initialProps: { selected: project } },
    );
    await waitFor(() => expect(result.current.activityHasMore).toBe(true));
    act(() => result.current.onLoadMoreActivity());
    rerender({ selected: secondProject });
    rejectOlder(new Error('stale project failure'));
    await act(async () => { await Promise.resolve(); });

    expect(result.current.activityError).toBeNull();
  });

  it('refetches only the named activity or debug resource', async () => {
    let invalidate!: (name: ProjectInvalidation) => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, onEvent) => { invalidate = onEvent; return () => undefined; }),
    };
    const api = apiDouble();
    renderHook(() => useActivity(api, events, project, true));
    await waitFor(() => expect(api.getProjectLog).toHaveBeenCalledTimes(2));

    act(() => invalidate('activity'));
    await waitFor(() => expect(api.getProjectLog).toHaveBeenCalledTimes(3));
    expect(api.getProjectLog).toHaveBeenLastCalledWith('7', 'activity', -1, 100);
    act(() => invalidate('debug'));
    await waitFor(() => expect(api.getProjectLog).toHaveBeenCalledTimes(4));
    expect(api.getProjectLog).toHaveBeenLastCalledWith('7', 'debug', -1, 100);
  });
});
