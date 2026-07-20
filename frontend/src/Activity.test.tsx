import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { useActivity, type ActivityModel } from './controllers/useActivity';
import type { ProjectEvent } from './models/event';
import type { Project } from './models/project';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from './services/eventStream';
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
    agent: 'Campaign manager', model: 'gpt-5.6-terra', request_id: 'req_1',
    input: { items: [{ role: 'user', content: 'Review the campaign.' }] },
    output: [{ type: 'message', content: 'Continue.' }],
    usage: { requests: 1, input_tokens: 120, output_tokens: 30, total_tokens: 150 },
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
    activeTab: 'activity', debugFilter: 'all', loading: false, error: null,
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
      stream === 'activity' ? { events: [activity], next_offset: 10 } : { events: [modelDebug, toolDebug], next_offset: 21 },
    )),
    ...overrides,
  } as BigEyeApi;
}

const idleEvents: ProjectEventStream = { subscribe: vi.fn().mockReturnValue(() => undefined) };

describe('Activity and Debug', () => {
  afterEach(() => { window.history.replaceState(null, '', '/'); });

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
    expect(screen.getByText('ninja -C build')).toBeVisible();
    expect(screen.getByText('build complete')).toBeVisible();
    expect(screen.getByText('https://example.com/reference')).toBeVisible();
    expect(screen.getByText(/\+\+\+ b\/harness.cc/)).toBeVisible();
    const modelName = screen.getByText('gpt-5.6-terra');
    expect(modelName).not.toBeVisible();
    await user.click(screen.getAllByText('Technical metadata')[0]);
    expect(modelName).toBeVisible();

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

  it('keeps the Activity route reachable without a selected project', async () => {
    window.history.replaceState(null, '', '/#activity');
    render(<App api={apiDouble({ listProjects: vi.fn().mockResolvedValue([]) })} events={idleEvents} />);

    expect(await screen.findByRole('heading', { name: 'Activity' })).toBeVisible();
    expect(screen.getByText('Select or create a project to review campaign activity.')).toBeVisible();
  });

  it('does not describe unavailable activity as a genuinely empty history', () => {
    render(<ActivityView model={model({
      activityEvents: [], debugEvents: [], error: 'Campaign activity is temporarily unavailable.',
    })} />);

    expect(screen.getByText('Campaign activity is temporarily unavailable.')).toBeVisible();
    expect(screen.queryByText('No campaign decisions have been recorded yet.')).not.toBeInTheDocument();
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
