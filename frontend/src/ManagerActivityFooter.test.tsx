import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ManagerActivityFooter } from './components/activity/ManagerActivityFooter';
import {
  managerActivityMessage,
  useManagerActivity,
} from './controllers/useManagerActivity';
import type { CampaignList } from './models/campaign';
import type { ProjectEvent } from './models/event';
import type { Project } from './models/project';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from './services/eventStream';

const now = new Date('2026-07-20T10:00:00Z');
const project: Project = {
  id: '7', repository_url: 'https://github.com/acme/parser.git', requested_revision: 'stable',
  worker_count: 2, commit_sha: 'a'.repeat(40), token_present: false,
  created_at: '2026-07-20T08:00:00Z', error: null,
};
const campaigns: CampaignList = {
  project_id: 7,
  campaigns: [{
    id: 4, target_asset_id: 31, target_name: 'Parser input path',
    configuration_asset_id: 32, configuration_name: 'Encrypted mode', engine: 'AFL++',
    started_at: '2026-07-20T09:00:00Z', stopped_at: null,
    last_heartbeat_at: '2026-07-20T09:59:30Z', cpu_exposure_seconds: 3600,
    next_review_after: '2026-07-20T10:30:00Z', next_review_reason: 'Periodic review',
    error: null, configuration_purpose: 'Exercise encrypted input.', retirement_reason: null,
    reached_line_count: 16, unique_line_count: 12, overlapping_line_count: 4,
    total_reached_lines: 16, recent_line_gain: 1, activity: 'running',
  }],
  assets: [],
};
const activity: ProjectEvent = {
  id: 20, created_at: '2026-07-20T09:59:40Z', stream: 'activity',
  payload: { decision: 'Continuing the decoder campaign' },
};
const managerStart: ProjectEvent = {
  id: 31, created_at: '2026-07-20T09:59:55Z', stream: 'debug',
  payload: { event: 'agent.start', agent: 'Campaign manager' },
};

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn(), listProjects: vi.fn(), getProject: vi.fn(),
    getProjectSettings: vi.fn(), updateProjectSettings: vi.fn(),
    listTasks: vi.fn(), getTaskLog: vi.fn(), getSettings: vi.fn(),
    listCampaigns: vi.fn().mockResolvedValue(campaigns), getCoverageTree: vi.fn(),
    getSourceFile: vi.fn(), getCoverageFunctions: vi.fn(), getLineEvidence: vi.fn(), retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn(), getFinding: vi.fn(), findingReproducerUrl: vi.fn(), startFindingReproduction: vi.fn(), findingReproductionEventsUrl: vi.fn(),
    getProjectLog: vi.fn((_projectId, stream) => Promise.resolve({
      events: stream === 'activity' ? [activity] : [], next_offset: 0, has_more: false,
    })),
    getProjectEvent: vi.fn(), ...overrides,
  } as BigEyeApi;
}

function idleEvents(): ProjectEventStream {
  return { subscribe: vi.fn().mockReturnValue(() => undefined) };
}

afterEach(() => vi.useRealTimers());

describe('manager activity footer', () => {
  it('prioritises a manager review that is currently in progress', () => {
    expect(managerActivityMessage({
      project, campaigns, activityEvents: [activity], debugEvents: [managerStart],
      loading: false, unavailable: false, now,
    })).toBe('Manager is reviewing campaign evidence...');
  });

  it('briefly presents the latest structured manager decision', () => {
    expect(managerActivityMessage({
      project, campaigns, activityEvents: [activity], debugEvents: [],
      loading: false, unavailable: false, now,
    })).toBe('Manager: Continuing the decoder campaign');
  });

  it('reports healthy fuzzing after the manager becomes idle', () => {
    const olderActivity = { ...activity, created_at: '2026-07-20T09:50:00Z' };
    expect(managerActivityMessage({
      project, campaigns, activityEvents: [olderActivity], debugEvents: [],
      loading: false, unavailable: false, now,
    })).toBe('Fuzzing at full speed!');
  });

  it('does not claim active fuzzing for failed or stale campaigns', () => {
    const oldActivity = [{ ...activity, created_at: '2026-07-20T09:50:00Z' }];
    expect(managerActivityMessage({
      project, campaigns: {
        ...campaigns,
        campaigns: [{ ...campaigns.campaigns[0], error: 'container failed' }],
      }, activityEvents: oldActivity, debugEvents: [], loading: false, unavailable: false, now,
    })).toBe('A fuzzing instance needs attention.');
    expect(managerActivityMessage({
      project, campaigns: {
        ...campaigns,
        campaigns: [{ ...campaigns.campaigns[0], last_heartbeat_at: '2026-07-20T09:50:00Z' }],
      }, activityEvents: oldActivity, debugEvents: [], loading: false, unavailable: false, now,
    })).toBe('Waiting for campaign telemetry...');
  });

  it('renders one accessible line that opens Activity', async () => {
    const user = userEvent.setup();
    const onOpenActivity = vi.fn();
    render(<ManagerActivityFooter message="Fuzzing at full speed!" onOpenActivity={onOpenActivity} />);

    const footer = screen.getByRole('contentinfo', { name: 'Current manager activity' });
    const button = screen.getByRole('button', { name: 'Open Activity: Fuzzing at full speed!' });
    expect(footer).toHaveTextContent('Fuzzing at full speed!');
    expect(footer.querySelectorAll('[aria-live="polite"]')).toHaveLength(1);
    await user.click(button);
    expect(onOpenActivity).toHaveBeenCalledOnce();
  });

  it('coalesces a burst of debug invalidations into one refresh', async () => {
    let invalidate!: (name: ProjectInvalidation) => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, onEvent) => { invalidate = onEvent; return () => undefined; }),
    };
    const api = apiDouble();
    renderHook(() => useManagerActivity(api, events, project));

    await waitFor(() => expect(api.listCampaigns).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(api.getProjectLog).toHaveBeenCalledTimes(2));
    act(() => invalidate('campaigns'));
    await waitFor(() => expect(api.listCampaigns).toHaveBeenCalledTimes(2));
    expect(api.getProjectLog).toHaveBeenCalledTimes(2);
    vi.useFakeTimers();
    act(() => {
      for (let index = 0; index < 20; index += 1) invalidate('debug');
    });
    expect(api.getProjectLog).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
    expect(api.getProjectLog).toHaveBeenCalledTimes(3);
    expect(api.getProjectLog).toHaveBeenLastCalledWith('7', 'debug', -1, 64);
  });

  it('keeps manager evidence when the same project receives refreshed facts', async () => {
    const api = apiDouble();
    const events = idleEvents();
    const { result, rerender } = renderHook(
      ({ selected }) => useManagerActivity(api, events, selected),
      { initialProps: { selected: project } },
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    rerender({ selected: { ...project, worker_count: 3 } });
    await act(async () => { await Promise.resolve(); });

    expect(api.listCampaigns).toHaveBeenCalledTimes(1);
    expect(api.getProjectLog).toHaveBeenCalledTimes(2);
  });
});
