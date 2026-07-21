import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { FuzzingTable } from './components/fuzzing/FuzzingTable';
import { useFuzzing } from './controllers/useFuzzing';
import type { FuzzingModel } from './models/fuzzing';
import type { Project } from './models/project';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from './services/eventStream';
import { FuzzingView } from './views/FuzzingView';

const project: Project = {
  id: '7', repository_url: 'https://github.com/acme/parser.git', requested_revision: 'stable',
  worker_count: 4, commit_sha: 'a'.repeat(40), token_present: false,
  created_at: '2026-07-20T08:00:00Z', error: null,
};

const response = {
  project_id: 7,
  campaigns: [{
    id: 4, target_asset_id: 31, target_name: 'Encrypted parser path',
    configuration_asset_id: 32, configuration_name: 'Framed input', engine: 'AFL++',
    started_at: '2026-07-20T08:00:00Z', stopped_at: null,
    last_heartbeat_at: '2026-07-20T09:59:30Z', cpu_exposure_seconds: 5_400,
    next_review_after: '2026-07-20T10:30:00Z', next_review_reason: 'Review after new branch reach.',
    error: null, configuration_purpose: 'Exercise encrypted parser input.', retirement_reason: null,
    reached_line_count: 19, unique_line_count: 12, overlapping_line_count: 7,
    total_reached_lines: 19, covered_line_delta_5m: null, activity: 'running',
  }],
  assets: [],
};

function model(overrides: Partial<FuzzingModel> = {}): FuzzingModel {
  return {
    project, rows: [{
      id: 4, target: 'Encrypted parser path', configuration: 'Framed input',
      purpose: 'Exercise encrypted parser input.', engine: 'AFL++', activity: 'running',
      coverageDelta5m: null, totalReach: 19, cpuExposureSeconds: 5_400,
      lastEvidenceAt: '2026-07-20T09:59:30Z', state: 'Running',
    }], loading: false, error: null, ...overrides,
  };
}

function apiDouble(): BigEyeApi {
  return { listCampaigns: vi.fn().mockResolvedValue(response) } as unknown as BigEyeApi;
}

describe('Fuzzing workspace', () => {
  it('shows authoritative campaign evidence while keeping the fuzzer secondary', () => {
    render(<FuzzingView model={model()} />);

    const scroller = screen.getByRole('region', { name: 'Scrollable autonomous fuzzing campaigns' });
    expect(scroller).toHaveAttribute('tabindex', '0');
    const table = screen.getByRole('table', { name: 'Autonomous fuzzing campaigns' });
    expect(within(table).getByText('Encrypted parser path')).toBeVisible();
    expect(within(table).getByText('Exercise encrypted parser input.')).toBeVisible();
    expect(within(table).getByText('Unavailable')).toBeVisible();
    expect(within(table).getByText('19 lines')).toBeVisible();
    expect(within(table).getByText('1.5 CPU h')).toBeVisible();
    expect(within(table).getAllByText('Running')).toHaveLength(2);
    expect(within(table).queryByText('Healthy')).not.toBeInTheDocument();
    expect(within(table).getByText('AFL++')).toHaveClass('technical-metadata');
  });

  it('renders a sparse empty state without promotional explanation', () => {
    render(<FuzzingTable rows={[]} />);
    expect(screen.getByText('No fuzzing work is active yet.')).toBeVisible();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('refreshes authoritative rows for campaign, coverage, and activity hints', async () => {
    let invalidate!: (name: ProjectInvalidation) => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn((_projectId, onEvent) => { invalidate = onEvent; return () => undefined; }),
    };
    const api = apiDouble();
    const { result } = renderHook(() => useFuzzing(api, events, project, true));
    await waitFor(() => expect(result.current.rows).toHaveLength(1));
    expect(result.current.rows[0].state).toBe('Running');

    for (const name of ['campaigns', 'coverage', 'activity'] as const) {
      act(() => invalidate(name));
      await waitFor(() => expect(api.listCampaigns).toHaveBeenCalledTimes(2 + ['campaigns', 'coverage', 'activity'].indexOf(name)));
    }
  });
});
