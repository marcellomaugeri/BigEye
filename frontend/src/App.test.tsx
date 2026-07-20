import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { BigEyeApi } from './services/apiClient';

const project = {
  id: 'project-1',
  repository_url: 'https://github.com/example/target.git',
  requested_revision: 'stable',
  worker_count: 2,
  commit_sha: null,
  token_present: false,
  created_at: '2026-07-19T10:00:00Z',
  error: null
};

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn().mockResolvedValue(project),
    listProjects: vi.fn().mockResolvedValue([]),
    getProject: vi.fn(),
    getProjectSettings: vi.fn(),
    updateProjectSettings: vi.fn(),
    listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(),
    getSettings: vi.fn(),
    listCampaigns: vi.fn().mockResolvedValue({ project_id: 1, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 1, commit_sha: '', files: [], pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(),
    getLineEvidence: vi.fn(),
    retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null }),
    getFinding: vi.fn(), findingReproducerUrl: vi.fn(),
    getProjectLog: vi.fn().mockResolvedValue({ events: [], next_offset: 0, has_more: false }),
    getProjectEvent: vi.fn(),
    ...overrides,
  } as BigEyeApi;
}

describe('App', () => {
  it('submits a valid repository revision and positive worker count, then opens overview', async () => {
    const api = apiDouble();
    const user = userEvent.setup();

    render(<App api={api} />);

    await user.click(screen.getByRole('button', { name: 'New project' }));
    await user.type(screen.getByLabelText('Repository URL'), project.repository_url);
    await user.type(screen.getByLabelText('Revision'), project.requested_revision);
    await user.clear(screen.getByLabelText('Worker count'));
    await user.type(screen.getByLabelText('Worker count'), '2');
    await user.click(screen.getByRole('button', { name: 'Start project' }));

    expect(api.createProject).toHaveBeenCalledWith({
      repository_url: project.repository_url,
      revision: project.requested_revision,
      worker_count: 2
    });
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
  });

  it('keeps one manager activity line visible and opens Activity from it', async () => {
    window.history.replaceState(null, '', '/#projects');
    const selected = { ...project, id: '1', commit_sha: 'a'.repeat(40) };
    const api = apiDouble({
      listProjects: vi.fn().mockResolvedValue([selected]),
      getProject: vi.fn().mockResolvedValue(selected),
      listCampaigns: vi.fn().mockResolvedValue({
        project_id: 1, campaigns: [], assets: [],
      }),
      getProjectLog: vi.fn((_projectId, stream) => Promise.resolve({
        events: stream === 'debug' ? [{
          id: 2, created_at: '2026-07-20T10:00:00Z', stream: 'debug' as const,
          payload: { event: 'agent.start', agent: 'Campaign manager' },
        }] : [],
        next_offset: 0,
        has_more: false,
      })),
    });
    const user = userEvent.setup();

    render(<App api={api} />);

    const status = await screen.findByRole('button', {
      name: 'Open Activity: Manager is reviewing campaign evidence...',
    });
    await user.click(status);
    expect(await screen.findByRole('heading', { name: 'Activity' })).toBeVisible();
  });
});
