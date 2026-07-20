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
  paused_at: null,
  error: null
};

function apiDouble(): BigEyeApi {
  return {
    createProject: vi.fn().mockResolvedValue(project),
    listProjects: vi.fn().mockResolvedValue([]),
    getProject: vi.fn(),
    getProjectSettings: vi.fn(),
    updateProjectSettings: vi.fn(),
    pauseProject: vi.fn(),
    resumeProject: vi.fn(),
    listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(),
    getSettings: vi.fn(),
    listCampaigns: vi.fn().mockResolvedValue({ project_id: 1, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 1, commit_sha: '', files: [], pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(),
    getLineEvidence: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null })
  };
}

describe('App', () => {
  it('submits a valid repository revision and positive worker count, then opens overview', async () => {
    const api = apiDouble();
    const user = userEvent.setup();

    render(<App api={api} />);

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
});
