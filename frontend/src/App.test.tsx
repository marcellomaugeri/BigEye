import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { BigEyeApi } from './services/apiClient';

const project = {
  id: 'project-1',
  repository_url: 'https://github.com/example/target.git',
  worker_count: 2,
  commit_sha: null,
  created_at: '2026-07-19T10:00:00Z',
  finished_at: null,
  error: null
};

function apiDouble(): BigEyeApi {
  return {
    createProject: vi.fn().mockResolvedValue(project),
    listProjects: vi.fn().mockResolvedValue([]),
    getProject: vi.fn(),
    listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(),
    getSettings: vi.fn()
  };
}

describe('App', () => {
  it('submits a valid repository and positive worker count, then opens its tasks', async () => {
    const api = apiDouble();
    const user = userEvent.setup();

    render(<App api={api} />);

    await user.type(screen.getByLabelText('Repository URL'), project.repository_url);
    await user.clear(screen.getByLabelText('Fuzzer workers'));
    await user.type(screen.getByLabelText('Fuzzer workers'), '2');
    await user.click(screen.getByRole('button', { name: 'Create project' }));

    expect(api.createProject).toHaveBeenCalledWith({
      repository_url: project.repository_url,
      worker_count: 2
    });
    expect(await screen.findByRole('heading', { name: 'Tasks' })).toBeInTheDocument();
  });
});
