import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { BigEyeApi } from './services/apiClient';

const firstProject = {
  id: 'project-1',
  repository_url: 'https://github.com/example/first.git',
  worker_count: 2,
  commit_sha: null,
  created_at: '2026-07-19T10:00:00Z',
  finished_at: null,
  error: null
};

const secondProject = {
  id: 'project-2',
  repository_url: 'https://github.com/example/second.git',
  worker_count: 3,
  commit_sha: 'f00dbabe',
  created_at: '2026-07-19T11:00:00Z',
  finished_at: '2026-07-19T11:04:00Z',
  error: null
};

const task = {
  id: 'task-1',
  project_id: secondProject.id,
  name: 'Repository analysis',
  created_at: '2026-07-19T11:00:00Z',
  finished_at: null,
  error: null
};

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn().mockResolvedValue(firstProject),
    listProjects: vi.fn().mockResolvedValue([firstProject, secondProject]),
    getProject: vi.fn(),
    listTasks: vi.fn().mockResolvedValue([task]),
    getTaskLog: vi.fn().mockResolvedValue({ content: 'analysis started\n', next_offset: 17 }),
    getSettings: vi.fn().mockResolvedValue({
      database: true,
      docker: false,
      openai_api_key_present: true,
      toolchain: false
    }),
    ...overrides
  };
}

describe('App journey', () => {
  it('keeps genuine projects selectable and loads tasks for the selected project', async () => {
    const api = apiDouble();
    const user = userEvent.setup();

    render(<App api={api} />);

    expect(await screen.findByRole('option', { name: secondProject.repository_url })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Current project'), secondProject.id);
    await user.click(screen.getByRole('link', { name: 'Tasks' }));

    expect(await screen.findByText(task.name)).toBeInTheDocument();
    expect(screen.getByText('Running')).toBeInTheDocument();
    expect(api.listTasks).toHaveBeenCalledWith(secondProject.id);
  });

  it('prevents a non-positive worker count before sending a project request', async () => {
    const api = apiDouble();
    const user = userEvent.setup();

    render(<App api={api} />);

    await user.type(screen.getByLabelText('Repository URL'), firstProject.repository_url);
    await user.clear(screen.getByLabelText('Fuzzer workers'));
    await user.type(screen.getByLabelText('Fuzzer workers'), '0');
    await user.click(screen.getByRole('button', { name: 'Create project' }));

    expect(screen.getByRole('alert')).toHaveTextContent('Worker count must be a positive whole number.');
    expect(api.createProject).not.toHaveBeenCalled();
  });

  it('states truthfully that findings are unavailable until crash processing exists', async () => {
    const user = userEvent.setup();

    render(<App api={apiDouble()} />);

    await user.click(screen.getByRole('link', { name: 'Findings' }));

    expect(await screen.findByText('Crash processing is not implemented yet.')).toBeInTheDocument();
  });

  it('loads the selected project task log from the API', async () => {
    const api = apiDouble();
    const user = userEvent.setup();

    render(<App api={api} />);

    await screen.findByRole('option', { name: secondProject.repository_url });
    await user.selectOptions(screen.getByLabelText('Current project'), secondProject.id);
    await user.click(screen.getByRole('link', { name: 'Logs' }));

    expect(await screen.findByText('analysis started')).toBeInTheDocument();
    expect(api.getTaskLog).toHaveBeenCalledWith(task.id, 0);
  });

  it('renders only health checks returned by settings', async () => {
    const api = apiDouble();
    const user = userEvent.setup();

    render(<App api={api} />);

    await user.click(screen.getByRole('link', { name: 'Settings' }));

    await waitFor(() => expect(api.getSettings).toHaveBeenCalledOnce());
    expect(screen.getByText('Database')).toBeInTheDocument();
    expect(screen.getByText('OpenAI API key')).toBeInTheDocument();
    expect(screen.queryByText(/sk-/i)).not.toBeInTheDocument();
  });
});
