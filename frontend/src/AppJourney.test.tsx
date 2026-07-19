import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { BigEyeApi } from './services/apiClient';

const activeProject = {
  id: '7',
  repository_url: 'https://github.com/acme/demo.git',
  requested_revision: 'stable',
  worker_count: 2,
  commit_sha: 'a'.repeat(40),
  token_present: true,
  created_at: '2026-07-19T10:00:00Z',
  paused_at: null,
  error: null
};

function apiDouble(overrides: Record<string, unknown> = {}) {
  return {
    createProject: vi.fn().mockResolvedValue(activeProject),
    listProjects: vi.fn().mockResolvedValue([activeProject]),
    getProject: vi.fn().mockResolvedValue(activeProject),
    getProjectSettings: vi.fn().mockResolvedValue({
      requested_revision: activeProject.requested_revision,
      commit_sha: activeProject.commit_sha,
      worker_count: activeProject.worker_count,
      token_present: activeProject.token_present
    }),
    updateProjectSettings: vi.fn().mockResolvedValue({
      requested_revision: activeProject.requested_revision,
      commit_sha: activeProject.commit_sha,
      worker_count: 4,
      token_present: activeProject.token_present
    }),
    pauseProject: vi.fn().mockResolvedValue({ ...activeProject, paused_at: '2026-07-19T11:00:00Z' }),
    resumeProject: vi.fn().mockResolvedValue(activeProject),
    listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(),
    getSettings: vi.fn(),
    ...overrides
  } as BigEyeApi & Record<string, ReturnType<typeof vi.fn>>;
}

describe('App journey', () => {
  it('keeps implementation names out of primary navigation', async () => {
    render(<App api={apiDouble()} />);

    expect(await screen.findByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    for (const label of ['AFL++', 'libFuzzer', 'Luna', 'Terra', 'Docker']) {
      expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument();
    }
  });

  it('creates a project with revision and an optional private token', async () => {
    const api = apiDouble();
    const user = userEvent.setup();
    render(<App api={api} />);

    await user.type(screen.getByLabelText('Repository URL'), activeProject.repository_url);
    await user.type(screen.getByLabelText('Revision'), 'stable');
    await user.click(screen.getByRole('button', { name: 'Private repository' }));
    await user.type(screen.getByLabelText('Read-only access token'), 'token');
    await user.click(screen.getByRole('button', { name: 'Start project' }));

    expect(api.createProject).toHaveBeenCalledWith(expect.objectContaining({
      repository_url: activeProject.repository_url,
      revision: 'stable',
      repository_token: 'token'
    }));
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
  });

  it('keeps revision and commit read-only while saving worker count and a blank token field', async () => {
    const api = apiDouble();
    const user = userEvent.setup();
    render(<App api={api} />);

    await user.click(screen.getByRole('link', { name: 'Settings' }));
    expect(await screen.findByDisplayValue(activeProject.requested_revision)).toHaveAttribute('readonly');
    expect(screen.getByDisplayValue(activeProject.commit_sha!)).toHaveAttribute('readonly');
    expect(screen.getByLabelText('Read-only access token')).toHaveValue('');
    expect(screen.getByText('Token configured')).toBeInTheDocument();

    await user.clear(screen.getByLabelText('Worker count'));
    await user.type(screen.getByLabelText('Worker count'), '4');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));

    expect(api.updateProjectSettings).toHaveBeenCalledWith(activeProject.id, { worker_count: 4 });
  });

  it('pauses and resumes the selected project through the API', async () => {
    const api = apiDouble();
    const user = userEvent.setup();
    render(<App api={api} />);

    await user.click(screen.getByRole('link', { name: 'Settings' }));
    await screen.findByRole('button', { name: 'Pause project' });
    await user.click(screen.getByRole('button', { name: 'Pause project' }));
    expect(api.pauseProject).toHaveBeenCalledWith(activeProject.id);

    expect(await screen.findByRole('button', { name: 'Resume project' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Resume project' }));
    expect(api.resumeProject).toHaveBeenCalledWith(activeProject.id);
  });

  it('uses truthful unavailable states for future data views', async () => {
    const user = userEvent.setup();
    render(<App api={apiDouble()} />);

    await user.click(screen.getByRole('link', { name: 'Findings' }));
    expect(await screen.findByText('Findings are unavailable until crash processing produces evidence.')).toBeInTheDocument();
  });

  it('retains the selected project when a stale refresh finishes after a newer selection', async () => {
    let resolveFirst!: (project: typeof activeProject) => void;
    const staleRefresh = new Promise<typeof activeProject>((resolve) => { resolveFirst = resolve; });
    const secondProject = { ...activeProject, id: '8', repository_url: 'https://github.com/acme/second.git' };
    const api = apiDouble({
      listProjects: vi.fn().mockResolvedValue([activeProject, secondProject]),
      getProject: vi.fn((projectId: string) => projectId === activeProject.id ? staleRefresh : Promise.resolve(secondProject))
    });
    const user = userEvent.setup();
    render(<App api={api} />);

    await screen.findByRole('option', { name: secondProject.repository_url });
    await user.selectOptions(screen.getByLabelText('Current project'), secondProject.id);
    resolveFirst(activeProject);

    await waitFor(() => expect(screen.getByLabelText('Current project')).toHaveValue(secondProject.id));
  });
});
