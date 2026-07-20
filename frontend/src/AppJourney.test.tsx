import { render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { useProjectSettings } from './controllers/useProjectSettings';
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
    getSettings: vi.fn().mockResolvedValue({ database: true, docker: false, openai_api_key_present: true, toolchain: true }),
    listCampaigns: vi.fn().mockResolvedValue({ project_id: 7, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 7, commit_sha: activeProject.commit_sha, files: [], pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(),
    getLineEvidence: vi.fn(),
    retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null }),
    getFinding: vi.fn(), findingReproducerUrl: vi.fn(), getProjectLog: vi.fn(),
    ...overrides
  } as BigEyeApi & Record<string, ReturnType<typeof vi.fn>>;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe('App journey', () => {
  afterEach(() => { window.history.replaceState(null, '', '/'); });

  it('keeps implementation names out of primary navigation', async () => {
    render(<App api={apiDouble()} />);

    expect(await screen.findByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    expect(screen.getByText('Continuous assurance')).toBeVisible();
    expect(screen.queryByText('Repository intelligence')).not.toBeInTheDocument();
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

  it('loads host health with project settings and presents compact local service checks', async () => {
    const api = apiDouble();
    const { result } = renderHook(() => useProjectSettings(api, activeProject, true, vi.fn()));

    await waitFor(() => expect(result.current.localServices?.database).toBe(true));
    expect(api.getProjectSettings).toHaveBeenCalledWith('7');
    expect(api.getSettings).toHaveBeenCalledTimes(1);

    const user = userEvent.setup();
    render(<App api={api} />);
    await user.click(screen.getByRole('link', { name: 'Settings' }));
    const services = await screen.findByRole('heading', { name: 'Local services' });
    const section = services.closest('section')!;
    expect(within(section).getByText('Database')).toBeVisible();
    expect(within(section).getByText('Docker')).toBeVisible();
    expect(within(section).getByText('OpenAI access')).toBeVisible();
    expect(within(section).getByText('Toolchain')).toBeVisible();
    expect(within(section).getByText('Needs attention')).toBeVisible();
    expect(within(section).queryByText(/sk-|api key/i)).not.toBeInTheDocument();
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

  it('uses a truthful empty state for replayed findings', async () => {
    const user = userEvent.setup();
    render(<App api={apiDouble()} />);

    await user.click(screen.getByRole('link', { name: 'Findings' }));
    expect(await screen.findByText('No replayed findings yet.')).toBeInTheDocument();
    expect(screen.queryByText(/not implemented/i)).not.toBeInTheDocument();
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

  it('keeps a newly created project selected when the initial list resolves without it', async () => {
    const initialProjects = deferred<typeof activeProject[]>();
    const createdProject = { ...activeProject, id: '9', repository_url: 'https://github.com/acme/created.git' };
    const api = apiDouble({
      listProjects: vi.fn().mockReturnValue(initialProjects.promise),
      createProject: vi.fn().mockResolvedValue(createdProject),
      getProject: vi.fn().mockResolvedValue(activeProject)
    });
    const user = userEvent.setup();
    render(<App api={api} />);

    await user.type(screen.getByLabelText('Repository URL'), createdProject.repository_url);
    await user.type(screen.getByLabelText('Revision'), createdProject.requested_revision);
    await user.click(screen.getByRole('button', { name: 'Start project' }));
    initialProjects.resolve([activeProject]);

    expect(await screen.findByRole('option', { name: createdProject.repository_url })).toBeInTheDocument();
    expect(screen.getByLabelText('Current project')).toHaveValue(createdProject.id);
  });

  it('keeps project B settings when a delayed save for project A completes', async () => {
    const secondProject = { ...activeProject, id: '8', repository_url: 'https://github.com/acme/second.git', worker_count: 3 };
    const secondSettings = deferred<{ requested_revision: string; commit_sha: string | null; worker_count: number; token_present: boolean }>();
    const saveA = deferred<{ requested_revision: string; commit_sha: string | null; worker_count: number; token_present: boolean }>();
    const api = apiDouble({
      listProjects: vi.fn().mockResolvedValue([activeProject, secondProject]),
      getProject: vi.fn((projectId: string) => Promise.resolve(projectId === secondProject.id ? secondProject : activeProject)),
      getProjectSettings: vi.fn()
        .mockResolvedValueOnce({ requested_revision: activeProject.requested_revision, commit_sha: activeProject.commit_sha, worker_count: activeProject.worker_count, token_present: activeProject.token_present })
        .mockReturnValueOnce(secondSettings.promise),
      updateProjectSettings: vi.fn().mockReturnValue(saveA.promise)
    });
    const user = userEvent.setup();
    render(<App api={api} />);

    await user.click(screen.getByRole('link', { name: 'Settings' }));
    await screen.findByDisplayValue(String(activeProject.worker_count));
    await user.clear(screen.getByLabelText('Worker count'));
    await user.type(screen.getByLabelText('Worker count'), '4');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    await user.selectOptions(screen.getByLabelText('Current project'), secondProject.id);
    await waitFor(() => expect(api.getProjectSettings).toHaveBeenCalledWith(secondProject.id));
    secondSettings.resolve({ requested_revision: secondProject.requested_revision, commit_sha: secondProject.commit_sha, worker_count: secondProject.worker_count, token_present: false });

    expect(await screen.findByDisplayValue('3')).toBeInTheDocument();
    saveA.resolve({ requested_revision: activeProject.requested_revision, commit_sha: activeProject.commit_sha, worker_count: 4, token_present: activeProject.token_present });

    await waitFor(() => expect(screen.getByLabelText('Worker count')).toHaveValue(3));
  });
});
