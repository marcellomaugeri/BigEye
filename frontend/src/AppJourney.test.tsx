import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
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
    listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(),
    getSettings: vi.fn().mockResolvedValue({ database: true, docker: false, openai_api_key_present: true, toolchain: true }),
    listCampaigns: vi.fn().mockResolvedValue({ project_id: 7, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 7, commit_sha: activeProject.commit_sha, files: [], summary: { lines: null, functions: null, branches: null }, pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(),
    getCoverageFunctions: vi.fn(),
    getLineEvidence: vi.fn(),
    retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null }),
    getFinding: vi.fn(), findingReproducerUrl: vi.fn(), startFindingReproduction: vi.fn(), findingReproductionEventsUrl: vi.fn(), getProjectLog: vi.fn(), getProjectEvent: vi.fn(),
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

  it('keeps the application chrome sparse and implementation names out of navigation', async () => {
    render(<App api={apiDouble()} />);

    expect(await screen.findByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    expect(screen.getAllByText('BigEye')).toHaveLength(1);
    expect(screen.queryByText('Continuous assurance')).not.toBeInTheDocument();
    expect(screen.queryByText('Campaign workspace')).not.toBeInTheDocument();
    expect(screen.queryByText('Repository intelligence')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Fuzzing' })).toBeVisible();
    for (const label of ['AFL++', 'libFuzzer', 'Luna', 'Terra', 'Docker']) {
      expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument();
    }
  });

  it('creates a project with revision and an optional private token', async () => {
    const api = apiDouble();
    const user = userEvent.setup();
    render(<App api={api} />);

    await user.click(screen.getByRole('button', { name: 'New project' }));
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

  it('opens project creation in a focus-managed modal and restores focus when dismissed', async () => {
    const user = userEvent.setup();
    render(<App api={apiDouble()} />);

    const trigger = await screen.findByRole('button', { name: 'New project' });
    expect(screen.queryByRole('dialog', { name: 'New project' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Repository URL')).not.toBeInTheDocument();

    await user.click(trigger);

    expect(screen.getByRole('dialog', { name: 'New project' })).toBeVisible();
    expect(screen.getByLabelText('Repository URL')).toHaveFocus();

    await user.keyboard('{Escape}');

    expect(screen.queryByRole('dialog', { name: 'New project' })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('returns to Projects with exact guidance from every project-dependent page', async () => {
    const user = userEvent.setup();
    render(<App api={apiDouble({ listProjects: vi.fn().mockResolvedValue([]) })} />);

    await screen.findByRole('heading', { name: 'Projects' });
    for (const page of ['Overview', 'Fuzzing', 'Source', 'Findings', 'Activity', 'Settings']) {
      await user.click(screen.getByRole('link', { name: page }));
      expect(await screen.findByRole('status')).toHaveTextContent('Select or create a project first.');
      expect(screen.getByRole('heading', { name: 'Projects' })).toBeVisible();
      expect(window.location.hash).toBe('#projects');
    }
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

    await user.clear(screen.getByLabelText('Concurrent jobs'));
    await user.type(screen.getByLabelText('Concurrent jobs'), '4');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));

    expect(api.updateProjectSettings).toHaveBeenCalledWith(activeProject.id, { worker_count: 4 });
  });

  it('loads host health with project settings and presents compact local service checks', async () => {
    const api = apiDouble();
    const { result } = renderHook(() => useProjectSettings(api, activeProject, true));

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

  it('keeps scheduling autonomous in Settings', async () => {
    const user = userEvent.setup();
    render(<App api={apiDouble()} />);
    await user.click(screen.getByRole('link', { name: 'Settings' }));
    expect(await screen.findByLabelText('Concurrent jobs')).toBeVisible();
    for (const label of [/pause/i, /resume/i, /stop/i, /restart/i]) {
      expect(screen.queryByRole('button', { name: label })).not.toBeInTheDocument();
    }
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

    await user.click(screen.getByRole('button', { name: 'New project' }));
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
    await user.clear(screen.getByLabelText('Concurrent jobs'));
    await user.type(screen.getByLabelText('Concurrent jobs'), '4');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    await user.selectOptions(screen.getByLabelText('Current project'), secondProject.id);
    await waitFor(() => expect(api.getProjectSettings).toHaveBeenCalledWith(secondProject.id));
    secondSettings.resolve({ requested_revision: secondProject.requested_revision, commit_sha: secondProject.commit_sha, worker_count: secondProject.worker_count, token_present: false });

    expect(await screen.findByDisplayValue('3')).toBeInTheDocument();
    saveA.resolve({ requested_revision: activeProject.requested_revision, commit_sha: activeProject.commit_sha, worker_count: 4, token_present: activeProject.token_present });

    await waitFor(() => expect(screen.getByLabelText('Concurrent jobs')).toHaveValue(3));
  });

  it('clears project A settings while project B settings are loading', async () => {
    const secondProject = { ...activeProject, id: '8', repository_url: 'https://github.com/acme/second.git' };
    const secondSettings = deferred<{ requested_revision: string; commit_sha: string | null; worker_count: number; token_present: boolean }>();
    const api = apiDouble({
      getProjectSettings: vi.fn((projectId: string) => projectId === activeProject.id
        ? Promise.resolve({ requested_revision: activeProject.requested_revision, commit_sha: activeProject.commit_sha, worker_count: 2, token_present: true })
        : secondSettings.promise),
    });
    const { result, rerender } = renderHook(
      ({ project }) => useProjectSettings(api, project, true),
      { initialProps: { project: activeProject } },
    );
    await waitFor(() => expect(result.current.workerCount).toBe('2'));

    rerender({ project: secondProject });
    await waitFor(() => expect(api.getProjectSettings).toHaveBeenCalledWith(secondProject.id));
    expect(result.current.settings).toBeNull();
    expect(result.current.workerCount).toBe('');
    await act(async () => { await result.current.save(); });
    expect(api.updateProjectSettings).not.toHaveBeenCalled();

    secondSettings.resolve({ requested_revision: secondProject.requested_revision, commit_sha: secondProject.commit_sha, worker_count: 3, token_present: false });
    await waitFor(() => expect(result.current.workerCount).toBe('3'));
  });

});
