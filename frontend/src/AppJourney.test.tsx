import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { Project } from './models/project';
import type { Task } from './models/task';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream } from './services/eventStream';

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

const firstTask: Task = { ...task, id: 'task-first', project_id: firstProject.id, name: 'First project task' };
const secondTask: Task = { ...task, id: 'task-second', project_id: secondProject.id, name: 'Second project task' };
const thirdTask: Task = { ...task, id: 'task-third', project_id: firstProject.id, name: 'Second task log' };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function apiDouble(overrides: Partial<BigEyeApi> = {}): BigEyeApi {
  return {
    createProject: vi.fn().mockResolvedValue(firstProject),
    listProjects: vi.fn().mockResolvedValue([firstProject, secondProject]),
    getProject: vi.fn().mockResolvedValue(firstProject),
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

  it('keeps tasks for the newly selected project when an earlier request finishes late', async () => {
    const firstTasks = deferred<Task[]>();
    const secondTasks = deferred<Task[]>();
    const api = apiDouble({
      listTasks: vi.fn((projectId: string) => projectId === firstProject.id ? firstTasks.promise : secondTasks.promise)
    });
    const user = userEvent.setup();

    render(<App api={api} />);

    await screen.findByRole('option', { name: secondProject.repository_url });
    await user.click(screen.getByRole('link', { name: 'Tasks' }));
    await user.selectOptions(screen.getByLabelText('Current project'), secondProject.id);
    secondTasks.resolve([secondTask]);

    expect(await screen.findByText(secondTask.name)).toBeInTheDocument();
    firstTasks.resolve([firstTask]);

    await waitFor(() => expect(screen.queryByText(firstTask.name)).not.toBeInTheDocument());
    expect(screen.getByText(secondTask.name)).toBeInTheDocument();
  });

  it('keeps the newly selected task log when an earlier task log finishes late', async () => {
    const firstLog = deferred<{ content: string; next_offset: number }>();
    const secondLog = deferred<{ content: string; next_offset: number }>();
    const api = apiDouble({
      listTasks: vi.fn().mockResolvedValue([firstTask, thirdTask]),
      getTaskLog: vi.fn((taskId: string) => taskId === firstTask.id ? firstLog.promise : secondLog.promise)
    });
    const user = userEvent.setup();

    render(<App api={api} />);

    await screen.findByRole('option', { name: secondProject.repository_url });
    await user.click(screen.getByRole('link', { name: 'Logs' }));
    await screen.findByRole('option', { name: thirdTask.name });
    await user.selectOptions(screen.getByLabelText('Task log'), thirdTask.id);
    secondLog.resolve({ content: 'second log\n', next_offset: 11 });

    expect(await screen.findByText('second log')).toBeInTheDocument();
    firstLog.resolve({ content: 'first log\n', next_offset: 10 });

    await waitFor(() => expect(screen.queryByText('first log')).not.toBeInTheDocument());
    expect(screen.getByText('second log')).toBeInTheDocument();
  });

  it('preserves a project created while the initial project list is still loading', async () => {
    const initialProjects = deferred<Project[]>();
    const createdProject: Project = { ...secondProject, id: 'project-created', repository_url: 'https://github.com/example/created.git' };
    const api = apiDouble({
      listProjects: vi.fn().mockReturnValue(initialProjects.promise),
      createProject: vi.fn().mockResolvedValue(createdProject),
      listTasks: vi.fn().mockResolvedValue([])
    });
    const user = userEvent.setup();

    render(<App api={api} />);

    await user.type(screen.getByLabelText('Repository URL'), createdProject.repository_url);
    await user.click(screen.getByRole('button', { name: 'Create project' }));
    expect(await screen.findByRole('heading', { name: 'Tasks' })).toBeInTheDocument();
    initialProjects.resolve([firstProject]);

    expect(await screen.findByRole('option', { name: createdProject.repository_url })).toBeInTheDocument();
    expect(screen.getByLabelText('Current project')).toHaveValue(createdProject.id);
  });

  it('clears a stale log loading state after creating a taskless project', async () => {
    const firstLog = deferred<{ content: string; next_offset: number }>();
    const createdProject: Project = { ...secondProject, id: 'project-created', repository_url: 'https://github.com/example/created.git' };
    const api = apiDouble({
      createProject: vi.fn().mockResolvedValue(createdProject),
      listTasks: vi.fn((projectId: string) => Promise.resolve(projectId === firstProject.id ? [firstTask] : [])),
      getTaskLog: vi.fn().mockReturnValue(firstLog.promise)
    });
    const user = userEvent.setup();

    render(<App api={api} />);

    await screen.findByRole('option', { name: secondProject.repository_url });
    await user.click(screen.getByRole('link', { name: 'Logs' }));
    await waitFor(() => expect(api.getTaskLog).toHaveBeenCalledWith(firstTask.id, 0));
    await user.click(screen.getByRole('link', { name: 'Projects' }));
    await user.type(screen.getByLabelText('Repository URL'), createdProject.repository_url);
    await user.click(screen.getByRole('button', { name: 'Create project' }));
    expect(await screen.findByRole('heading', { name: 'Tasks' })).toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'Logs' }));

    expect(await screen.findByText('This project has no task logs yet.')).toBeInTheDocument();
  });

  it('shows an operational error when the project event stream fails', async () => {
    let reportError: ((message: string) => void) | undefined;
    const eventStream: ProjectEventStream = {
      subscribe: vi.fn((_projectId, _onEvent, onError) => {
        reportError = onError;
        return () => undefined;
      })
    };
    const user = userEvent.setup();

    render(<App api={apiDouble()} eventStream={eventStream} />);

    await screen.findByRole('option', { name: secondProject.repository_url });
    await user.click(screen.getByRole('link', { name: 'Tasks' }));
    reportError?.('Live updates are temporarily unavailable.');

    expect(await screen.findByRole('alert')).toHaveTextContent('Live updates are temporarily unavailable.');
  });

  it('refreshes the selected project on a live event and renders its genuine completion state', async () => {
    let notify: (() => void) | undefined;
    const completed = { ...firstProject, commit_sha: 'a'.repeat(40), finished_at: '2026-07-19T12:00:00Z' };
    const api = apiDouble({ getProject: vi.fn().mockResolvedValue(completed) });
    const eventStream: ProjectEventStream = { subscribe: vi.fn((_id, onEvent) => { notify = onEvent; return () => undefined; }) };
    render(<App api={api} eventStream={eventStream} />);
    await screen.findByRole('option', { name: secondProject.repository_url });
    await waitFor(() => expect(eventStream.subscribe).toHaveBeenCalled());
    notify?.();
    await waitFor(() => expect(api.getProject).toHaveBeenCalledWith(firstProject.id));
    expect(await screen.findByText(/Complete/)).toBeInTheDocument();
    expect(screen.getByText(completed.commit_sha)).toBeInTheDocument();
  });

  it('appends only new log bytes after a live event', async () => {
    let notify: (() => void) | undefined;
    const api = apiDouble({ getTaskLog: vi.fn().mockResolvedValueOnce({ content: 'one\n', next_offset: 4 }).mockResolvedValueOnce({ content: 'two\n', next_offset: 8 }) });
    const eventStream: ProjectEventStream = { subscribe: vi.fn((_id, onEvent) => { notify = onEvent; return () => undefined; }) };
    const user = userEvent.setup();
    render(<App api={api} eventStream={eventStream} />);
    await screen.findByRole('option', { name: secondProject.repository_url });
    await waitFor(() => expect(eventStream.subscribe).toHaveBeenCalled());
    await user.click(screen.getByRole('link', { name: 'Logs' }));
    expect(await screen.findByText('one')).toBeInTheDocument();
    notify?.();
    await waitFor(() => expect(screen.getByLabelText('Task log output')).toHaveTextContent('two'));
    expect(api.getTaskLog).toHaveBeenLastCalledWith(task.id, 4);
    expect(screen.getByLabelText('Task log output').textContent).toBe('one\ntwo\n');
  });

  it('drains all available bounded log chunks without waiting for another event', async () => {
    const firstChunk = 'a'.repeat(64 * 1024);
    const api = apiDouble({
      getTaskLog: vi.fn()
        .mockResolvedValueOnce({ content: firstChunk, next_offset: firstChunk.length })
        .mockResolvedValueOnce({ content: 'tail', next_offset: firstChunk.length + 4 })
    });
    const user = userEvent.setup();
    render(<App api={api} />);
    await screen.findByRole('option', { name: secondProject.repository_url });
    await user.click(screen.getByRole('link', { name: 'Logs' }));
    await waitFor(() => expect(api.getTaskLog).toHaveBeenLastCalledWith(task.id, firstChunk.length));
    expect(screen.getByLabelText('Task log output').textContent).toBe(`${firstChunk}tail`);
  });

  it('preserves the existing log and cursor when an incremental request fails', async () => {
    let notify: (() => void) | undefined;
    const api = apiDouble({
      getTaskLog: vi.fn()
        .mockResolvedValueOnce({ content: 'one\n', next_offset: 4 })
        .mockRejectedValueOnce(new Error('temporary failure'))
        .mockResolvedValueOnce({ content: 'two\n', next_offset: 8 })
        .mockResolvedValueOnce({ content: '', next_offset: 8 })
    });
    const eventStream: ProjectEventStream = { subscribe: vi.fn((_id, onEvent) => { notify = onEvent; return () => undefined; }) };
    const user = userEvent.setup();
    render(<App api={api} eventStream={eventStream} />);
    await screen.findByRole('option', { name: secondProject.repository_url });
    await waitFor(() => expect(eventStream.subscribe).toHaveBeenCalled());
    await user.click(screen.getByRole('link', { name: 'Logs' }));
    expect(await screen.findByText('one')).toBeInTheDocument();
    notify?.();
    expect(await screen.findByRole('alert')).toHaveTextContent('temporary failure');
    expect(screen.getByLabelText('Task log output').textContent).toBe('one\n');
    notify?.();
    await waitFor(() => expect(api.getTaskLog).toHaveBeenLastCalledWith(task.id, 4));
    expect(screen.getByLabelText('Task log output').textContent).toBe('one\ntwo\n');
  });
});
