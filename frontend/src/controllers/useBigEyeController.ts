import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Project } from '../models/project';
import type { Settings } from '../models/settings';
import type { Task } from '../models/task';
import type { BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream } from '../services/eventStream';

export type Page = 'projects' | 'tasks' | 'findings' | 'logs' | 'settings';

function message(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

export function useBigEyeController(api: BigEyeApi, eventStream: ProjectEventStream) {
  const [page, setPage] = useState<Page>('projects');
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [workerCount, setWorkerCount] = useState('1');
  const [projectError, setProjectError] = useState<string | null>(null);
  const [creatingProject, setCreatingProject] = useState(false);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [tasksLoading, setTasksLoading] = useState(false);
  const [tasksError, setTasksError] = useState<string | null>(null);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [logContent, setLogContent] = useState('');
  const [logLoading, setLogLoading] = useState(false);
  const [logError, setLogError] = useState<string | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null;

  const loadTasks = useCallback(async (projectId: string) => {
    setTasksLoading(true);
    setTasksError(null);
    try {
      const nextTasks = await api.listTasks(projectId);
      setTasks(nextTasks);
      setSelectedTaskId((current) => nextTasks.some((task) => task.id === current) ? current : (nextTasks[0]?.id ?? null));
    } catch (error) {
      setTasks([]);
      setTasksError(message(error, 'Could not load tasks.'));
    } finally {
      setTasksLoading(false);
    }
  }, [api]);

  const loadLog = useCallback(async (taskId: string) => {
    setLogLoading(true);
    setLogError(null);
    try {
      const log = await api.getTaskLog(taskId, 0);
      setLogContent(log.content);
    } catch (error) {
      setLogContent('');
      setLogError(message(error, 'Could not load the task log.'));
    } finally {
      setLogLoading(false);
    }
  }, [api]);

  const selectProject = useCallback((projectId: string) => {
    setSelectedProjectId(projectId);
    setSelectedTaskId(null);
    setLogContent('');
    void loadTasks(projectId);
  }, [loadTasks]);

  const navigate = useCallback((nextPage: Page) => {
    setPage(nextPage);
    if ((nextPage === 'tasks' || nextPage === 'logs') && selectedProjectId) void loadTasks(selectedProjectId);
    if (nextPage === 'settings') {
      setSettingsLoading(true);
      setSettingsError(null);
      void api.getSettings().then(setSettings).catch((error: unknown) => setSettingsError(message(error, 'Could not load checks.'))).finally(() => setSettingsLoading(false));
    }
  }, [api, loadTasks, selectedProjectId]);

  const submitProject = useCallback(async () => {
    const workerCountValue = Number(workerCount);
    if (!repositoryUrl.trim()) {
      setProjectError('Repository URL is required.');
      return;
    }
    if (!Number.isInteger(workerCountValue) || workerCountValue <= 0) {
      setProjectError('Worker count must be a positive whole number.');
      return;
    }
    setCreatingProject(true);
    setProjectError(null);
    try {
      const project = await api.createProject({ repository_url: repositoryUrl.trim(), worker_count: workerCountValue });
      setProjects((current) => current.some((item) => item.id === project.id) ? current : [...current, project]);
      setSelectedProjectId(project.id);
      setRepositoryUrl('');
      setPage('tasks');
      await loadTasks(project.id);
    } catch (error) {
      setProjectError(message(error, 'Could not create the project.'));
    } finally {
      setCreatingProject(false);
    }
  }, [api, loadTasks, repositoryUrl, workerCount]);

  const selectTask = useCallback((taskId: string) => {
    setSelectedTaskId(taskId);
    void loadLog(taskId);
  }, [loadLog]);

  useEffect(() => {
    let active = true;
    void api.listProjects().then((nextProjects) => {
      if (!active) return;
      setProjects(nextProjects);
      setSelectedProjectId((current) => current && nextProjects.some((project) => project.id === current) ? current : (nextProjects[0]?.id ?? null));
    }).catch((error: unknown) => {
      if (active) setProjectError(message(error, 'Could not load projects.'));
    }).finally(() => { if (active) setProjectsLoading(false); });
    return () => { active = false; };
  }, [api]);

  useEffect(() => {
    if (!selectedProjectId) return;
    return eventStream.subscribe(selectedProjectId, () => {
      void loadTasks(selectedProjectId);
      if (selectedTaskId) void loadLog(selectedTaskId);
    }, () => undefined);
  }, [eventStream, loadLog, loadTasks, selectedProjectId, selectedTaskId]);

  useEffect(() => {
    if (page === 'logs' && selectedTaskId) void loadLog(selectedTaskId);
  }, [loadLog, page, selectedTaskId]);

  return {
    page,
    projects,
    selectedProjectId,
    projectsLoading,
    navigate,
    selectProject,
    projectsView: {
      repositoryUrl,
      workerCount,
      loading: creatingProject,
      error: projectError,
      onRepositoryUrlChange: setRepositoryUrl,
      onWorkerCountChange: setWorkerCount,
      onSubmit: submitProject
    },
    tasksView: { hasProject: Boolean(selectedProject), loading: tasksLoading, error: tasksError, tasks },
    logsView: {
      hasProject: Boolean(selectedProject),
      tasks,
      selectedTaskId,
      loading: logLoading || tasksLoading,
      error: logError ?? tasksError,
      content: logContent,
      onSelectTask: selectTask
    },
    settingsView: { loading: settingsLoading, error: settingsError, settings }
  };
}
