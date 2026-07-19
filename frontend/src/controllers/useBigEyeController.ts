import { useCallback, useEffect, useRef, useState } from 'react';
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
  const selectedProjectIdRef = useRef<string | null>(null);
  const selectedTaskIdRef = useRef<string | null>(null);
  const taskRequestGeneration = useRef(0);
  const logRequestGeneration = useRef(0);
  const createdProjectIds = useRef(new Set<string>());

  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null;

  const loadTasks = useCallback(async (projectId: string) => {
    const requestGeneration = ++taskRequestGeneration.current;
    setTasksLoading(true);
    setTasksError(null);
    try {
      const nextTasks = await api.listTasks(projectId);
      if (requestGeneration !== taskRequestGeneration.current || selectedProjectIdRef.current !== projectId) return;
      setTasks(nextTasks);
      const nextTaskId = nextTasks.some((task) => task.id === selectedTaskIdRef.current)
        ? selectedTaskIdRef.current
        : (nextTasks[0]?.id ?? null);
      if (nextTaskId !== selectedTaskIdRef.current) {
        selectedTaskIdRef.current = nextTaskId;
        setSelectedTaskId(nextTaskId);
        ++logRequestGeneration.current;
        setLogContent('');
        setLogError(null);
      }
    } catch (error) {
      if (requestGeneration !== taskRequestGeneration.current || selectedProjectIdRef.current !== projectId) return;
      setTasks([]);
      setTasksError(message(error, 'Could not load tasks.'));
    } finally {
      if (requestGeneration === taskRequestGeneration.current && selectedProjectIdRef.current === projectId) setTasksLoading(false);
    }
  }, [api]);

  const loadLog = useCallback(async (taskId: string) => {
    const requestGeneration = ++logRequestGeneration.current;
    setLogLoading(true);
    setLogError(null);
    try {
      const log = await api.getTaskLog(taskId, 0);
      if (requestGeneration !== logRequestGeneration.current || selectedTaskIdRef.current !== taskId) return;
      setLogContent(log.content);
    } catch (error) {
      if (requestGeneration !== logRequestGeneration.current || selectedTaskIdRef.current !== taskId) return;
      setLogContent('');
      setLogError(message(error, 'Could not load the task log.'));
    } finally {
      if (requestGeneration === logRequestGeneration.current && selectedTaskIdRef.current === taskId) setLogLoading(false);
    }
  }, [api]);

  const selectProject = useCallback((projectId: string) => {
    selectedProjectIdRef.current = projectId;
    setSelectedProjectId(projectId);
    ++taskRequestGeneration.current;
    ++logRequestGeneration.current;
    setTasks([]);
    setTasksError(null);
    setTasksLoading(false);
    selectedTaskIdRef.current = null;
    setSelectedTaskId(null);
    setLogContent('');
    setLogError(null);
    setLogLoading(false);
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
      createdProjectIds.current.add(project.id);
      setProjects((current) => current.some((item) => item.id === project.id) ? current : [...current, project]);
      selectedProjectIdRef.current = project.id;
      setSelectedProjectId(project.id);
      ++taskRequestGeneration.current;
      ++logRequestGeneration.current;
      setTasks([]);
      setTasksError(null);
      selectedTaskIdRef.current = null;
      setSelectedTaskId(null);
      setLogContent('');
      setLogError(null);
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
    selectedTaskIdRef.current = taskId;
    setSelectedTaskId(taskId);
    ++logRequestGeneration.current;
    setLogContent('');
    setLogError(null);
    setLogLoading(false);
    void loadLog(taskId);
  }, [loadLog]);

  useEffect(() => {
    let active = true;
    void api.listProjects().then((nextProjects) => {
      if (!active) return;
      const createdProjects = (current: Project[]) => current.filter((project) =>
        createdProjectIds.current.has(project.id) && !nextProjects.some((item) => item.id === project.id)
      );
      setProjects((current) => [...nextProjects, ...createdProjects(current)]);
      const selectedProjectStillExists = nextProjects.some((project) => project.id === selectedProjectIdRef.current)
        || createdProjectIds.current.has(selectedProjectIdRef.current ?? '');
      if (!selectedProjectStillExists) {
        const nextProjectId = nextProjects[0]?.id ?? null;
        selectedProjectIdRef.current = nextProjectId;
        setSelectedProjectId(nextProjectId);
      }
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
    }, (eventError) => {
      if (selectedProjectIdRef.current === selectedProjectId) setTasksError(eventError);
    });
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
