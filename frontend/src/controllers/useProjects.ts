import { useCallback, useEffect, useRef, useState } from 'react';
import { MAX_WORKER_COUNT, type Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';

export function useProjects(api: BigEyeApi, onProjectCreated: () => void) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [revision, setRevision] = useState('');
  const [workerCount, setWorkerCount] = useState('1');
  const [privateRepository, setPrivateRepository] = useState(false);
  const [repositoryToken, setRepositoryToken] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selectedProjectIdRef = useRef<string | null>(null);
  const projectRequestGeneration = useRef(0);
  const createdProjectIds = useRef(new Set<string>());

  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null;

  const replaceProject = useCallback((project: Project) => {
    setProjects((current) => current.map((item) => item.id === project.id ? project : item));
  }, []);

  const refreshProject = useCallback(async (projectId: string) => {
    const generation = ++projectRequestGeneration.current;
    try {
      const project = await api.getProject(projectId);
      if (generation !== projectRequestGeneration.current || selectedProjectIdRef.current !== projectId) return;
      replaceProject(project);
    } catch (requestError) {
      if (generation === projectRequestGeneration.current && selectedProjectIdRef.current === projectId) {
        setError(friendlyApiError(requestError, 'BigEye local services are temporarily unavailable.'));
      }
    }
  }, [api, replaceProject]);

  const selectProject = useCallback((projectId: string) => {
    selectedProjectIdRef.current = projectId;
    setSelectedProjectId(projectId);
    void refreshProject(projectId);
  }, [refreshProject]);

  useEffect(() => {
    let active = true;
    void api.listProjects().then((nextProjects) => {
      if (!active) return;
      setProjects((current) => [
        ...nextProjects,
        ...current.filter((project) => createdProjectIds.current.has(project.id) && !nextProjects.some((item) => item.id === project.id))
      ]);
      const currentId = selectedProjectIdRef.current;
      const selectedCreatedProject = currentId !== null && createdProjectIds.current.has(currentId);
      const nextId = nextProjects.some((project) => project.id === currentId) || selectedCreatedProject
        ? currentId
        : (nextProjects[0]?.id ?? null);
      selectedProjectIdRef.current = nextId;
      setSelectedProjectId(nextId);
      if (nextId && nextProjects.some((project) => project.id === nextId)) void refreshProject(nextId);
    }).catch((requestError: unknown) => {
      if (active) setError(friendlyApiError(requestError, 'BigEye local services are temporarily unavailable.'));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [api, refreshProject]);

  const submitProject = useCallback(async () => {
    const workerCountValue = Number(workerCount);
    if (!repositoryUrl.trim()) {
      setError('Repository URL is required.');
      return;
    }
    if (!revision.trim()) {
      setError('Revision is required.');
      return;
    }
    if (!Number.isInteger(workerCountValue) || workerCountValue <= 0) {
      setError('Worker count must be a positive whole number.');
      return;
    }
    if (workerCountValue > MAX_WORKER_COUNT) {
      setError(`Worker count must not exceed ${MAX_WORKER_COUNT}.`);
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const project = await api.createProject({
        repository_url: repositoryUrl.trim(),
        revision: revision.trim(),
        worker_count: workerCountValue,
        ...(privateRepository && repositoryToken ? { repository_token: repositoryToken } : {})
      });
      createdProjectIds.current.add(project.id);
      setProjects((current) => current.some((item) => item.id === project.id) ? current : [...current, project]);
      selectedProjectIdRef.current = project.id;
      setSelectedProjectId(project.id);
      setRepositoryUrl('');
      setRevision('');
      setPrivateRepository(false);
      setRepositoryToken('');
      onProjectCreated();
    } catch (requestError) {
      setError(friendlyApiError(requestError, 'Could not start the project.'));
    } finally {
      setCreating(false);
    }
  }, [api, onProjectCreated, privateRepository, repositoryToken, repositoryUrl, revision, workerCount]);

  return {
    projects, selectedProject, selectedProjectId, loading, error, creating,
    repositoryUrl, revision, workerCount, privateRepository, repositoryToken,
    setRepositoryUrl, setRevision, setWorkerCount, setPrivateRepository, setRepositoryToken,
    selectProject, submitProject, replaceProject
  };
}
