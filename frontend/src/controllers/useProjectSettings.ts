import { useCallback, useEffect, useRef, useState } from 'react';
import { MAX_WORKER_COUNT, type Project } from '../models/project';
import type { ProjectSettings, Settings } from '../models/settings';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';

export function useProjectSettings(api: BigEyeApi, project: Project | null, enabled: boolean, onProjectChange: (project: Project) => void) {
  const [settings, setSettings] = useState<ProjectSettings | null>(null);
  const [localServices, setLocalServices] = useState<Settings | null>(null);
  const [workerCount, setWorkerCount] = useState('');
  const [repositoryToken, setRepositoryToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);
  const selectedProjectIdRef = useRef<string | null>(project?.id ?? null);
  const settingsProjectIdRef = useRef<string | null>(null);
  selectedProjectIdRef.current = project?.id ?? null;

  const load = useCallback(async (projectId: string) => {
    const generation = ++requestGeneration.current;
    settingsProjectIdRef.current = null;
    setSettings(null);
    setWorkerCount('');
    setRepositoryToken('');
    setLocalServices(null);
    setLoading(true);
    setError(null);
    try {
      const [projectResult, servicesResult] = await Promise.allSettled([
        api.getProjectSettings(projectId), api.getSettings(),
      ]);
      if (generation !== requestGeneration.current) return;
      if (projectResult.status === 'fulfilled') {
        settingsProjectIdRef.current = projectId;
        setSettings(projectResult.value);
        setWorkerCount(String(projectResult.value.worker_count));
        setRepositoryToken('');
      } else {
        setError(friendlyApiError(projectResult.reason, 'Could not load project settings.'));
      }
      if (servicesResult.status === 'fulfilled') {
        setLocalServices(servicesResult.value);
      } else {
        setLocalServices(null);
        setError((current) => current ?? friendlyApiError(
          servicesResult.reason, 'Could not load local service checks.',
        ));
      }
    } catch (requestError) {
      if (generation === requestGeneration.current) {
        setError(friendlyApiError(requestError, 'Could not load project settings.'));
      }
    } finally {
      if (generation === requestGeneration.current) setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    if (!enabled || !project) {
      requestGeneration.current += 1;
      settingsProjectIdRef.current = null;
      setSettings(null);
      setLocalServices(null);
      setWorkerCount('');
      setRepositoryToken('');
      setLoading(false);
      setSaving(false);
      return;
    }
    setSaving(false);
    void load(project.id);
  }, [enabled, load, project]);

  const save = useCallback(async () => {
    if (!project || !settings || settingsProjectIdRef.current !== project.id) return;
    const workerCountValue = Number(workerCount);
    if (!Number.isInteger(workerCountValue) || workerCountValue <= 0 || workerCountValue > MAX_WORKER_COUNT) {
      setError('Worker count must be a positive whole number.');
      return;
    }
    const projectId = project.id;
    const generation = ++requestGeneration.current;
    setSaving(true);
    setError(null);
    try {
      const request = {
        worker_count: workerCountValue,
        ...(repositoryToken ? { repository_token: repositoryToken } : {})
      };
      const nextSettings = await api.updateProjectSettings(projectId, request);
      if (generation !== requestGeneration.current || selectedProjectIdRef.current !== projectId) return;
      setSettings(nextSettings);
      setWorkerCount(String(nextSettings.worker_count));
      setRepositoryToken('');
    } catch (requestError) {
      if (generation === requestGeneration.current && selectedProjectIdRef.current === projectId) {
        setError(friendlyApiError(requestError, 'Could not save project settings.'));
      }
    } finally {
      if (generation === requestGeneration.current && selectedProjectIdRef.current === projectId) setSaving(false);
    }
  }, [api, project, repositoryToken, settings, workerCount]);

  const setPaused = useCallback(async (paused: boolean) => {
    if (!project) return;
    const projectId = project.id;
    const generation = ++requestGeneration.current;
    setSaving(true);
    setError(null);
    try {
      const updated = paused ? await api.pauseProject(projectId) : await api.resumeProject(projectId);
      if (generation !== requestGeneration.current || selectedProjectIdRef.current !== projectId) return;
      onProjectChange(updated);
    } catch (requestError) {
      if (generation === requestGeneration.current && selectedProjectIdRef.current === projectId) {
        setError(friendlyApiError(
          requestError, paused ? 'Could not pause the project.' : 'Could not resume the project.',
        ));
      }
    } finally {
      if (generation === requestGeneration.current && selectedProjectIdRef.current === projectId) {
        setSaving(false);
      }
    }
  }, [api, onProjectChange, project]);

  return {
    settings, localServices, workerCount, repositoryToken, loading, saving, error,
    setWorkerCount, setRepositoryToken, save, setPaused,
  };
}
