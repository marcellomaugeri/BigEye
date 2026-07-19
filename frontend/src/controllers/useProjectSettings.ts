import { useCallback, useEffect, useRef, useState } from 'react';
import { MAX_WORKER_COUNT, type Project } from '../models/project';
import type { ProjectSettings } from '../models/settings';
import type { BigEyeApi } from '../services/apiClient';

function message(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

export function useProjectSettings(api: BigEyeApi, project: Project | null, enabled: boolean, onProjectChange: (project: Project) => void) {
  const [settings, setSettings] = useState<ProjectSettings | null>(null);
  const [workerCount, setWorkerCount] = useState('');
  const [repositoryToken, setRepositoryToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);

  const load = useCallback(async (projectId: string) => {
    const generation = ++requestGeneration.current;
    setLoading(true);
    setError(null);
    try {
      const value = await api.getProjectSettings(projectId);
      if (generation !== requestGeneration.current) return;
      setSettings(value);
      setWorkerCount(String(value.worker_count));
      setRepositoryToken('');
    } catch (requestError) {
      if (generation === requestGeneration.current) setError(message(requestError, 'Could not load project settings.'));
    } finally {
      if (generation === requestGeneration.current) setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    if (!enabled || !project) return;
    void load(project.id);
  }, [enabled, load, project]);

  const save = useCallback(async () => {
    if (!project || !settings) return;
    const workerCountValue = Number(workerCount);
    if (!Number.isInteger(workerCountValue) || workerCountValue <= 0 || workerCountValue > MAX_WORKER_COUNT) {
      setError('Worker count must be a positive whole number.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const request = {
        worker_count: workerCountValue,
        ...(repositoryToken ? { repository_token: repositoryToken } : {})
      };
      const nextSettings = await api.updateProjectSettings(project.id, request);
      setSettings(nextSettings);
      setWorkerCount(String(nextSettings.worker_count));
      setRepositoryToken('');
    } catch (requestError) {
      setError(message(requestError, 'Could not save project settings.'));
    } finally {
      setSaving(false);
    }
  }, [api, project, repositoryToken, settings, workerCount]);

  const setPaused = useCallback(async (paused: boolean) => {
    if (!project) return;
    setSaving(true);
    setError(null);
    try {
      onProjectChange(paused ? await api.pauseProject(project.id) : await api.resumeProject(project.id));
    } catch (requestError) {
      setError(message(requestError, paused ? 'Could not pause the project.' : 'Could not resume the project.'));
    } finally {
      setSaving(false);
    }
  }, [api, onProjectChange, project]);

  return { settings, workerCount, repositoryToken, loading, saving, error, setWorkerCount, setRepositoryToken, save, setPaused };
}
