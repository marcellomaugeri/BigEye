import { useCallback, useEffect, useRef, useState } from 'react';
import type { CampaignList } from '../models/campaign';
import type { CoverageTree } from '../models/coverage';
import type { Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from '../services/eventStream';

const UNAVAILABLE = 'Could not refresh the project overview.';

export interface ProjectOverviewModel {
  project: Project | null;
  campaigns: CampaignList | null;
  coverage: CoverageTree | null;
  findingCount: number;
  findingsHaveMore: boolean;
  loading: boolean;
  error: string | null;
}

export function useProjectOverview(
  api: BigEyeApi,
  events: ProjectEventStream,
  project: Project | null,
  enabled: boolean,
  onProjectChange: (project: Project) => void,
): ProjectOverviewModel {
  const [campaigns, setCampaigns] = useState<CampaignList | null>(null);
  const [coverage, setCoverage] = useState<CoverageTree | null>(null);
  const [findingCount, setFindingCount] = useState(0);
  const [findingsHaveMore, setFindingsHaveMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const selectedProjectId = useRef<string | null>(project?.id ?? null);
  const projectId = project?.id ?? null;
  const projectCommit = project?.commit_sha ?? null;
  const onProjectChangeRef = useRef(onProjectChange);
  onProjectChangeRef.current = onProjectChange;

  const reportError = useCallback((requestError: unknown) => {
    setError(friendlyApiError(requestError, UNAVAILABLE));
  }, []);

  useEffect(() => {
    selectedProjectId.current = projectId;
    const currentGeneration = ++generation.current;

    if (!enabled || projectId === null) {
      setCampaigns(null);
      setCoverage(null);
      setFindingCount(0);
      setFindingsHaveMore(false);
      setLoading(false);
      setError(null);
      return;
    }

    const isCurrent = () => generation.current === currentGeneration && selectedProjectId.current === projectId;
    const loadCampaigns = async () => {
      try {
        const value = await api.listCampaigns(projectId);
        if (isCurrent()) setCampaigns(value);
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      }
    };
    const loadCoverage = async () => {
      if (projectCommit === null) return;
      try {
        const value = await api.getCoverageTree(projectId);
        if (isCurrent()) setCoverage(value);
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      }
    };
    const loadFindings = async () => {
      try {
        const value = await api.listFindings(projectId);
        if (isCurrent()) {
          setFindingCount(value.items.length);
          setFindingsHaveMore(value.next_cursor !== null);
        }
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      }
    };
    const loadProject = async () => {
      try {
        const value = await api.getProject(projectId);
        if (isCurrent()) onProjectChangeRef.current(value);
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      }
    };

    setCampaigns(null);
    setCoverage(null);
    setFindingCount(0);
    setFindingsHaveMore(false);
    setError(null);
    setLoading(true);
    void Promise.allSettled([loadCampaigns(), loadCoverage(), loadFindings()]).finally(() => {
      if (isCurrent()) setLoading(false);
    });

    const unsubscribe = events.subscribe(projectId, (name: ProjectInvalidation) => {
      if (name === 'campaigns') void loadCampaigns();
      if (name === 'coverage') void loadCoverage();
      if (name === 'findings') void loadFindings();
      if (name === 'project') void loadProject();
    });
    return () => unsubscribe();
  }, [api, enabled, events, projectCommit, projectId, reportError]);

  return {
    project, campaigns, coverage, findingCount, findingsHaveMore,
    loading, error,
  };
}
