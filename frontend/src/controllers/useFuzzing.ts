import { useCallback, useEffect, useRef, useState } from 'react';
import type { Campaign } from '../models/campaign';
import type { FuzzingModel, FuzzingRow } from '../models/fuzzing';
import type { Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream } from '../services/eventStream';

function campaignState(campaign: Campaign): string {
  if (campaign.error !== null) return 'Needs attention';
  if (campaign.retirement_reason !== null) return 'Retired';
  if (campaign.activity === 'stopped') return 'Stopped';
  if (campaign.activity === 'running') return 'Running';
  return 'Waiting';
}

function row(campaign: Campaign): FuzzingRow {
  return {
    id: campaign.id,
    target: campaign.target_name,
    configuration: campaign.configuration_name,
    purpose: campaign.configuration_purpose,
    engine: campaign.engine,
    activity: campaign.activity,
    coverageDelta5m: campaign.covered_line_delta_5m,
    totalReach: campaign.total_reached_lines,
    cpuExposureSeconds: campaign.cpu_exposure_seconds,
    lastEvidenceAt: campaign.last_heartbeat_at,
    state: campaignState(campaign),
  };
}

export function useFuzzing(
  api: BigEyeApi,
  events: ProjectEventStream,
  project: Project | null,
  enabled: boolean,
): FuzzingModel {
  const [rows, setRows] = useState<FuzzingRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const projectId = project?.id ?? null;

  const load = useCallback(async (id: string, currentGeneration: number) => {
    try {
      const response = await api.listCampaigns(id);
      if (generation.current !== currentGeneration) return;
      setRows(response.campaigns.map(row));
      setError(null);
    } catch (requestError) {
      if (generation.current === currentGeneration) {
        setError(friendlyApiError(requestError, 'Fuzzing evidence is temporarily unavailable.'));
      }
    } finally {
      if (generation.current === currentGeneration) setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    const currentGeneration = ++generation.current;
    setRows([]);
    setError(null);
    if (!enabled || projectId === null) {
      setLoading(false);
      return;
    }
    setLoading(true);
    void load(projectId, currentGeneration);
    const unsubscribe = events.subscribe(projectId, (name) => {
      if (name === 'campaigns' || name === 'coverage' || name === 'activity') {
        void load(projectId, currentGeneration);
      }
    });
    return () => unsubscribe();
  }, [enabled, events, load, projectId]);

  return { project, rows, loading, error };
}
