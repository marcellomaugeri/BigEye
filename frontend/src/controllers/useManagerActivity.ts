import { useEffect, useRef, useState } from 'react';
import type { CampaignList } from '../models/campaign';
import type { ProjectEvent } from '../models/event';
import type { Project } from '../models/project';
import type { BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from '../services/eventStream';

const ACTIVITY_PAGE_SIZE = 1;
const DEBUG_PAGE_SIZE = 64;
const RECENT_DECISION_MILLISECONDS = 90_000;
const FRESH_HEARTBEAT_MILLISECONDS = 120_000;
const FUTURE_CLOCK_TOLERANCE_MILLISECONDS = 30_000;
const MESSAGE_LIMIT = 180;

interface ManagerActivityInput {
  project: Project | null;
  campaigns: CampaignList | null;
  activityEvents: ProjectEvent[];
  debugEvents: ProjectEvent[];
  loading: boolean;
  unavailable: boolean;
  now: Date;
}

interface ResourceFailures {
  activity: boolean;
  campaigns: boolean;
  debug: boolean;
}

export interface ManagerActivityModel {
  message: string | null;
  loading: boolean;
  unavailable: boolean;
}

function timestamp(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function isRecent(value: string, now: Date, windowMilliseconds: number): boolean {
  const observed = timestamp(value);
  if (observed === null) return false;
  const age = now.getTime() - observed;
  return age >= -FUTURE_CLOCK_TOLERANCE_MILLISECONDS && age <= windowMilliseconds;
}

function managerIsReviewing(events: ProjectEvent[]): boolean {
  const boundary = events.find((event) => (
    event.payload.agent === 'Campaign manager'
    && ['agent.start', 'agent.end', 'workflow.error'].includes(String(event.payload.event))
  ));
  return boundary?.payload.event === 'agent.start';
}

function conciseDecision(events: ProjectEvent[], now: Date): string | null {
  const latest = events.find((event) => (
    typeof event.payload.decision === 'string'
    && event.payload.decision.trim().length > 0
    && isRecent(event.created_at, now, RECENT_DECISION_MILLISECONDS)
  ));
  if (!latest) return null;
  const value = (latest.payload.decision as string).trim();
  return value.length <= MESSAGE_LIMIT ? value : `${value.slice(0, MESSAGE_LIMIT - 1).trimEnd()}…`;
}

export function managerActivityMessage(input: ManagerActivityInput): string | null {
  const { project, campaigns, activityEvents, debugEvents, loading, unavailable, now } = input;
  if (project === null) return null;
  if (project.error !== null) return 'Project preparation needs attention.';
  if (project.commit_sha === null) return 'Preparing the repository...';
  if (managerIsReviewing(debugEvents)) return 'Manager is reviewing campaign evidence...';

  const decision = conciseDecision(activityEvents, now);
  if (decision !== null) return `Manager: ${decision}`;

  if (campaigns !== null) {
    const active = campaigns.campaigns.filter((campaign) => campaign.activity === 'running');
    if (active.some((campaign) => campaign.error !== null)) {
      return 'A fuzzing instance needs attention.';
    }
    if (active.some((campaign) => (
      campaign.last_heartbeat_at !== null
      && isRecent(campaign.last_heartbeat_at, now, FRESH_HEARTBEAT_MILLISECONDS)
    ))) {
      return 'Fuzzing at full speed!';
    }
    if (active.some((campaign) => (
      campaign.last_heartbeat_at === null
      && isRecent(campaign.started_at, now, FRESH_HEARTBEAT_MILLISECONDS)
    ))) {
      return 'Starting fuzzing instances...';
    }
    if (active.length > 0) return 'Waiting for campaign telemetry...';
    return 'Waiting for the manager\'s next decision...';
  }

  if (loading) return 'Checking campaign activity...';
  if (unavailable) return 'Manager activity is temporarily unavailable.';
  return 'Waiting for the manager\'s first decision...';
}

export function useManagerActivity(
  api: BigEyeApi,
  events: ProjectEventStream,
  project: Project | null,
): ManagerActivityModel {
  const [campaigns, setCampaigns] = useState<CampaignList | null>(null);
  const [activityEvents, setActivityEvents] = useState<ProjectEvent[]>([]);
  const [debugEvents, setDebugEvents] = useState<ProjectEvent[]>([]);
  const [failures, setFailures] = useState<ResourceFailures>({
    activity: false, campaigns: false, debug: false,
  });
  const [loading, setLoading] = useState(false);
  const [now, setNow] = useState(() => new Date());
  const generation = useRef(0);
  const projectId = project?.id ?? null;

  useEffect(() => {
    const currentGeneration = ++generation.current;
    setCampaigns(null);
    setActivityEvents([]);
    setDebugEvents([]);
    setFailures({ activity: false, campaigns: false, debug: false });
    setNow(new Date());
    if (projectId === null) {
      setLoading(false);
      return;
    }

    const isCurrent = () => generation.current === currentGeneration;
    const loadCampaigns = async () => {
      try {
        const value = await api.listCampaigns(projectId);
        if (!value || !Array.isArray(value.campaigns)) throw new TypeError('invalid campaign list');
        if (isCurrent()) {
          setCampaigns(value);
          setFailures((current) => ({ ...current, campaigns: false }));
        }
      } catch {
        if (isCurrent()) setFailures((current) => ({ ...current, campaigns: true }));
      }
    };
    const loadLog = async (stream: 'activity' | 'debug') => {
      const limit = stream === 'activity' ? ACTIVITY_PAGE_SIZE : DEBUG_PAGE_SIZE;
      try {
        const page = await api.getProjectLog(projectId, stream, -1, limit);
        if (!page || !Array.isArray(page.events)) throw new TypeError('invalid project log page');
        if (isCurrent()) {
          if (stream === 'activity') setActivityEvents(page.events);
          else setDebugEvents(page.events);
          setFailures((current) => ({ ...current, [stream]: false }));
        }
      } catch {
        if (isCurrent()) setFailures((current) => ({ ...current, [stream]: true }));
      }
    };

    setLoading(true);
    void Promise.allSettled([loadCampaigns(), loadLog('activity'), loadLog('debug')]).finally(() => {
      if (isCurrent()) setLoading(false);
    });
    const unsubscribe = events.subscribe(projectId, (name: ProjectInvalidation) => {
      if (name === 'campaigns') void loadCampaigns();
      if (name === 'activity') void loadLog('activity');
      if (name === 'debug') void loadLog('debug');
    });
    const clock = window.setInterval(() => setNow(new Date()), 15_000);
    return () => {
      window.clearInterval(clock);
      unsubscribe();
    };
  }, [api, events, projectId]);

  const unavailable = failures.activity && failures.campaigns && failures.debug;
  return {
    message: managerActivityMessage({
      project, campaigns, activityEvents, debugEvents, loading, unavailable, now,
    }),
    loading,
    unavailable,
  };
}
