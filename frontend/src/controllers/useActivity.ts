import { useCallback, useEffect, useRef, useState } from 'react';
import { eventHasEvidence, type ActivityTab, type DebugFilter, type ProjectEvent } from '../models/event';
import type { Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream } from '../services/eventStream';

const UNAVAILABLE = 'Campaign activity is temporarily unavailable.';
const PAGE_SIZE = 100;

function evidenceFromLocation(): string | null {
  const [page, query = ''] = window.location.hash.slice(1).split('?', 2);
  if (page !== 'activity') return null;
  const value = new URLSearchParams(query).get('evidence');
  return value && value.length <= 2_000 ? value : null;
}

export interface ActivityModel {
  project: Project | null;
  activityEvents: ProjectEvent[];
  debugEvents: ProjectEvent[];
  activeTab: ActivityTab;
  debugFilter: DebugFilter;
  loading: boolean;
  activityError: string | null;
  debugError: string | null;
  liveError: string | null;
  focusedEvidenceId: string | null;
  activityHasMore: boolean;
  debugHasMore: boolean;
  onTabChange: (tab: ActivityTab) => void;
  onDebugFilter: (filter: DebugFilter) => void;
  onLoadMoreActivity: () => void;
  onLoadMoreDebug: () => void;
}

export function useActivity(
  api: BigEyeApi, events: ProjectEventStream, project: Project | null, enabled: boolean,
): ActivityModel {
  const [activityEvents, setActivityEvents] = useState<ProjectEvent[]>([]);
  const [debugEvents, setDebugEvents] = useState<ProjectEvent[]>([]);
  const [activeTab, setActiveTab] = useState<ActivityTab>('activity');
  const [debugFilter, setDebugFilter] = useState<DebugFilter>('all');
  const [activityHasMore, setActivityHasMore] = useState(false);
  const [debugHasMore, setDebugHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [activityError, setActivityError] = useState<string | null>(null);
  const [debugError, setDebugError] = useState<string | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [focusedEvidenceId, setFocusedEvidenceId] = useState<string | null>(evidenceFromLocation);
  const generation = useRef(0);
  const currentProjectId = useRef<string | null>(project?.id ?? null);
  const cursors = useRef({ activity: -1, debug: -1 });

  useEffect(() => {
    const update = () => setFocusedEvidenceId(evidenceFromLocation());
    update();
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);

  useEffect(() => {
    setFocusedEvidenceId(evidenceFromLocation());
  }, [enabled]);

  useEffect(() => {
    if (focusedEvidenceId === null) return;
    if (activityEvents.some((event) => eventHasEvidence(event, focusedEvidenceId))) {
      setActiveTab('activity');
    } else if (debugEvents.some((event) => eventHasEvidence(event, focusedEvidenceId))) {
      setActiveTab('debug');
    }
  }, [activityEvents, debugEvents, focusedEvidenceId]);

  const reportError = useCallback((stream: ActivityTab, requestError: unknown) => {
    const message = friendlyApiError(requestError, UNAVAILABLE);
    if (stream === 'activity') setActivityError(message);
    else setDebugError(message);
  }, []);

  useEffect(() => {
    currentProjectId.current = project?.id ?? null;
    const currentGeneration = ++generation.current;
    if (!enabled || project === null) {
      setActivityEvents([]);
      setDebugEvents([]);
      setActivityHasMore(false);
      setDebugHasMore(false);
      cursors.current = { activity: -1, debug: -1 };
      setLoading(false);
      setActivityError(null);
      setDebugError(null);
      setLiveError(null);
      return;
    }
    const projectId = project.id;
    const isCurrent = () => generation.current === currentGeneration && currentProjectId.current === projectId;
    const load = async (stream: ActivityTab) => {
      try {
        const page = await api.getProjectLog(projectId, stream, -1, PAGE_SIZE);
        if (!isCurrent()) return;
        cursors.current[stream] = page.next_offset;
        if (stream === 'activity') {
          setActivityEvents(page.events);
          setActivityHasMore(page.has_more);
          setActivityError(null);
        } else {
          setDebugEvents(page.events);
          setDebugHasMore(page.has_more);
          setDebugError(null);
        }
      } catch (requestError) {
        if (isCurrent()) reportError(stream, requestError);
      }
    };

    setActivityEvents([]);
    setDebugEvents([]);
    setActivityHasMore(false);
    setDebugHasMore(false);
    cursors.current = { activity: -1, debug: -1 };
    setActivityError(null);
    setDebugError(null);
    setLiveError(null);
    setLoading(true);
    void Promise.allSettled([load('activity'), load('debug')]).finally(() => {
      if (isCurrent()) setLoading(false);
    });
    const unsubscribe = events.subscribe(projectId, (name) => {
      setLiveError(null);
      if (name === 'activity') void load('activity');
      if (name === 'debug') void load('debug');
    }, setLiveError);
    return () => unsubscribe();
  }, [api, enabled, events, project, reportError]);

  const loadMore = useCallback((stream: ActivityTab) => {
    if (!project || loading) return;
    const projectId = project.id;
    const currentGeneration = generation.current;
    setLoading(true);
    void api.getProjectLog(projectId, stream, cursors.current[stream], PAGE_SIZE).then((page) => {
      if (generation.current !== currentGeneration || currentProjectId.current !== projectId) return;
      cursors.current[stream] = page.next_offset;
      if (stream === 'activity') {
        setActivityEvents((current) => [...current, ...page.events]);
        setActivityHasMore(page.has_more);
        setActivityError(null);
      } else {
        setDebugEvents((current) => [...current, ...page.events]);
        setDebugHasMore(page.has_more);
        setDebugError(null);
      }
    }).catch((requestError) => reportError(stream, requestError)).finally(() => {
      if (generation.current === currentGeneration && currentProjectId.current === projectId) setLoading(false);
    });
  }, [api, loading, project, reportError]);

  return {
    project, activityEvents, debugEvents, activeTab, debugFilter, loading,
    activityError, debugError, liveError, focusedEvidenceId,
    activityHasMore, debugHasMore, onTabChange: setActiveTab, onDebugFilter: setDebugFilter,
    onLoadMoreActivity: () => loadMore('activity'), onLoadMoreDebug: () => loadMore('debug'),
  };
}
