import { useCallback, useEffect, useRef, useState } from 'react';
import type { ActivityTab, DebugFilter, ProjectEvent } from '../models/event';
import type { Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream } from '../services/eventStream';

const UNAVAILABLE = 'Campaign activity is temporarily unavailable.';
const PAGE_SIZE = 100;

export interface ActivityModel {
  project: Project | null;
  activityEvents: ProjectEvent[];
  debugEvents: ProjectEvent[];
  activeTab: ActivityTab;
  debugFilter: DebugFilter;
  loading: boolean;
  error: string | null;
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
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const currentProjectId = useRef<string | null>(project?.id ?? null);
  const cursors = useRef({ activity: -1, debug: -1 });

  const reportError = useCallback((requestError: unknown) => {
    setError(friendlyApiError(requestError, UNAVAILABLE));
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
      setError(null);
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
          setActivityHasMore(page.events.length === PAGE_SIZE);
        } else {
          setDebugEvents(page.events);
          setDebugHasMore(page.events.length === PAGE_SIZE);
        }
        setError(null);
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      }
    };

    setActivityEvents([]);
    setDebugEvents([]);
    setActivityHasMore(false);
    setDebugHasMore(false);
    cursors.current = { activity: -1, debug: -1 };
    setError(null);
    setLoading(true);
    void Promise.allSettled([load('activity'), load('debug')]).finally(() => {
      if (isCurrent()) setLoading(false);
    });
    const unsubscribe = events.subscribe(projectId, (name) => {
      if (name === 'activity') void load('activity');
      if (name === 'debug') void load('debug');
    });
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
        setActivityHasMore(page.events.length === PAGE_SIZE);
      } else {
        setDebugEvents((current) => [...current, ...page.events]);
        setDebugHasMore(page.events.length === PAGE_SIZE);
      }
    }).catch(reportError).finally(() => {
      if (generation.current === currentGeneration && currentProjectId.current === projectId) setLoading(false);
    });
  }, [api, loading, project, reportError]);

  return {
    project, activityEvents, debugEvents, activeTab, debugFilter, loading, error,
    activityHasMore, debugHasMore, onTabChange: setActiveTab, onDebugFilter: setDebugFilter,
    onLoadMoreActivity: () => loadMore('activity'), onLoadMoreDebug: () => loadMore('debug'),
  };
}
