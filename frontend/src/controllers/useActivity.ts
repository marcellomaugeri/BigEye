import { useCallback, useEffect, useRef, useState } from 'react';
import { eventHasEvidence, type ActivityTab, type DebugFilter, type ProjectEvent } from '../models/event';
import type { Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream } from '../services/eventStream';

const UNAVAILABLE = 'Campaign activity is temporarily unavailable.';
const PAGE_SIZE = 100;

interface EvidenceTarget {
  evidenceId: string;
  stream: ActivityTab;
  eventId: number;
}

function evidenceTargetFromLocation(): EvidenceTarget | null {
  const [page, query = ''] = window.location.hash.slice(1).split('?', 2);
  if (page !== 'activity') return null;
  const params = new URLSearchParams(query);
  const evidenceId = params.get('evidence');
  const stream = params.get('stream');
  const eventValue = params.get('event');
  if (
    !evidenceId || evidenceId.length > 2_000
    || (stream !== 'activity' && stream !== 'debug')
    || eventValue === null || !/^\d+$/.test(eventValue)
  ) return null;
  const eventId = Number(eventValue);
  if (!Number.isSafeInteger(eventId)) return null;
  return { evidenceId, stream, eventId };
}

function appendUniqueEvents(current: ProjectEvent[], older: ProjectEvent[]): ProjectEvent[] {
  const retained = new Set(current.map((event) => event.id));
  return [...current, ...older.filter((event) => !retained.has(event.id))];
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
  focusedEventId: number | null;
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
  const [evidenceTarget, setEvidenceTarget] = useState<EvidenceTarget | null>(evidenceTargetFromLocation);
  const [focusedTarget, setFocusedTarget] = useState<EvidenceTarget | null>(null);
  const generation = useRef(0);
  const currentProjectId = useRef<string | null>(project?.id ?? null);
  const focusedTargetRef = useRef<EvidenceTarget | null>(null);
  const cursors = useRef({ activity: -1, debug: -1 });

  useEffect(() => {
    const update = () => setEvidenceTarget(evidenceTargetFromLocation());
    update();
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);

  useEffect(() => {
    setEvidenceTarget(evidenceTargetFromLocation());
  }, [enabled]);

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
      focusedTargetRef.current = null;
      setFocusedTarget(null);
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
          setActivityEvents((current) => {
            const focused = focusedTargetRef.current?.stream === stream
              ? current.find((event) => event.id === focusedTargetRef.current?.eventId) : undefined;
            return focused && !page.events.some((event) => event.id === focused.id)
              ? [focused, ...page.events] : page.events;
          });
          setActivityHasMore(page.has_more);
          setActivityError(null);
        } else {
          setDebugEvents((current) => {
            const focused = focusedTargetRef.current?.stream === stream
              ? current.find((event) => event.id === focusedTargetRef.current?.eventId) : undefined;
            return focused && !page.events.some((event) => event.id === focused.id)
              ? [focused, ...page.events] : page.events;
          });
          setDebugHasMore(page.has_more);
          setDebugError(null);
        }
      } catch (requestError) {
        if (isCurrent()) reportError(stream, requestError);
      }
    };
    const loadExact = async () => {
      if (evidenceTarget === null) return;
      try {
        const event = await api.getProjectEvent(
          projectId, evidenceTarget.stream, evidenceTarget.eventId,
        );
        if (!isCurrent()) return;
        if (
          event.id !== evidenceTarget.eventId || event.stream !== evidenceTarget.stream
          || !eventHasEvidence(event, evidenceTarget.evidenceId)
        ) return;
        focusedTargetRef.current = evidenceTarget;
        setFocusedTarget(evidenceTarget);
        const merge = (current: ProjectEvent[]) => [
          event, ...current.filter((item) => item.id !== event.id),
        ];
        if (evidenceTarget.stream === 'activity') setActivityEvents(merge);
        else {
          setDebugEvents(merge);
          setDebugFilter('all');
        }
        setActiveTab(evidenceTarget.stream);
      } catch (requestError) {
        if (isCurrent()) reportError(evidenceTarget.stream, requestError);
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
    focusedTargetRef.current = null;
    setFocusedTarget(null);
    setLoading(true);
    void (async () => {
      await Promise.allSettled([load('activity'), load('debug')]);
      await loadExact();
    })().finally(() => { if (isCurrent()) setLoading(false); });
    const unsubscribe = events.subscribe(projectId, (name) => {
      if (name === 'activity') void load('activity');
      if (name === 'debug') void load('debug');
    }, setLiveError, () => setLiveError(null));
    return () => unsubscribe();
  }, [api, enabled, events, evidenceTarget, project, reportError]);

  const loadMore = useCallback((stream: ActivityTab) => {
    if (!project || loading) return;
    const projectId = project.id;
    const currentGeneration = generation.current;
    setLoading(true);
    void api.getProjectLog(projectId, stream, cursors.current[stream], PAGE_SIZE).then((page) => {
      if (generation.current !== currentGeneration || currentProjectId.current !== projectId) return;
      cursors.current[stream] = page.next_offset;
      if (stream === 'activity') {
        setActivityEvents((current) => appendUniqueEvents(current, page.events));
        setActivityHasMore(page.has_more);
        setActivityError(null);
      } else {
        setDebugEvents((current) => appendUniqueEvents(current, page.events));
        setDebugHasMore(page.has_more);
        setDebugError(null);
      }
    }).catch((requestError) => {
      if (generation.current === currentGeneration && currentProjectId.current === projectId) {
        reportError(stream, requestError);
      }
    }).finally(() => {
      if (generation.current === currentGeneration && currentProjectId.current === projectId) setLoading(false);
    });
  }, [api, loading, project, reportError]);

  return {
    project, activityEvents, debugEvents, activeTab, debugFilter, loading,
    activityError, debugError, liveError,
    focusedEvidenceId: focusedTarget?.evidenceId ?? null,
    focusedEventId: focusedTarget?.eventId ?? null,
    activityHasMore, debugHasMore, onTabChange: setActiveTab, onDebugFilter: setDebugFilter,
    onLoadMoreActivity: () => loadMore('activity'), onLoadMoreDebug: () => loadMore('debug'),
  };
}
