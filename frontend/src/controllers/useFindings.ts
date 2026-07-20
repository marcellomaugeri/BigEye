import { useCallback, useEffect, useRef, useState } from 'react';
import type { FindingDetail, FindingSummary } from '../models/finding';
import type { Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream } from '../services/eventStream';

const UNAVAILABLE = 'Replayed findings are temporarily unavailable.';

export interface FindingsModel {
  project: Project | null;
  findings: FindingSummary[];
  selectedFindingId: string | null;
  selectedFinding: FindingDetail | null;
  reproducerUrl: string | null;
  nextCursor: string | null;
  loading: boolean;
  detailLoading: boolean;
  error: string | null;
  onSelectFinding: (findingId: string) => void;
  onLoadMore: () => void;
}

function priorityOrder(left: FindingSummary, right: FindingSummary): number {
  const leftRank = left.priority_rank ?? Number.MAX_SAFE_INTEGER;
  const rightRank = right.priority_rank ?? Number.MAX_SAFE_INTEGER;
  return leftRank - rightRank || right.created_at.localeCompare(left.created_at);
}

export function useFindings(
  api: BigEyeApi, events: ProjectEventStream, project: Project | null, enabled: boolean,
): FindingsModel {
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingDetail | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const projectGeneration = useRef(0);
  const detailGeneration = useRef(0);
  const currentProjectId = useRef<string | null>(project?.id ?? null);
  const selectedIdRef = useRef<string | null>(null);
  const cursorRef = useRef<string | null>(null);

  const reportError = useCallback((requestError: unknown) => {
    setError(friendlyApiError(requestError, UNAVAILABLE));
  }, []);

  const loadDetail = useCallback(async (projectId: string, findingId: string) => {
    const generation = ++detailGeneration.current;
    setDetailLoading(true);
    setSelectedFinding(null);
    try {
      const value = await api.getFinding(projectId, findingId);
      if (
        generation === detailGeneration.current && currentProjectId.current === projectId
        && selectedIdRef.current === findingId
      ) setSelectedFinding(value);
    } catch (requestError) {
      if (generation === detailGeneration.current && currentProjectId.current === projectId) {
        reportError(requestError);
      }
    } finally {
      if (generation === detailGeneration.current && currentProjectId.current === projectId) {
        setDetailLoading(false);
      }
    }
  }, [api, reportError]);

  useEffect(() => {
    currentProjectId.current = project?.id ?? null;
    const generation = ++projectGeneration.current;
    detailGeneration.current += 1;
    if (!enabled || project === null) {
      setFindings([]);
      setSelectedFindingId(null);
      setSelectedFinding(null);
      setNextCursor(null);
      selectedIdRef.current = null;
      cursorRef.current = null;
      setLoading(false);
      setDetailLoading(false);
      setError(null);
      return;
    }

    const projectId = project.id;
    const isCurrent = () => generation === projectGeneration.current && currentProjectId.current === projectId;
    const load = async (append = false) => {
      const cursor = append ? cursorRef.current ?? undefined : undefined;
      if (append && cursor === undefined) return;
      setLoading(true);
      try {
        const page = await api.listFindings(projectId, cursor);
        if (!isCurrent()) return;
        setFindings((current) => {
          const combined = append ? [...current, ...page.items] : page.items;
          return [...new Map(combined.map((item) => [item.id, item])).values()].sort(priorityOrder);
        });
        cursorRef.current = page.next_cursor;
        setNextCursor(page.next_cursor);
        if (!append) {
          const retained = selectedIdRef.current && page.items.some((item) => item.id === selectedIdRef.current)
            ? selectedIdRef.current : page.items[0]?.id ?? null;
          selectedIdRef.current = retained;
          setSelectedFindingId(retained);
          if (retained === null) setSelectedFinding(null);
        }
        setError(null);
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      } finally {
        if (isCurrent()) setLoading(false);
      }
    };

    setFindings([]);
    setSelectedFindingId(null);
    setSelectedFinding(null);
    setNextCursor(null);
    selectedIdRef.current = null;
    cursorRef.current = null;
    setError(null);
    void load();
    const unsubscribe = events.subscribe(projectId, (name) => {
      if (name === 'findings') void load();
    });
    return () => unsubscribe();
  }, [api, enabled, events, project, reportError]);

  useEffect(() => {
    if (!enabled || !project || selectedFindingId === null) return;
    selectedIdRef.current = selectedFindingId;
    void loadDetail(project.id, selectedFindingId);
  }, [enabled, loadDetail, project, selectedFindingId]);

  const onSelectFinding = useCallback((findingId: string) => {
    selectedIdRef.current = findingId;
    setSelectedFindingId(findingId);
  }, []);

  const onLoadMore = useCallback(() => {
    if (!project || cursorRef.current === null || loading) return;
    const projectId = project.id;
    const generation = projectGeneration.current;
    setLoading(true);
    void api.listFindings(projectId, cursorRef.current).then((page) => {
      if (generation !== projectGeneration.current || currentProjectId.current !== projectId) return;
      setFindings((current) => [...new Map([...current, ...page.items].map((item) => [item.id, item])).values()].sort(priorityOrder));
      cursorRef.current = page.next_cursor;
      setNextCursor(page.next_cursor);
    }).catch(reportError).finally(() => {
      if (generation === projectGeneration.current && currentProjectId.current === projectId) setLoading(false);
    });
  }, [api, loading, project, reportError]);

  return {
    project, findings, selectedFindingId, selectedFinding,
    reproducerUrl: project && selectedFindingId
      ? api.findingReproducerUrl(project.id, selectedFindingId) : null,
    nextCursor, loading, detailLoading, error, onSelectFinding, onLoadMore,
  };
}
