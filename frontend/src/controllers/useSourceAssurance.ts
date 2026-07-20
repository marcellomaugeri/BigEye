import { useCallback, useEffect, useRef, useState } from 'react';
import type { CampaignList } from '../models/campaign';
import type { CoverageTree, LineEvidence, LineEvidencePage, SourceFile } from '../models/coverage';
import type { Project } from '../models/project';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream, ProjectInvalidation } from '../services/eventStream';

const UNAVAILABLE = 'BigEye local services are temporarily unavailable.';
const SOURCE_PAGE_SIZE = 500;

function sourceLocation(): { path: string; line: number | null } | null {
  const [page, query = ''] = window.location.hash.slice(1).split('?', 2);
  if (page !== 'source') return null;
  const parameters = new URLSearchParams(query);
  const path = parameters.get('path');
  const rawLine = parameters.get('line');
  if (!path) return null;
  const line = rawLine && /^\d+$/.test(rawLine) ? Number(rawLine) : null;
  return { path, line: line !== null && Number.isSafeInteger(line) && line > 0 ? line : null };
}

function sourcePageStart(line: number): number {
  return Math.floor((line - 1) / SOURCE_PAGE_SIZE) * SOURCE_PAGE_SIZE + 1;
}

function writeSourceLocation(path: string, line: number | null): void {
  const parameters = new URLSearchParams({ path });
  if (line !== null) parameters.set('line', String(line));
  window.history.replaceState(null, '', `#source?${parameters}`);
}

export interface SourceAssuranceModel {
  project: Project | null;
  tree: CoverageTree | null;
  source: SourceFile | null;
  campaigns: CampaignList | null;
  evidence: LineEvidencePage | null;
  selectedPath: string | null;
  selectedLine: number | null;
  strategyFilter: string;
  loading: boolean;
  error: string | null;
  onSelectPath: (path: string) => void;
  onSelectLine: (line: number) => void;
  onPreviousSourcePage: () => void;
  onNextSourcePage: () => void;
  onStrategyFilter: (strategyId: string) => void;
  testcaseUrl: (evidence: LineEvidence) => string;
}

export function useSourceAssurance(
  api: BigEyeApi,
  events: ProjectEventStream,
  project: Project | null,
  enabled: boolean,
): SourceAssuranceModel {
  const [tree, setTree] = useState<CoverageTree | null>(null);
  const [source, setSource] = useState<SourceFile | null>(null);
  const [campaigns, setCampaigns] = useState<CampaignList | null>(null);
  const [evidence, setEvidence] = useState<LineEvidencePage | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [selectedLine, setSelectedLine] = useState<number | null>(null);
  const [strategyFilter, setStrategyFilter] = useState('all');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const projectGeneration = useRef(0);
  const sourceGeneration = useRef(0);
  const evidenceGeneration = useRef(0);
  const currentProjectId = useRef<string | null>(project?.id ?? null);
  const selectedPathRef = useRef<string | null>(null);
  const selectedLineRef = useRef<number | null>(null);

  const reportError = useCallback((requestError: unknown) => {
    setError(friendlyApiError(requestError, UNAVAILABLE));
  }, []);

  const loadSource = useCallback(async (
    projectId: string, path: string, startLine = 1, preferredLine: number | null = null,
  ) => {
    const requestGeneration = ++sourceGeneration.current;
    setSource(null);
    setEvidence(null);
    try {
      const value = await api.getSourceFile(projectId, path, startLine, startLine + SOURCE_PAGE_SIZE - 1);
      if (
        requestGeneration !== sourceGeneration.current ||
        currentProjectId.current !== projectId || selectedPathRef.current !== path
      ) return;
      setSource(value);
      const selected = preferredLine !== null && value.lines.some((line) => line.number === preferredLine)
        ? preferredLine
        : (value.lines.find((line) => line.covered)?.number ?? null);
      selectedLineRef.current = selected;
      setSelectedLine(selected);
      writeSourceLocation(path, selected);
    } catch (requestError) {
      if (requestGeneration === sourceGeneration.current && currentProjectId.current === projectId) {
        reportError(requestError);
      }
    }
  }, [api, reportError]);

  const loadEvidence = useCallback(async (projectId: string, path: string, line: number) => {
    const requestGeneration = ++evidenceGeneration.current;
    setEvidence(null);
    try {
      const value = await api.getLineEvidence(projectId, path, line);
      if (
        requestGeneration !== evidenceGeneration.current || currentProjectId.current !== projectId ||
        selectedPathRef.current !== path || selectedLineRef.current !== line
      ) return;
      setEvidence(value);
    } catch (requestError) {
      if (requestGeneration === evidenceGeneration.current && currentProjectId.current === projectId) {
        reportError(requestError);
      }
    }
  }, [api, reportError]);

  useEffect(() => {
    currentProjectId.current = project?.id ?? null;
    const generation = ++projectGeneration.current;
    sourceGeneration.current += 1;
    evidenceGeneration.current += 1;

    if (!enabled || project === null) {
      setTree(null);
      setSource(null);
      setCampaigns(null);
      setEvidence(null);
      setSelectedPath(null);
      setSelectedLine(null);
      selectedPathRef.current = null;
      selectedLineRef.current = null;
      setLoading(false);
      setError(null);
      return;
    }

    const projectId = project.id;
    const isCurrent = () => projectGeneration.current === generation && currentProjectId.current === projectId;
    const loadTree = async () => {
      try {
        const value = await api.getCoverageTree(projectId);
        if (!isCurrent()) return;
        setTree(value);
        const requested = sourceLocation();
        const requestedPath = requested && value.files.some((file) => file.path === requested.path)
          ? requested.path
          : null;
        const nextPath = requestedPath ?? (
          selectedPathRef.current && value.files.some((file) => file.path === selectedPathRef.current)
            ? selectedPathRef.current
            : (value.files[0]?.path ?? null)
        );
        if (nextPath !== selectedPathRef.current) {
          selectedPathRef.current = nextPath;
          setSelectedPath(nextPath);
        }
        if (nextPath) {
          const requestedLine = requestedPath === nextPath ? requested?.line ?? null : null;
          void loadSource(
            projectId, nextPath,
            requestedLine === null ? 1 : sourcePageStart(requestedLine),
            requestedLine,
          );
        } else {
          selectedLineRef.current = null;
          setSelectedLine(null);
          setSource(null);
          setEvidence(null);
        }
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      }
    };
    const loadCampaigns = async () => {
      try {
        const value = await api.listCampaigns(projectId);
        if (isCurrent()) setCampaigns(value);
      } catch (requestError) {
        if (isCurrent()) reportError(requestError);
      }
    };

    setTree(null);
    setSource(null);
    setCampaigns(null);
    setEvidence(null);
    selectedPathRef.current = null;
    selectedLineRef.current = null;
    setSelectedPath(null);
    setSelectedLine(null);
    setStrategyFilter('all');
    setError(null);
    setLoading(true);
    void Promise.allSettled([loadTree(), loadCampaigns()]).finally(() => {
      if (isCurrent()) setLoading(false);
    });

    const unsubscribe = events.subscribe(projectId, (name: ProjectInvalidation) => {
      if (name === 'coverage') void loadTree();
      if (name === 'campaigns') void loadCampaigns();
    });
    return () => unsubscribe();
  }, [api, enabled, events, loadSource, project, reportError]);

  useEffect(() => {
    if (!enabled || !project || !selectedPath || selectedLine === null) return;
    selectedPathRef.current = selectedPath;
    selectedLineRef.current = selectedLine;
    const selectedSourceLine = source?.lines.find((line) => line.number === selectedLine);
    if (!selectedSourceLine?.covered) {
      evidenceGeneration.current += 1;
      setEvidence(null);
      return;
    }
    void loadEvidence(project.id, selectedPath, selectedLine);
  }, [enabled, loadEvidence, project, selectedLine, selectedPath, source]);

  const onSelectPath = useCallback((path: string) => {
    if (!project || path === selectedPathRef.current) return;
    selectedPathRef.current = path;
    selectedLineRef.current = null;
    setSelectedPath(path);
    setSelectedLine(null);
    setStrategyFilter('all');
    writeSourceLocation(path, null);
    void loadSource(project.id, path);
  }, [loadSource, project]);

  const onSelectLine = useCallback((line: number) => {
    selectedLineRef.current = line;
    setSelectedLine(line);
    if (selectedPathRef.current) writeSourceLocation(selectedPathRef.current, line);
  }, []);

  const onPreviousSourcePage = useCallback(() => {
    if (!project || !source || !selectedPathRef.current || source.start_line <= 1) return;
    selectedLineRef.current = null;
    setSelectedLine(null);
    void loadSource(project.id, selectedPathRef.current, Math.max(1, source.start_line - SOURCE_PAGE_SIZE));
  }, [loadSource, project, source]);

  const onNextSourcePage = useCallback(() => {
    if (!project || !source || !selectedPathRef.current || source.end_line >= source.total_lines) return;
    selectedLineRef.current = null;
    setSelectedLine(null);
    void loadSource(project.id, selectedPathRef.current, source.start_line + SOURCE_PAGE_SIZE);
  }, [loadSource, project, source]);

  return {
    project, tree, source, campaigns, evidence, selectedPath, selectedLine,
    strategyFilter, loading, error, onSelectPath, onSelectLine,
    onPreviousSourcePage, onNextSourcePage,
    onStrategyFilter: setStrategyFilter,
    testcaseUrl: (item) => (
      project && selectedPath && selectedLine !== null
        ? api.retainedTestcaseUrl(
          project.id, selectedPath, selectedLine, item.strategy_asset_id, item.testcase_sha256,
        )
        : '#'
    ),
  };
}
