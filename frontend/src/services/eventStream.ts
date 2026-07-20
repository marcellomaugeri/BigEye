export type ProjectInvalidation = 'project' | 'campaigns' | 'coverage' | 'findings' | 'activity' | 'debug';

import type { ReproductionOutput, ReproductionRun } from '../models/reproduction';

export type ReproductionStreamEvent =
  | { type: 'output'; data: ReproductionOutput }
  | { type: 'reproduction'; data: ReproductionRun };

export interface ProjectEventStream {
  subscribe(
    projectId: string,
    onEvent: (name: ProjectInvalidation) => void,
    onError?: (message: string) => void,
    onOpen?: () => void,
  ): () => void;
  subscribeReproduction?(
    url: string,
    onEvent: (event: ReproductionStreamEvent) => void,
    onError?: (message: string) => void,
  ): () => void;
}

export class EventStream implements ProjectEventStream {
  constructor(private readonly baseUrl = import.meta.env.VITE_API_BASE_URL ?? '') {}

  subscribe(
    projectId: string,
    onEvent: (name: ProjectInvalidation) => void,
    onError?: (message: string) => void,
    onOpen?: () => void,
  ): () => void {
    if (typeof EventSource === 'undefined') return () => undefined;
    const source = new EventSource(`${this.baseUrl}/api/projects/${encodeURIComponent(projectId)}/events`);
    const names: ProjectInvalidation[] = ['project', 'campaigns', 'coverage', 'findings', 'activity', 'debug'];
    names.forEach((name) => source.addEventListener(name, () => onEvent(name)));
    source.onerror = () => onError?.('Live updates are temporarily unavailable.');
    source.onopen = () => onOpen?.();
    return () => source.close();
  }

  subscribeReproduction(
    url: string,
    onEvent: (event: ReproductionStreamEvent) => void,
    onError?: (message: string) => void,
  ): () => void {
    if (typeof EventSource === 'undefined') return () => undefined;
    const source = new EventSource(url);
    source.addEventListener('output', (event) => {
      onEvent({ type: 'output', data: JSON.parse((event as MessageEvent).data) as ReproductionOutput });
    });
    source.addEventListener('reproduction', (event) => {
      onEvent({ type: 'reproduction', data: JSON.parse((event as MessageEvent).data) as ReproductionRun });
    });
    source.onerror = () => onError?.('Live reproduction output is temporarily unavailable.');
    return () => source.close();
  }
}

export function createEventStream(baseUrl?: string): ProjectEventStream {
  return new EventStream(baseUrl);
}
