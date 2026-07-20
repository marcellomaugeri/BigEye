export type ProjectInvalidation = 'project' | 'campaigns' | 'coverage' | 'findings' | 'activity' | 'debug';

export interface ProjectEventStream {
  subscribe(
    projectId: string,
    onEvent: (name: ProjectInvalidation) => void,
    onError?: (message: string) => void,
    onOpen?: () => void,
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
}

export function createEventStream(baseUrl?: string): ProjectEventStream {
  return new EventStream(baseUrl);
}
