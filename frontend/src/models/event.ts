export interface ProjectEvent {
  id: number;
  created_at: string;
  stream: 'activity' | 'debug';
  payload: Record<string, unknown>;
}

export interface ProjectEventPage {
  events: ProjectEvent[];
  next_offset: number;
}

export type ActivityTab = 'activity' | 'debug';
export type DebugFilter = 'all' | 'agent' | 'api' | 'tool' | 'build' | 'fuzzer' | 'coverage' | 'error';
