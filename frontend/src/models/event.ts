export interface ProjectEvent {
  id: number;
  created_at: string;
  stream: 'activity' | 'debug';
  payload: Record<string, unknown>;
}

export interface ProjectEventPage {
  events: ProjectEvent[];
  next_offset: number;
  has_more: boolean;
}

export function eventHasEvidence(event: ProjectEvent, evidenceId: string): boolean {
  const payload = event.payload;
  if (payload.evidence_id === evidenceId) return true;
  if (Array.isArray(payload.evidence_ids) && payload.evidence_ids.includes(evidenceId)) return true;
  if (!Array.isArray(payload.outcomes)) return false;
  return payload.outcomes.some((outcome) => (
    typeof outcome === 'object' && outcome !== null
    && !Array.isArray(outcome) && (outcome as Record<string, unknown>).evidence_id === evidenceId
  ));
}

export type ActivityTab = 'activity' | 'debug';
export type DebugFilter = 'all' | 'agent' | 'api' | 'tool' | 'build' | 'fuzzer' | 'coverage' | 'error';
