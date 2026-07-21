export interface FindingSummary {
  id: string;
  project_id: string;
  classification: string;
  priority_rank: number | null;
  priority_reason: string | null;
  description: string;
  reproducible: boolean;
  occurrence_count: number;
  created_at: string;
  triaged_at: string | null;
}

export interface ReplayVariant {
  variant: string;
  crashed: boolean;
  signal: string | null;
  sanitizer: string | null;
  source_location: string | null;
  image_id: string;
  error: string | null;
}

export interface CrashGrouping {
  version: 1;
  commit_sha: string;
  failure_class: string;
  reproducible: boolean;
  minimisation_accepted: boolean;
  minimised_sha256: string;
  harness_misuse: boolean;
  frames: Array<{
    function: string;
    source_location: string | null;
  }>;
}

export interface FindingDetail extends FindingSummary {
  uncertainty: string;
  evidence_ids: string[];
  reproducer: { sha256: string; size: number };
  replay: {
    attempts: number;
    matching: number;
    compatible_variants: ReplayVariant[];
    clean_variant: ReplayVariant | null;
  };
  minimisation: { accepted: boolean; original_size: number; minimal_size: number } | null;
  correction: Record<string, unknown> | null;
  repair_intent: string | null;
  grouping: CrashGrouping | null;
  evidence_events: Array<{
    evidence_id: string;
    stream: 'activity' | 'debug';
    event_id: number;
  }>;
}

export interface FindingPage {
  items: FindingSummary[];
  next_cursor: string | null;
}
