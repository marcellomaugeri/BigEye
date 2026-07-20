export type ReproductionPhase = 'starting' | 'completed' | 'failed' | 'timed_out' | 'interrupted';

export interface ReproductionRun {
  run_id: string;
  phase: ReproductionPhase;
  started_at: string;
  completed_at: string | null;
  image_id: string;
  command: string[];
  exit_code: number | null;
  terminal_reason: string | null;
}

export interface ReproductionOutput {
  stream: 'stdout' | 'stderr';
  text: string;
}

export interface FindingReproductionModel {
  run: ReproductionRun | null;
  output: ReproductionOutput[];
  starting: boolean;
  error: string | null;
  start: () => Promise<void>;
}
