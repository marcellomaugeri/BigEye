import type { Campaign } from './campaign';

export interface FuzzingRow {
  id: number;
  target: string;
  configuration: string | null;
  purpose: string | null;
  engine: string;
  activity: Campaign['activity'];
  recentLineGain: number | null;
  reproducibleLines: number | null;
  cpuExposureSeconds: number;
  lastEvidenceAt: string | null;
  state: string;
}

export interface FuzzingModel {
  project: import('./project').Project | null;
  rows: FuzzingRow[];
  loading: boolean;
  error: string | null;
}
