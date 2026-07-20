export interface Pagination {
  limit: number;
  offset: number;
  total: number;
}

export interface CoverageFile {
  path: string;
  covered_lines: number;
  cpu_exposure_seconds: number;
}

export interface CoverageTree {
  project_id: number;
  commit_sha: string;
  files: CoverageFile[];
  pagination: Pagination;
}

export interface SourceLine {
  number: number;
  text: string;
  covered: boolean;
  strategy_count: number;
  cpu_exposure_seconds: number;
}

export interface SourceFile {
  project_id: number;
  commit_sha: string;
  path: string;
  start_line: number;
  end_line: number;
  lines: SourceLine[];
}

export interface LineEvidence {
  campaign_id: number;
  strategy_asset_id: number;
  testcase_sha256: string;
  replay_command: string[];
  target_asset_id: number;
  configuration_asset_id: number | null;
  clean_image_id: string;
  cpu_exposure_seconds: number;
}

export interface LineEvidencePage {
  evidence: LineEvidence[];
  pagination: Pagination;
}
