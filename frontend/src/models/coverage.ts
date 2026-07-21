export interface Pagination {
  limit: number;
  offset: number;
  total: number;
}

export interface CoverageFile {
  path: string;
  covered_lines: number;
  total_lines: number | null;
  covered_functions: number | null;
  total_functions: number | null;
  covered_branches: number | null;
  total_branches: number | null;
  lines: CoverageMeasurement | null;
  functions: CoverageMeasurement | null;
  branches: CoverageMeasurement | null;
  cpu_exposure_seconds: number;
}

export interface CoverageMeasurement {
  covered: number;
  total: number;
  percent: number;
}

export interface CoverageSummary {
  lines: CoverageMeasurement | null;
  functions: CoverageMeasurement | null;
  branches: CoverageMeasurement | null;
}

export interface CoverageHistoryPoint {
  observed_at: string;
  covered: number;
  total: number;
  percent: number;
}

export interface CoverageTree {
  project_id: number;
  commit_sha: string;
  files: CoverageFile[];
  summary: CoverageSummary;
  history: CoverageHistoryPoint[];
  pagination: Pagination;
}

export interface SourceLine {
  number: number;
  text: string;
  covered: boolean;
  branches: boolean[] | null;
  strategy_count: number;
  cpu_exposure_seconds: number;
}

export interface SourceFile {
  project_id: number;
  commit_sha: string;
  path: string;
  start_line: number;
  end_line: number;
  total_lines: number;
  lines: SourceLine[];
}

export interface FunctionCoverage {
  name: string;
  path: string;
  start_line: number | null;
  start_column: number | null;
  covered: boolean | null;
  covered_lines: number;
  cpu_exposure_seconds: number;
}

export interface FunctionCoveragePage {
  functions: FunctionCoverage[];
  pagination: Pagination;
}

export interface LineEvidence {
  campaign_id: number;
  strategy_asset_id: number;
  testcase_sha256: string;
  replay_command: string[];
  replay_environment: Record<string, string>;
  target_asset_id: number;
  configuration_asset_id: number | null;
  clean_image_id: string;
  cpu_exposure_seconds: number;
}

export interface LineEvidencePage {
  evidence: LineEvidence[];
  pagination: Pagination;
}
