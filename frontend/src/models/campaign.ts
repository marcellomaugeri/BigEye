export interface CampaignAsset {
  id: number;
  kind: string;
  name: string;
  parent_id: number | null;
}

export interface Campaign {
  id: number;
  target_asset_id: number;
  target_name: string;
  configuration_asset_id: number | null;
  configuration_name: string | null;
  engine: string;
  started_at: string;
  stopped_at: string | null;
  last_heartbeat_at: string | null;
  cpu_exposure_seconds: number;
  next_review_after: string | null;
  next_review_reason: string | null;
  error: string | null;
  configuration_purpose: string | null;
  retirement_reason: string | null;
  reached_line_count: number | null;
  unique_line_count: number | null;
  overlapping_line_count: number | null;
  total_reached_lines: number | null;
  covered_line_delta_5m: number | null;
  activity: 'failed' | 'stopped' | 'running' | 'waiting';
}

export interface CampaignList {
  project_id: number;
  campaigns: Campaign[];
  assets: CampaignAsset[];
}

export interface FindingPageSummary {
  items: Array<{ id: string }>;
  next_cursor: string | null;
}
