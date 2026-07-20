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
