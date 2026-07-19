export interface Project {
  id: string;
  repository_url: string;
  requested_revision: string;
  worker_count: number;
  commit_sha: string | null;
  token_present: boolean;
  created_at: string;
  paused_at: string | null;
  error: string | null;
}

export interface CreateProjectRequest {
  repository_url: string;
  revision: string;
  worker_count: number;
  repository_token?: string;
}

export const MAX_WORKER_COUNT = 2_147_483_647;
