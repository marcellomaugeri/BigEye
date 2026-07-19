export interface Project {
  id: string;
  repository_url: string;
  worker_count: number;
  commit_sha: string | null;
  created_at: string;
  finished_at: string | null;
  error: string | null;
}

export interface CreateProjectRequest {
  repository_url: string;
  worker_count: number;
}
