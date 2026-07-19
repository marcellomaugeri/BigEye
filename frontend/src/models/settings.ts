export interface Settings {
  database: boolean;
  docker: boolean;
  openai_api_key_present: boolean;
  toolchain: boolean;
}

export interface ProjectSettings {
  requested_revision: string;
  commit_sha: string | null;
  worker_count: number;
  token_present: boolean;
}

export interface UpdateProjectSettingsRequest {
  worker_count?: number;
  repository_token?: string;
}
