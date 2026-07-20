import type { CreateProjectRequest, Project } from '../models/project';
import type { ProjectSettings, Settings, UpdateProjectSettingsRequest } from '../models/settings';
import type { Task, TaskLog } from '../models/task';
import type { CampaignList } from '../models/campaign';
import type { CoverageTree, LineEvidencePage, SourceFile } from '../models/coverage';
import type { ProjectEvent, ProjectEventPage } from '../models/event';
import type { FindingDetail, FindingPage } from '../models/finding';

export interface BigEyeApi {
  createProject(request: CreateProjectRequest): Promise<Project>;
  listProjects(): Promise<Project[]>;
  getProject(projectId: string): Promise<Project>;
  getProjectSettings(projectId: string): Promise<ProjectSettings>;
  updateProjectSettings(projectId: string, request: UpdateProjectSettingsRequest): Promise<ProjectSettings>;
  pauseProject(projectId: string): Promise<Project>;
  resumeProject(projectId: string): Promise<Project>;
  listTasks(projectId: string): Promise<Task[]>;
  getTaskLog(taskId: string, after?: number): Promise<TaskLog>;
  getSettings(): Promise<Settings>;
  listCampaigns(projectId: string): Promise<CampaignList>;
  getCoverageTree(projectId: string): Promise<CoverageTree>;
  getSourceFile(projectId: string, path: string, startLine?: number, endLine?: number): Promise<SourceFile>;
  getLineEvidence(projectId: string, path: string, lineNumber: number): Promise<LineEvidencePage>;
  retainedTestcaseUrl(
    projectId: string, path: string, lineNumber: number,
    strategyAssetId: number, testcaseSha256: string,
  ): string;
  listFindings(projectId: string, cursor?: string): Promise<FindingPage>;
  getFinding(projectId: string, findingId: string): Promise<FindingDetail>;
  findingReproducerUrl(projectId: string, findingId: string): string;
  getProjectLog(
    projectId: string, stream: 'activity' | 'debug', before?: number, limit?: number,
  ): Promise<ProjectEventPage>;
  getProjectEvent(projectId: string, stream: 'activity' | 'debug', eventId: number): Promise<ProjectEvent>;
}

export class ApiClient implements BigEyeApi {
  constructor(private readonly baseUrl = import.meta.env.VITE_API_BASE_URL ?? '') {}

  async createProject(request: CreateProjectRequest): Promise<Project> {
    return this.request('/api/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request)
    });
  }

  listProjects(): Promise<Project[]> {
    return this.request('/api/projects');
  }

  getProject(projectId: string): Promise<Project> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}`);
  }

  getProjectSettings(projectId: string): Promise<ProjectSettings> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/settings`);
  }

  updateProjectSettings(projectId: string, request: UpdateProjectSettingsRequest): Promise<ProjectSettings> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/settings`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request)
    });
  }

  pauseProject(projectId: string): Promise<Project> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/pause`, { method: 'POST' });
  }

  resumeProject(projectId: string): Promise<Project> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/resume`, { method: 'POST' });
  }

  listTasks(projectId: string): Promise<Task[]> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/tasks`);
  }

  getTaskLog(taskId: string, after = 0): Promise<TaskLog> {
    return this.request(`/api/tasks/${encodeURIComponent(taskId)}/log?after=${after}`);
  }

  getSettings(): Promise<Settings> {
    return this.request('/api/settings');
  }

  listCampaigns(projectId: string): Promise<CampaignList> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/campaigns`);
  }

  getCoverageTree(projectId: string): Promise<CoverageTree> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/coverage/tree`);
  }

  getSourceFile(projectId: string, path: string, startLine = 1, endLine = 500): Promise<SourceFile> {
    const query = new URLSearchParams({ path, start_line: String(startLine), end_line: String(endLine) });
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/coverage/source?${query}`);
  }

  getLineEvidence(projectId: string, path: string, lineNumber: number): Promise<LineEvidencePage> {
    const query = new URLSearchParams({ path });
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/coverage/lines/${lineNumber}?${query}`);
  }

  retainedTestcaseUrl(
    projectId: string, path: string, lineNumber: number,
    strategyAssetId: number, testcaseSha256: string,
  ): string {
    const query = new URLSearchParams({ path, sha256: testcaseSha256 });
    return `${this.baseUrl}/api/projects/${encodeURIComponent(projectId)}/coverage/lines/${lineNumber}`
      + `/testcases/${strategyAssetId}?${query}`;
  }

  listFindings(projectId: string, cursor?: string): Promise<FindingPage> {
    const query = cursor ? `?${new URLSearchParams({ cursor })}` : '';
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/findings${query}`);
  }

  getFinding(projectId: string, findingId: string): Promise<FindingDetail> {
    return this.request(
      `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}`,
    );
  }

  findingReproducerUrl(projectId: string, findingId: string): string {
    return `${this.baseUrl}/api/projects/${encodeURIComponent(projectId)}`
      + `/findings/${encodeURIComponent(findingId)}/reproducer`;
  }

  getProjectLog(
    projectId: string, stream: 'activity' | 'debug', before = -1, limit = 100,
  ): Promise<ProjectEventPage> {
    const query = new URLSearchParams({ before: String(before), limit: String(limit) });
    return this.request(
      `/api/projects/${encodeURIComponent(projectId)}/logs/${stream}?${query}`,
    );
  }

  getProjectEvent(projectId: string, stream: 'activity' | 'debug', eventId: number): Promise<ProjectEvent> {
    return this.request(
      `/api/projects/${encodeURIComponent(projectId)}/logs/${stream}/${eventId}`,
    );
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, init);
    if (!response.ok) throw new Error('BigEye local services are temporarily unavailable.');
    return response.json() as Promise<T>;
  }
}

export function friendlyApiError(error: unknown, fallback: string): string {
  void error;
  return fallback;
}

export function createApiClient(baseUrl?: string): BigEyeApi {
  return new ApiClient(baseUrl);
}
