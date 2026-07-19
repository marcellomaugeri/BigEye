import type { CreateProjectRequest, Project } from '../models/project';
import type { Settings } from '../models/settings';
import type { Task, TaskLog } from '../models/task';

export interface BigEyeApi {
  createProject(request: CreateProjectRequest): Promise<Project>;
  listProjects(): Promise<Project[]>;
  getProject(projectId: string): Promise<Project>;
  listTasks(projectId: string): Promise<Task[]>;
  getTaskLog(taskId: string, after?: number): Promise<TaskLog>;
  getSettings(): Promise<Settings>;
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

  listTasks(projectId: string): Promise<Task[]> {
    return this.request(`/api/projects/${encodeURIComponent(projectId)}/tasks`);
  }

  getTaskLog(taskId: string, after = 0): Promise<TaskLog> {
    return this.request(`/api/tasks/${encodeURIComponent(taskId)}/log?after=${after}`);
  }

  getSettings(): Promise<Settings> {
    return this.request('/api/settings');
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, init);
    if (!response.ok) throw new Error(`Request failed (${response.status}).`);
    return response.json() as Promise<T>;
  }
}

export function createApiClient(baseUrl?: string): BigEyeApi {
  return new ApiClient(baseUrl);
}
