export interface Task {
  id: string;
  project_id: string;
  name: string;
  created_at: string;
  finished_at: string | null;
  error: string | null;
}

export type TaskDisplayState = 'Running' | 'Complete' | 'Failed';

export function taskDisplayState(task: Task): TaskDisplayState {
  if (task.error) return 'Failed';
  if (task.finished_at) return 'Complete';
  return 'Running';
}

export interface TaskLog {
  content: string;
  next_offset: number;
}
