import { StatusMessage } from '../components/StatusMessage';
import type { Task } from '../models/task';
import { taskDisplayState } from '../models/task';

interface TasksViewProps {
  hasProject: boolean;
  loading: boolean;
  error: string | null;
  tasks: Task[];
}

export function TasksView({ hasProject, loading, error, tasks }: TasksViewProps) {
  return (
    <section aria-labelledby="tasks-heading" className="panel">
      <h2 id="tasks-heading">Tasks</h2>
      {!hasProject && <StatusMessage>Select a project to view its tasks.</StatusMessage>}
      {hasProject && loading && <StatusMessage>Loading tasks…</StatusMessage>}
      {error && <StatusMessage tone="error">{error}</StatusMessage>}
      {hasProject && !loading && !error && tasks.length === 0 && <StatusMessage>This project has no tasks yet.</StatusMessage>}
      {tasks.length > 0 && (
        <ul className="record-list">
          {tasks.map((task) => <li key={task.id}><strong>{task.name}</strong><span>{taskDisplayState(task)}</span>{task.error && <small>{task.error}</small>}</li>)}
        </ul>
      )}
    </section>
  );
}
