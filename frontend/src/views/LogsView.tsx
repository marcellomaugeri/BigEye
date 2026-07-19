import { StatusMessage } from '../components/StatusMessage';
import type { Task } from '../models/task';

interface LogsViewProps {
  hasProject: boolean;
  tasks: Task[];
  selectedTaskId: string | null;
  loading: boolean;
  error: string | null;
  content: string;
  onSelectTask: (taskId: string) => void;
}

export function LogsView({ hasProject, tasks, selectedTaskId, loading, error, content, onSelectTask }: LogsViewProps) {
  return (
    <section aria-labelledby="logs-heading" className="panel">
      <h2 id="logs-heading">Logs</h2>
      {!hasProject && <StatusMessage>Select a project to view its task logs.</StatusMessage>}
      {hasProject && tasks.length === 0 && !loading && <StatusMessage>This project has no task logs yet.</StatusMessage>}
      {tasks.length > 0 && (
        <label>
          Task log
          <select onChange={(event) => onSelectTask(event.target.value)} value={selectedTaskId ?? ''}>
            {tasks.map((task) => <option key={task.id} value={task.id}>{task.name}</option>)}
          </select>
        </label>
      )}
      {loading && <StatusMessage>Loading log…</StatusMessage>}
      {error && <StatusMessage tone="error">{error}</StatusMessage>}
      {!loading && !error && selectedTaskId && content.length === 0 && <StatusMessage>This task has not written any log output yet.</StatusMessage>}
      {content && <pre aria-label="Task log output">{content}</pre>}
    </section>
  );
}
