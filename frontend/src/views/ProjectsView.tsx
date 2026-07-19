import { StatusMessage } from '../components/StatusMessage';
import { MAX_WORKER_COUNT, type Project } from '../models/project';

interface ProjectsViewProps {
  repositoryUrl: string;
  workerCount: string;
  loading: boolean;
  error: string | null;
  onRepositoryUrlChange: (value: string) => void;
  onWorkerCountChange: (value: string) => void;
  onSubmit: () => void;
  selectedProject: Project | null;
}

export function ProjectsView(props: ProjectsViewProps) {
  const state = props.selectedProject?.error ? 'Failed' : props.selectedProject?.finished_at ? 'Complete' : 'Running';
  return (
    <section aria-labelledby="projects-heading" className="panel">
      <h2 id="projects-heading">Projects</h2>
      <p>Start a repository campaign with the number of fuzzer workers to prepare.</p>
      <form noValidate onSubmit={(event) => { event.preventDefault(); props.onSubmit(); }}>
        <label>
          Repository URL
          <input
            name="repository-url"
            onChange={(event) => props.onRepositoryUrlChange(event.target.value)}
            placeholder="https://github.com/owner/repository.git"
            required
            type="url"
            value={props.repositoryUrl}
          />
        </label>
        <label>
          Fuzzer workers
          <input
            name="worker-count"
            onChange={(event) => props.onWorkerCountChange(event.target.value)}
            required
            max={MAX_WORKER_COUNT}
            min="1"
            step="1"
            type="number"
            value={props.workerCount}
          />
        </label>
        {props.error && <StatusMessage tone="error">{props.error}</StatusMessage>}
        <button disabled={props.loading} type="submit">{props.loading ? 'Creating project…' : 'Create project'}</button>
      </form>
      {props.selectedProject && <aside aria-label="Selected project summary">
        <h3>Selected project</h3>
        <p>{props.selectedProject.repository_url}</p>
        <p>{props.selectedProject.worker_count} worker{props.selectedProject.worker_count === 1 ? '' : 's'} · {state}</p>
        {props.selectedProject.commit_sha && <p>{props.selectedProject.commit_sha}</p>}
        {props.selectedProject.error && <StatusMessage tone="error">{props.selectedProject.error}</StatusMessage>}
      </aside>}
    </section>
  );
}
