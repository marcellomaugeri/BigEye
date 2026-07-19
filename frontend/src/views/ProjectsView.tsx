import { StatusMessage } from '../components/StatusMessage';

interface ProjectsViewProps {
  repositoryUrl: string;
  workerCount: string;
  loading: boolean;
  error: string | null;
  onRepositoryUrlChange: (value: string) => void;
  onWorkerCountChange: (value: string) => void;
  onSubmit: () => void;
}

export function ProjectsView(props: ProjectsViewProps) {
  return (
    <section aria-labelledby="projects-heading" className="panel">
      <h2 id="projects-heading">Projects</h2>
      <p>Start a repository campaign with the number of fuzzer workers to prepare.</p>
      <form onSubmit={(event) => { event.preventDefault(); props.onSubmit(); }}>
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
            step="1"
            type="number"
            value={props.workerCount}
          />
        </label>
        {props.error && <StatusMessage tone="error">{props.error}</StatusMessage>}
        <button disabled={props.loading} type="submit">{props.loading ? 'Creating project…' : 'Create project'}</button>
      </form>
    </section>
  );
}
