import { Button } from '../components/design-system/Button';
import { Disclosure } from '../components/design-system/Disclosure';
import { TextField } from '../components/design-system/Field';
import { StatusText } from '../components/design-system/StatusText';
import { MAX_WORKER_COUNT } from '../models/project';

interface ProjectsViewProps {
  repositoryUrl: string;
  revision: string;
  workerCount: string;
  privateRepository: boolean;
  repositoryToken: string;
  loading: boolean;
  error: string | null;
  onRepositoryUrlChange: (value: string) => void;
  onRevisionChange: (value: string) => void;
  onWorkerCountChange: (value: string) => void;
  onPrivateRepositoryChange: () => void;
  onRepositoryTokenChange: (value: string) => void;
  onSubmit: () => void;
}

export function ProjectsView(props: ProjectsViewProps) {
  return (
    <section aria-labelledby="projects-heading" className="panel project-start">
      <p className="eyebrow">Projects</p>
      <h2 id="projects-heading">Start a project</h2>
      <p>Connect a repository and choose the revision to prepare for analysis.</p>
      <form noValidate onSubmit={(event) => { event.preventDefault(); props.onSubmit(); }}>
        <TextField label="Repository URL" name="repository-url" onChange={(event) => props.onRepositoryUrlChange(event.target.value)} placeholder="https://github.com/owner/repository.git" required type="url" value={props.repositoryUrl} />
        <TextField label="Revision" name="revision" onChange={(event) => props.onRevisionChange(event.target.value)} required value={props.revision} />
        <TextField label="Worker count" max={MAX_WORKER_COUNT} min="1" name="worker-count" onChange={(event) => props.onWorkerCountChange(event.target.value)} required step="1" type="number" value={props.workerCount} />
        <Disclosure label="Private repository" onToggle={props.onPrivateRepositoryChange} open={props.privateRepository}>
          <TextField autoComplete="off" label="Read-only access token" name="repository-token" onChange={(event) => props.onRepositoryTokenChange(event.target.value)} type="password" value={props.repositoryToken} />
        </Disclosure>
        {props.error && <StatusText tone="error">{props.error}</StatusText>}
        <Button disabled={props.loading} type="submit">{props.loading ? 'Starting project…' : 'Start project'}</Button>
      </form>
    </section>
  );
}
