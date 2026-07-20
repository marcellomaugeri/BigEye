import { NewProjectDialog } from '../components/projects/NewProjectDialog';
import type { Project } from '../models/project';

interface ProjectsViewProps {
  projects: Project[];
  selectedProjectId: string | null;
  projectNotice: string | null;
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
  onSelectProject: (projectId: string) => void;
}

export function ProjectsView(props: ProjectsViewProps) {
  return (
    <section aria-labelledby="projects-heading" className="projects-view">
      <div className="projects-header">
        <h1 id="projects-heading">Projects</h1>
        <NewProjectDialog {...props} />
      </div>
      {props.projectNotice && <p className="project-guidance" role="status">{props.projectNotice}</p>}
      {props.projects.length > 0 && <ul aria-label="Projects" className="project-list">
        {props.projects.map((project) => <li key={project.id}>
          <button
            aria-current={project.id === props.selectedProjectId ? 'true' : undefined}
            onClick={() => props.onSelectProject(project.id)}
            type="button"
          >
            <strong>{project.repository_url}</strong>
            <span>{project.requested_revision}</span>
          </button>
        </li>)}
      </ul>}
    </section>
  );
}
