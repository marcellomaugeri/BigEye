import type { Project } from '../models/project';

interface ProjectPickerProps {
  projects: Project[];
  selectedProjectId: string | null;
  loading: boolean;
  onSelect: (projectId: string) => void;
}

export function ProjectPicker({ projects, selectedProjectId, loading, onSelect }: ProjectPickerProps) {
  return (
    <label className="project-picker">
      <span>Current project</span>
      <select
        aria-label="Current project"
        disabled={loading || projects.length === 0}
        onChange={(event) => onSelect(event.target.value)}
        value={selectedProjectId ?? ''}
      >
        {projects.length === 0 && <option value="">No projects yet</option>}
        {projects.map((project) => (
          <option key={project.id} value={project.id}>{project.repository_url}</option>
        ))}
      </select>
    </label>
  );
}
