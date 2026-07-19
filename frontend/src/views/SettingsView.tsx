import { Button } from '../components/design-system/Button';
import { EmptyState } from '../components/design-system/EmptyState';
import { TextField } from '../components/design-system/Field';
import { StatusText } from '../components/design-system/StatusText';
import type { Project } from '../models/project';
import type { ProjectSettings } from '../models/settings';

interface SettingsViewProps {
  project: Project | null;
  loading: boolean;
  saving: boolean;
  error: string | null;
  settings: ProjectSettings | null;
  workerCount: string;
  repositoryToken: string;
  onWorkerCountChange: (value: string) => void;
  onRepositoryTokenChange: (value: string) => void;
  onSave: () => void;
  onPauseToggle: (paused: boolean) => void;
}

export function SettingsView({ project, loading, saving, error, settings, workerCount, repositoryToken, onWorkerCountChange, onRepositoryTokenChange, onSave, onPauseToggle }: SettingsViewProps) {
  if (!project) return <EmptyState title="Settings">Select a project to review its settings.</EmptyState>;
  return (
    <section aria-labelledby="settings-heading" className="panel">
      <h2 id="settings-heading">Settings</h2>
      <p>Revision and commit are recorded for this project and cannot be changed here.</p>
      {loading && <StatusText>Loading project settings…</StatusText>}
      {error && <StatusText tone="error">{error}</StatusText>}
      {settings && <form noValidate onSubmit={(event) => { event.preventDefault(); onSave(); }}>
        <TextField label="Revision" readOnly value={settings.requested_revision} />
        <TextField label="Commit" readOnly value={settings.commit_sha ?? 'Not resolved yet'} />
        <TextField label="Worker count" min="1" onChange={(event) => onWorkerCountChange(event.target.value)} step="1" type="number" value={workerCount} />
        <TextField autoComplete="off" label="Read-only access token" onChange={(event) => onRepositoryTokenChange(event.target.value)} type="password" value={repositoryToken} />
        <p className="field-hint">{settings.token_present ? 'Token configured' : 'No token configured'}</p>
        <Button disabled={saving} type="submit">Save settings</Button>
        <Button disabled={saving} onClick={() => onPauseToggle(!project.paused_at)} type="button" variant="secondary">{project.paused_at ? 'Resume project' : 'Pause project'}</Button>
      </form>}
    </section>
  );
}
