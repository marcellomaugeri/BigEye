import { Button } from '../components/design-system/Button';
import { EmptyState } from '../components/design-system/EmptyState';
import { TextField } from '../components/design-system/Field';
import { StatusText } from '../components/design-system/StatusText';
import type { Project } from '../models/project';
import type { ProjectSettings, Settings } from '../models/settings';

interface SettingsViewProps {
  project: Project | null;
  loading: boolean;
  saving: boolean;
  error: string | null;
  settings: ProjectSettings | null;
  localServices: Settings | null;
  workerCount: string;
  repositoryToken: string;
  onWorkerCountChange: (value: string) => void;
  onRepositoryTokenChange: (value: string) => void;
  onSave: () => void;
  onPauseToggle: (paused: boolean) => void;
}

const serviceRows: Array<{ key: keyof Settings; label: string; ready: string }> = [
  { key: 'database', label: 'Database', ready: 'Ready' },
  { key: 'docker', label: 'Docker', ready: 'Ready' },
  { key: 'openai_api_key_present', label: 'OpenAI access', ready: 'Configured' },
  { key: 'toolchain', label: 'Toolchain', ready: 'Ready' },
];

export function SettingsView({ project, loading, saving, error, settings, localServices, workerCount, repositoryToken, onWorkerCountChange, onRepositoryTokenChange, onSave, onPauseToggle }: SettingsViewProps) {
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
      {localServices && <section aria-labelledby="local-services-heading" className="local-services">
        <p className="eyebrow">This laptop</p>
        <h3 id="local-services-heading">Local services</h3>
        <ul>{serviceRows.map((service) => {
          const available = localServices[service.key];
          return <li className={available ? 'service-ready' : 'service-attention'} key={service.key}>
            <span>{service.label}</span><strong>{available ? service.ready : 'Needs attention'}</strong>
          </li>;
        })}</ul>
      </section>}
    </section>
  );
}
