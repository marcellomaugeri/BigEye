import { StatusMessage } from '../components/StatusMessage';
import type { Settings } from '../models/settings';

interface SettingsViewProps {
  loading: boolean;
  error: string | null;
  settings: Settings | null;
}

const checks: { key: keyof Settings; label: string }[] = [
  { key: 'database', label: 'Database' },
  { key: 'docker', label: 'Docker' },
  { key: 'openai_api_key_present', label: 'OpenAI API key' },
  { key: 'toolchain', label: 'Toolchain' }
];

export function SettingsView({ loading, error, settings }: SettingsViewProps) {
  return (
    <section aria-labelledby="settings-heading" className="panel">
      <h2 id="settings-heading">Settings</h2>
      <p>Connection checks report availability only. Secret values are never shown.</p>
      {loading && <StatusMessage>Loading checks…</StatusMessage>}
      {error && <StatusMessage tone="error">{error}</StatusMessage>}
      {settings && <ul className="record-list">{checks.map(({ key, label }) => <li key={key}><strong>{label}</strong><span>{settings[key] ? 'Available' : 'Unavailable'}</span></li>)}</ul>}
    </section>
  );
}
