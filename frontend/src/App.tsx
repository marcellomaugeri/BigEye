import { useMemo, useState } from 'react';
import { Navigation, type Page } from './components/Navigation';
import { ProjectPicker } from './components/ProjectPicker';
import { EmptyState } from './components/design-system/EmptyState';
import { StatusText } from './components/design-system/StatusText';
import { useProjectSettings } from './controllers/useProjectSettings';
import { useProjects } from './controllers/useProjects';
import { createApiClient, type BigEyeApi } from './services/apiClient';
import { ProjectsView } from './views/ProjectsView';
import { SettingsView } from './views/SettingsView';
import './app.css';

interface AppProps {
  api?: BigEyeApi;
}

export function App({ api }: AppProps) {
  const apiClient = useMemo(() => api ?? createApiClient(), [api]);
  const [page, setPage] = useState<Page>('projects');
  const projects = useProjects(apiClient, () => setPage('overview'));
  const projectSettings = useProjectSettings(apiClient, projects.selectedProject, page === 'settings', projects.replaceProject);

  const content = {
    projects: <ProjectsView
      error={projects.error}
      loading={projects.creating}
      onPrivateRepositoryChange={() => projects.setPrivateRepository(!projects.privateRepository)}
      onRepositoryTokenChange={projects.setRepositoryToken}
      onRepositoryUrlChange={projects.setRepositoryUrl}
      onRevisionChange={projects.setRevision}
      onSubmit={projects.submitProject}
      onWorkerCountChange={projects.setWorkerCount}
      privateRepository={projects.privateRepository}
      repositoryToken={projects.repositoryToken}
      repositoryUrl={projects.repositoryUrl}
      revision={projects.revision}
      workerCount={projects.workerCount}
    />,
    overview: <EmptyState title="Overview">Project evidence is not available yet.</EmptyState>,
    source: <EmptyState title="Source">Source details are unavailable until repository preparation completes.</EmptyState>,
    findings: <EmptyState title="Findings">Findings are unavailable until crash processing produces evidence.</EmptyState>,
    activity: <EmptyState title="Activity">Activity is unavailable until project events are recorded.</EmptyState>,
    settings: <SettingsView
      error={projectSettings.error}
      loading={projectSettings.loading}
      onPauseToggle={projectSettings.setPaused}
      onRepositoryTokenChange={projectSettings.setRepositoryToken}
      onSave={projectSettings.save}
      onWorkerCountChange={projectSettings.setWorkerCount}
      project={projects.selectedProject}
      repositoryToken={projectSettings.repositoryToken}
      saving={projectSettings.saving}
      settings={projectSettings.settings}
      workerCount={projectSettings.workerCount}
    />
  } satisfies Record<Page, React.ReactNode>;

  return <main className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span>BigEye</span><small>Repository intelligence</small></div>
      <Navigation activePage={page} onNavigate={setPage} />
    </aside>
    <div className="work-surface">
      <header className="app-header">
        <div><p className="eyebrow">Campaign workspace</p><h1>BigEye</h1></div>
        <ProjectPicker loading={projects.loading} onSelect={projects.selectProject} projects={projects.projects} selectedProjectId={projects.selectedProjectId} />
      </header>
      {projects.error && page !== 'projects' && <StatusText tone="error">{projects.error}</StatusText>}
      {content[page]}
    </div>
  </main>;
}
