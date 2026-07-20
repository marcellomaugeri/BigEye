import { useCallback, useEffect, useMemo, useState } from 'react';
import { Navigation, type Page } from './components/Navigation';
import { ProjectPicker } from './components/ProjectPicker';
import { StatusText } from './components/design-system/StatusText';
import { useProjectOverview } from './controllers/useProjectOverview';
import { useActivity } from './controllers/useActivity';
import { useFindings } from './controllers/useFindings';
import { useProjectSettings } from './controllers/useProjectSettings';
import { useProjects } from './controllers/useProjects';
import { useSourceAssurance } from './controllers/useSourceAssurance';
import { createApiClient, type BigEyeApi } from './services/apiClient';
import { createEventStream, type ProjectEventStream } from './services/eventStream';
import { OverviewView } from './views/OverviewView';
import { ActivityView } from './views/ActivityView';
import { FindingsView } from './views/FindingsView';
import { ProjectsView } from './views/ProjectsView';
import { SettingsView } from './views/SettingsView';
import { SourceAssuranceView } from './views/SourceAssuranceView';
import './app.css';

interface AppProps {
  api?: BigEyeApi;
  events?: ProjectEventStream;
}

const pages: Page[] = ['projects', 'overview', 'source', 'findings', 'activity', 'settings'];

function pageFromLocation(): Page {
  const candidate = window.location.hash.slice(1).split('?', 1)[0];
  return pages.includes(candidate as Page) ? candidate as Page : 'projects';
}

export function App({ api, events }: AppProps) {
  const apiClient = useMemo(() => api ?? createApiClient(), [api]);
  const eventStream = useMemo(() => events ?? createEventStream(), [events]);
  const [page, setPage] = useState<Page>(pageFromLocation);
  const navigate = useCallback((nextPage: Page) => {
    setPage(nextPage);
    window.history.replaceState(null, '', `#${nextPage}`);
  }, []);
  useEffect(() => {
    const onHashChange = () => setPage(pageFromLocation());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const projects = useProjects(apiClient, () => navigate('overview'));
  const projectSettings = useProjectSettings(apiClient, projects.selectedProject, page === 'settings', projects.replaceProject);
  const overview = useProjectOverview(
    apiClient, eventStream, projects.selectedProject, page === 'overview', projects.replaceProject,
  );
  const sourceAssurance = useSourceAssurance(
    apiClient, eventStream, projects.selectedProject, page === 'source',
  );
  const findings = useFindings(
    apiClient, eventStream, projects.selectedProject, page === 'findings',
  );
  const activity = useActivity(
    apiClient, eventStream, projects.selectedProject, page === 'activity',
  );

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
    overview: <OverviewView model={overview} />,
    source: <SourceAssuranceView model={sourceAssurance} />,
    findings: <FindingsView model={findings} />,
    activity: <ActivityView model={activity} />,
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
      localServices={projectSettings.localServices}
      workerCount={projectSettings.workerCount}
    />
  } satisfies Record<Page, React.ReactNode>;

  return <main className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span>BigEye</span><small>Continuous assurance</small></div>
      <Navigation activePage={page} onNavigate={navigate} />
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
