import { useCallback, useEffect, useMemo, useState } from 'react';
import { Navigation, type Page } from './components/Navigation';
import { FirstVisitIntro } from './components/FirstVisitIntro';
import { ProjectPicker } from './components/ProjectPicker';
import { ManagerActivityFooter } from './components/activity/ManagerActivityFooter';
import { StatusText } from './components/design-system/StatusText';
import { useProjectOverview } from './controllers/useProjectOverview';
import { useActivity } from './controllers/useActivity';
import { useFindings } from './controllers/useFindings';
import { useFuzzing } from './controllers/useFuzzing';
import { useFirstVisitIntro } from './controllers/useFirstVisitIntro';
import { useManagerActivity } from './controllers/useManagerActivity';
import { useProjectSettings } from './controllers/useProjectSettings';
import { useProjects } from './controllers/useProjects';
import { useSourceAssurance } from './controllers/useSourceAssurance';
import { createApiClient, type BigEyeApi } from './services/apiClient';
import { createEventStream, type ProjectEventStream } from './services/eventStream';
import { OverviewView } from './views/OverviewView';
import { ActivityView } from './views/ActivityView';
import { FindingsView } from './views/FindingsView';
import { FuzzingView } from './views/FuzzingView';
import { ProjectsView } from './views/ProjectsView';
import { SettingsView } from './views/SettingsView';
import { SourceAssuranceView } from './views/SourceAssuranceView';
import './app.css';

interface AppProps {
  api?: BigEyeApi;
  events?: ProjectEventStream;
}

const pages: Page[] = ['projects', 'overview', 'fuzzing', 'source', 'findings', 'activity', 'settings'];

function pageFromLocation(): Page {
  const candidate = window.location.hash.slice(1).split('?', 1)[0];
  return pages.includes(candidate as Page) ? candidate as Page : 'projects';
}

export function App(props: AppProps) {
  const introVisible = useFirstVisitIntro();
  return introVisible ? <FirstVisitIntro visible /> : <BigEyeApplication {...props} />;
}

function BigEyeApplication({ api, events }: AppProps) {
  const apiClient = useMemo(() => api ?? createApiClient(), [api]);
  const eventStream = useMemo(() => events ?? createEventStream(), [events]);
  const [page, setPage] = useState<Page>(pageFromLocation);
  const [projectNotice, setProjectNotice] = useState<string | null>(null);
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
  const managerActivity = useManagerActivity(apiClient, eventStream, projects.selectedProject);
  useEffect(() => {
    if (!projects.loading && projects.error === null && projects.selectedProject === null && page !== 'projects') {
      setProjectNotice('Select or create a project first.');
      navigate('projects');
    }
  }, [navigate, page, projects.error, projects.loading, projects.selectedProject]);
  useEffect(() => {
    if (projects.selectedProject !== null) setProjectNotice(null);
  }, [projects.selectedProject]);
  const projectSettings = useProjectSettings(apiClient, projects.selectedProject, page === 'settings');
  const overview = useProjectOverview(
    apiClient, eventStream, projects.selectedProject, page === 'overview', projects.replaceProject,
  );
  const sourceAssurance = useSourceAssurance(
    apiClient, eventStream, projects.selectedProject, page === 'source',
  );
  const fuzzing = useFuzzing(apiClient, eventStream, projects.selectedProject, page === 'fuzzing');
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
      onSelectProject={projects.selectProject}
      onSubmit={projects.submitProject}
      onWorkerCountChange={projects.setWorkerCount}
      privateRepository={projects.privateRepository}
      projects={projects.projects}
      projectNotice={projectNotice}
      repositoryToken={projects.repositoryToken}
      repositoryUrl={projects.repositoryUrl}
      revision={projects.revision}
      selectedProjectId={projects.selectedProjectId}
      workerCount={projects.workerCount}
    />,
    overview: <OverviewView model={overview} />,
    fuzzing: <FuzzingView model={fuzzing} />,
    source: <SourceAssuranceView model={sourceAssurance} />,
    findings: <FindingsView model={findings} />,
    activity: <ActivityView model={activity} />,
    settings: <SettingsView
      error={projectSettings.error}
      loading={projectSettings.loading}
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
      <div className="brand"><span>BigEye</span></div>
      <Navigation activePage={page} onNavigate={navigate} />
    </aside>
    <div className="work-surface">
      {projects.projects.length > 0 && <header className="app-header">
        <ProjectPicker loading={projects.loading} onSelect={projects.selectProject} projects={projects.projects} selectedProjectId={projects.selectedProjectId} />
      </header>}
      {projects.error && page !== 'projects' && <StatusText tone="error">{projects.error}</StatusText>}
      {content[page]}
    </div>
    <ManagerActivityFooter
      message={managerActivity.message}
      onOpenActivity={() => navigate('activity')}
    />
  </main>;
}
