import { useMemo } from 'react';
import { useBigEyeController } from './controllers/useBigEyeController';
import { Navigation } from './components/Navigation';
import { ProjectPicker } from './components/ProjectPicker';
import { ProjectsView } from './views/ProjectsView';
import { TasksView } from './views/TasksView';
import { FindingsView } from './views/FindingsView';
import { LogsView } from './views/LogsView';
import { SettingsView } from './views/SettingsView';
import { createApiClient, type BigEyeApi } from './services/apiClient';
import { createEventStream, type ProjectEventStream } from './services/eventStream';
import './app.css';

interface AppProps {
  api?: BigEyeApi;
  eventStream?: ProjectEventStream;
}

export function App({ api, eventStream }: AppProps) {
  const apiClient = useMemo(() => api ?? createApiClient(), [api]);
  const projectEventStream = useMemo(() => eventStream ?? createEventStream(), [eventStream]);
  const controller = useBigEyeController(apiClient, projectEventStream);

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">BigEye</p>
          <h1>Repository campaigns</h1>
        </div>
        <ProjectPicker
          projects={controller.projects}
          selectedProjectId={controller.selectedProjectId}
          loading={controller.projectsLoading}
          onSelect={controller.selectProject}
        />
      </header>
      <Navigation activePage={controller.page} onNavigate={controller.navigate} />
      {controller.page === 'projects' && <ProjectsView {...controller.projectsView} />}
      {controller.page === 'tasks' && <TasksView {...controller.tasksView} />}
      {controller.page === 'findings' && <FindingsView />}
      {controller.page === 'logs' && <LogsView {...controller.logsView} />}
      {controller.page === 'settings' && <SettingsView {...controller.settingsView} />}
    </main>
  );
}
