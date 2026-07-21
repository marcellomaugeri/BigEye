export type Page = 'projects' | 'overview' | 'fuzzing' | 'source' | 'findings' | 'activity' | 'settings';

const pages: { id: Page; label: string }[] = [
  { id: 'projects', label: 'Projects' },
  { id: 'overview', label: 'Overview' },
  { id: 'fuzzing', label: 'Fuzzing' },
  { id: 'source', label: 'Coverage' },
  { id: 'findings', label: 'Findings' },
  { id: 'activity', label: 'Activity' },
  { id: 'settings', label: 'Settings' }
];

export function Navigation({ activePage, onNavigate }: { activePage: Page; onNavigate: (page: Page) => void }) {
  return (
    <nav className="navigation" aria-label="Main navigation">
      {pages.map(({ id, label }) => (
        <a
          aria-current={activePage === id ? 'page' : undefined}
          href={`#${id}`}
          key={id}
          onClick={(event) => {
            event.preventDefault();
            onNavigate(id);
          }}
        >
          {label}
        </a>
      ))}
    </nav>
  );
}
