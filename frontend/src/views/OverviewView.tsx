import { CoverageMap } from '../components/coverage/CoverageMap';
import { Button } from '../components/design-system/Button';
import { EmptyState } from '../components/design-system/EmptyState';
import { StatusText } from '../components/design-system/StatusText';
import type { ProjectOverviewModel } from '../controllers/useProjectOverview';

export function OverviewView({ model }: { model: ProjectOverviewModel }) {
  if (model.project === null) {
    return <EmptyState title="Overview">Select or create a project to inspect its assurance work.</EmptyState>;
  }

  const active = model.campaigns?.campaigns.find((campaign) => campaign.stopped_at === null && campaign.error === null) ?? null;
  const findingLabel = model.findingCount === 0
    ? 'No replayed findings yet'
    : `${model.findingsHaveMore ? 'At least ' : ''}${model.findingCount} replayed ${model.findingCount === 1 ? 'finding' : 'findings'}`;
  const activeCampaigns = model.campaigns?.campaigns.filter((campaign) => (
    campaign.stopped_at === null && campaign.error === null
  )) ?? [];

  return <div className="overview-view">
    <header className="view-title">
      <div><p className="eyebrow">Assurance overview</p><h2>Overview</h2></div>
      <Button disabled={model.pauseChanging} onClick={model.onTogglePause} variant="secondary">
        {model.project.paused_at === null ? 'Pause project' : 'Resume project'}
      </Button>
    </header>
    {model.error && <StatusText tone="error">{model.error}</StatusText>}
    {model.loading && <StatusText>Loading verified project evidence…</StatusText>}

    <div className="overview-layout">
      <div className="overview-primary">
        <section aria-labelledby="current-focus-heading" className="current-focus">
          <p className="eyebrow">Now</p>
          <h2 id="current-focus-heading">Current focus</h2>
          {active ? <>
            <h3>{active.target_name}</h3>
            {active.configuration_name && <p className="focus-configuration">{active.configuration_name}</p>}
            <p>{active.next_review_reason ?? 'The current strategy is running and awaiting verified evidence.'}</p>
            <details>
              <summary>Technical details</summary>
              <dl><div><dt>Underlying fuzzer</dt><dd>{active.engine}</dd></div></dl>
            </details>
          </> : <p>No active assurance strategy is running yet.</p>}
        </section>
        <CoverageMap files={model.coverage?.files ?? []} />
      </div>

      <aside className="overview-aside" aria-label="Project assurance summary">
        <section>
          <p className="eyebrow">Verified findings</p>
          <h2>{findingLabel}</h2>
          <p>Only deterministic replay results are counted.</p>
        </section>
        <section>
          <p className="eyebrow">Active work</p>
          <h2>Active work</h2>
          {activeCampaigns.length === 0
            ? <p>No assurance work is active yet.</p>
            : <ul>{activeCampaigns.map((campaign) => <li key={campaign.id}>
              <strong>{campaign.target_name}</strong>
              {campaign.configuration_name && <span>{campaign.configuration_name}</span>}
            </li>)}</ul>}
        </section>
      </aside>
    </div>
  </div>;
}
