import { CoverageMap } from '../components/coverage/CoverageMap';
import { EmptyState } from '../components/design-system/EmptyState';
import { StatusText } from '../components/design-system/StatusText';
import type { ProjectOverviewModel } from '../controllers/useProjectOverview';

export function OverviewView({ model }: { model: ProjectOverviewModel }) {
  if (model.project === null) {
    return <EmptyState title="Overview">Select or create a project to inspect its assurance work.</EmptyState>;
  }

  const focusCandidates = model.campaigns?.campaigns.filter((campaign) => (
    campaign.stopped_at === null && campaign.error === null && campaign.retirement_reason === null
    && (campaign.activity === 'running' || campaign.activity === 'waiting')
  )) ?? [];
  const focus = focusCandidates.find((campaign) => campaign.activity === 'running')
    ?? focusCandidates.find((campaign) => campaign.activity === 'waiting') ?? null;
  const findingLabel = model.findingCount === 0
    ? 'No replayed findings yet'
    : `${model.findingsHaveMore ? 'At least ' : ''}${model.findingCount} replayed ${model.findingCount === 1 ? 'finding' : 'findings'}`;
  const campaignEvidence = model.campaigns?.campaigns ?? [];
  const campaignObservation = (campaign: typeof campaignEvidence[number]) => {
    if (campaign.error) return 'Failed';
    if (campaign.retirement_reason) return 'Retired';
    if (campaign.stopped_at) return 'Stopped';
    if (campaign.last_heartbeat_at) return `Last observed ${new Date(campaign.last_heartbeat_at).toLocaleString()}`;
    return 'Configured';
  };
  const activeJobs = campaignEvidence.filter((campaign) => (
    campaign.activity === 'running' && campaign.stopped_at === null
    && campaign.error === null && campaign.retirement_reason === null
  )).length;

  return <div className="overview-view">
    <header className="view-title"><div><p className="eyebrow">Assurance overview</p><h2>Overview</h2></div></header>
    {model.error && <StatusText tone="error">{model.error}</StatusText>}
    {model.loading && <StatusText>Loading verified project evidence…</StatusText>}

    <div className="overview-layout">
      <div className="overview-primary">
        <section aria-labelledby="current-focus-heading" className="current-focus">
          <p className="eyebrow">Now</p>
          <h2 id="current-focus-heading">Current focus</h2>
          {focus ? <>
            <h3>{focus.target_name}</h3>
            {focus.configuration_name && <p className="focus-configuration">{focus.configuration_name}</p>}
            <p className="campaign-observation">{campaignObservation(focus)}</p>
            <p>{focus.next_review_reason ?? 'This configured strategy is awaiting verified evidence.'}</p>
            <details>
              <summary>Technical details</summary>
              <dl><div><dt>Underlying fuzzer</dt><dd>{focus.engine}</dd></div></dl>
            </details>
          </> : <p>No active fuzzing focus is available.</p>}
        </section>
        <CoverageMap files={model.coverage?.files ?? []} summary={model.coverage?.summary ?? null} />
      </div>

      <aside className="overview-aside" aria-label="Project assurance summary">
        <section><p className="eyebrow">Execution</p><h2>{activeJobs} active heavy {activeJobs === 1 ? 'job' : 'jobs'}</h2></section>
        <section>
          <p className="eyebrow">Verified findings</p>
          <h2>{findingLabel}</h2>
          <p>Only deterministic replay results are counted.</p>
        </section>
        <section>
          <p className="eyebrow">Persisted reach</p>
          <h2>Campaign evidence</h2>
          {campaignEvidence.length === 0
            ? <p>No campaign evidence is available yet.</p>
            : <ul className="campaign-evidence-list">{campaignEvidence.map((campaign) => <li key={campaign.id}>
              <strong>{campaign.target_name}</strong>
              {campaign.configuration_name && <span>{campaign.configuration_name}</span>}
              <span>{campaignObservation(campaign)}</span>
              {campaign.unique_line_count !== null && <span>{campaign.unique_line_count} unique lines</span>}
              {campaign.overlapping_line_count !== null && <span>{campaign.overlapping_line_count} overlapping lines</span>}
              {campaign.configuration_purpose && <p>{campaign.configuration_purpose}</p>}
              {campaign.retirement_reason && <p className="retirement-reason">{campaign.retirement_reason}</p>}
            </li>)}</ul>}
        </section>
      </aside>
    </div>
  </div>;
}
