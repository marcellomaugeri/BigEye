import type { CampaignList } from '../../models/campaign';
import type { LineEvidence as LineEvidenceModel, LineEvidencePage } from '../../models/coverage';
import { formatCpuExposure } from './CoverageMap';

export function LineEvidence({ campaigns, evidence, strategyFilter, onStrategyFilter, testcaseUrl }: {
  campaigns: CampaignList | null;
  evidence: LineEvidencePage | null;
  strategyFilter: string;
  onStrategyFilter: (strategyId: string) => void;
  testcaseUrl: (item: LineEvidenceModel) => string;
}) {
  const assetNames = new Map(campaigns?.assets.map((asset) => [asset.id, asset.name]) ?? []);
  const strategyIds = [...new Set(evidence?.evidence.map((item) => item.strategy_asset_id) ?? [])];
  const visibleEvidence = evidence?.evidence.filter((item) => (
    strategyFilter === 'all' || String(item.strategy_asset_id) === strategyFilter
  )) ?? [];

  return <section aria-label="Selected line evidence" className="line-evidence">
    <p className="eyebrow">Reproduction evidence</p>
    <h2>First testcase</h2>
    {evidence === null
      ? <p className="muted-copy">Select a covered line to inspect its evidence.</p>
      : evidence.evidence.length === 0
        ? <p className="muted-copy">No replay-verified testcase reaches this line yet.</p>
        : <>
          <label className="field" htmlFor="strategy-filter">
            Reaching strategy
            <select id="strategy-filter" onChange={(event) => onStrategyFilter(event.target.value)} value={strategyFilter}>
              <option value="all">All reaching strategies</option>
              {strategyIds.map((id) => <option key={id} value={String(id)}>{assetNames.get(id) ?? 'Strategy name unavailable'}</option>)}
            </select>
          </label>
          <div className="evidence-list">
            {visibleEvidence.map((item) => {
              const strategyName = assetNames.get(item.strategy_asset_id) ?? 'Strategy name unavailable';
              return <article key={`${item.campaign_id}-${item.strategy_asset_id}-${item.testcase_sha256}`}>
                <h3>{strategyName}</h3>
                <a
                  aria-label={`Download first testcase for ${strategyName}`}
                  download
                  href={testcaseUrl(item)}
                >Download first testcase</a>
                <dl>
                  <div><dt>CPU exposure</dt><dd>{formatCpuExposure(item.cpu_exposure_seconds)}</dd></div>
                  <div><dt>Testcase SHA-256</dt><dd><code>{item.testcase_sha256}</code></dd></div>
                  <div><dt>Replay command</dt><dd><code>{item.replay_command.join(' ')}</code></dd></div>
                </dl>
                <details>
                  <summary>Technical details</summary>
                  <dl><div><dt>Clean image</dt><dd><code>{item.clean_image_id}</code></dd></div></dl>
                </details>
              </article>;
            })}
          </div>
        </>}
  </section>;
}
