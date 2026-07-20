import { FindingDetail } from '../components/findings/FindingDetail';
import { FindingList } from '../components/findings/FindingList';
import { Button } from '../components/design-system/Button';
import { EmptyState } from '../components/design-system/EmptyState';
import { StatusText } from '../components/design-system/StatusText';
import type { FindingsModel } from '../controllers/useFindings';

export function FindingsView({ model }: { model: FindingsModel }) {
  if (model.project === null) {
    return <EmptyState title="Findings">Select or create a project to review replayed findings.</EmptyState>;
  }
  return <section aria-labelledby="findings-heading" className="findings-view">
    <header className="view-title"><div><p className="eyebrow">Deterministic crash evidence</p><h2 id="findings-heading">Findings</h2></div></header>
    {model.error && <StatusText tone="error">{model.error}</StatusText>}
    {model.loading && <StatusText>Loading replayed findings…</StatusText>}
    {!model.loading && model.error === null && model.findings.length === 0
      ? <EmptyState title="No replayed findings yet.">BigEye reports a finding only after deterministic replay and triage.</EmptyState>
      : (model.findings.length > 0 || model.detailLoading) && <div className="findings-workspace">
        <div>
          <FindingList findings={model.findings} onSelect={model.onSelectFinding} selectedFindingId={model.selectedFindingId} />
          {model.nextCursor && <Button disabled={model.loading} onClick={model.onLoadMore} variant="secondary">Load more findings</Button>}
        </div>
        {model.detailLoading
          ? <section className="finding-detail"><StatusText>Loading replay evidence…</StatusText></section>
          : <FindingDetail finding={model.selectedFinding} reproducerUrl={model.reproducerUrl} />}
      </div>}
  </section>;
}
