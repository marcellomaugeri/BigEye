import { LineEvidence } from '../components/coverage/LineEvidence';
import { SourceCode } from '../components/coverage/SourceCode';
import { SourceTree } from '../components/coverage/SourceTree';
import { EmptyState } from '../components/design-system/EmptyState';
import { StatusText } from '../components/design-system/StatusText';
import type { SourceAssuranceModel } from '../controllers/useSourceAssurance';

export function SourceAssuranceView({ model }: { model: SourceAssuranceModel }) {
  if (model.project === null) {
    return <EmptyState title="Source assurance">Select or create a project to inspect source assurance.</EmptyState>;
  }

  return <section aria-labelledby="source-assurance-heading" className="source-assurance-view">
    <header className="view-title">
      <div><p className="eyebrow">Reproducible reach</p><h2 id="source-assurance-heading">Source assurance</h2></div>
      {model.tree && <p className="commit-reference">Clean revision {model.tree.commit_sha.slice(0, 12)}</p>}
    </header>
    {model.error && <StatusText tone="error">{model.error}</StatusText>}
    {model.loading && <StatusText>Loading clean source evidence…</StatusText>}
    <div className="source-workspace">
      <SourceTree files={model.tree?.files ?? []} onSelect={model.onSelectPath} selectedPath={model.selectedPath} />
      <SourceCode onSelect={model.onSelectLine} selectedLine={model.selectedLine} source={model.source} />
      <LineEvidence
        campaigns={model.campaigns}
        evidence={model.evidence}
        onStrategyFilter={model.onStrategyFilter}
        strategyFilter={model.strategyFilter}
      />
    </div>
  </section>;
}
