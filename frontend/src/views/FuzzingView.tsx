import { FuzzingTable } from '../components/fuzzing/FuzzingTable';
import { EmptyState } from '../components/design-system/EmptyState';
import { StatusText } from '../components/design-system/StatusText';
import type { FuzzingModel } from '../models/fuzzing';

export function FuzzingView({ model }: { model: FuzzingModel }) {
  if (model.project === null) return <EmptyState title="Fuzzing">Select or create a project first.</EmptyState>;
  return <section aria-labelledby="fuzzing-heading" className="fuzzing-view">
    <header className="view-title"><h2 id="fuzzing-heading">Fuzzing</h2></header>
    {model.error && <StatusText tone="error">{model.error}</StatusText>}
    {model.loading ? <StatusText>Loading fuzzing evidence…</StatusText> : <FuzzingTable rows={model.rows} />}
  </section>;
}
