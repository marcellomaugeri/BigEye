import type { FindingSummary } from '../../models/finding';

function title(value: string): string {
  return value.length === 0 ? 'Unresolved' : value[0].toUpperCase() + value.slice(1);
}

export function FindingList({ findings, selectedFindingId, onSelect }: {
  findings: FindingSummary[];
  selectedFindingId: string | null;
  onSelect: (findingId: string) => void;
}) {
  return <nav aria-label="Replayed findings" className="finding-list">
    <p className="eyebrow">Priority order</p>
    <h2>Replayed findings</h2>
    <ol>
      {findings.map((finding) => <li key={finding.id}>
        <button
          aria-current={selectedFindingId === finding.id ? 'true' : undefined}
          onClick={() => onSelect(finding.id)}
          type="button"
        >
          <span>Classification: {title(finding.classification)}</span>
          <strong>{finding.description}</strong>
          <small>Observed {finding.occurrence_count} {finding.occurrence_count === 1 ? 'time' : 'times'}</small>
        </button>
      </li>)}
    </ol>
  </nav>;
}
