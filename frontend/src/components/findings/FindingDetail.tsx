import type { FindingDetail as FindingDetailModel } from '../../models/finding';

function title(value: string): string {
  return value.length === 0 ? 'Unresolved' : value[0].toUpperCase() + value.slice(1);
}

function evidenceHref(evidenceId: string): string {
  return `#activity?evidence=${encodeURIComponent(evidenceId)}`;
}

function sourceHref(sourceLocation: string): string | null {
  const match = /^(.+):([1-9]\d*)$/.exec(sourceLocation);
  if (!match) return null;
  return `#source?path=${encodeURIComponent(match[1])}&line=${match[2]}`;
}

export function FindingDetail({ finding, reproducerUrl }: {
  finding: FindingDetailModel | null;
  reproducerUrl: string | null;
}) {
  if (finding === null) {
    return <section className="finding-detail empty-detail"><p className="muted-copy">Select a finding to inspect its replay evidence.</p></section>;
  }
  const variants = [
    ...finding.replay.compatible_variants,
    ...(finding.replay.clean_variant ? [finding.replay.clean_variant] : []),
  ];
  return <article className="finding-detail">
    <header>
      <div><p className="eyebrow">Priority {finding.priority_rank ?? 'pending'}</p><h2>{title(finding.classification)}</h2></div>
      <p className="finding-reproduction">{finding.reproducible ? 'Reproduced' : 'Not consistently reproduced'}</p>
    </header>
    <p className="finding-description">{finding.description}</p>
    <dl className="finding-summary">
      <div><dt>Occurrences</dt><dd>{finding.occurrence_count} {finding.occurrence_count === 1 ? 'occurrence' : 'occurrences'}</dd></div>
      <div><dt>Replay</dt><dd>{finding.replay.matching} of {finding.replay.attempts} matching attempts</dd></div>
      <div><dt>Minimal input</dt><dd>{finding.reproducer.size} bytes</dd></div>
      <div><dt>Reproducer SHA-256</dt><dd><code>{finding.reproducer.sha256}</code></dd></div>
    </dl>
    {finding.priority_reason && <section><h3>Why this is prioritised</h3><p>{finding.priority_reason}</p></section>}
    <section><h3>Uncertainty</h3><p>{finding.uncertainty}</p></section>
    {finding.repair_intent && <section><h3>Investigation direction</h3><p>{finding.repair_intent}</p></section>}
    {reproducerUrl && <a className="finding-download" download href={reproducerUrl}>Download minimal reproducer</a>}
    <section>
      <h3>Evidence</h3>
      <ul className="evidence-links">{finding.evidence_ids.map((evidenceId) => <li key={evidenceId}>
        <a href={evidenceHref(evidenceId)}>{evidenceId}</a>
      </li>)}</ul>
    </section>
    <details>
      <summary>Technical evidence</summary>
      {variants.map((variant) => <dl className="technical-variant" key={`${variant.variant}-${variant.image_id}`}>
        <div><dt>Variant</dt><dd>{variant.variant}</dd></div>
        <div><dt>Result</dt><dd>{variant.crashed ? 'Crashed' : 'Did not crash'}</dd></div>
        {variant.sanitizer && <div><dt>Sanitizer</dt><dd>{variant.sanitizer}</dd></div>}
        {variant.signal && <div><dt>Signal</dt><dd>{variant.signal}</dd></div>}
        {variant.source_location && <div><dt>Source</dt><dd>{sourceHref(variant.source_location)
          ? <a href={sourceHref(variant.source_location)!}><code>{variant.source_location}</code></a>
          : <code>{variant.source_location}</code>}
        </dd></div>}
        <div><dt>Image</dt><dd><code>{variant.image_id}</code></dd></div>
        {variant.error && <div><dt>Replay error</dt><dd>{variant.error}</dd></div>}
      </dl>)}
      {finding.minimisation && <p>
        Minimisation {finding.minimisation.accepted ? 'accepted' : 'not accepted'}:
        {' '}{finding.minimisation.original_size} to {finding.minimisation.minimal_size} bytes.
      </p>}
      {finding.correction && <pre>{JSON.stringify(finding.correction, null, 2)}</pre>}
    </details>
  </article>;
}
