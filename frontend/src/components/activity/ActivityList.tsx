import type { ProjectEvent } from '../../models/event';

function text(payload: Record<string, unknown>, key: string, fallback: string): string {
  return typeof payload[key] === 'string' && payload[key].length > 0 ? payload[key] as string : fallback;
}

function evidenceHref(evidenceId: string): string {
  if (evidenceId.startsWith('coverage:')) return '#source';
  if (evidenceId.startsWith('finding:') || evidenceId.startsWith('crash:')) return '#findings';
  return '#activity';
}

export function ActivityList({ events }: { events: ProjectEvent[] }) {
  if (events.length === 0) return <p className="muted-copy">No campaign decisions have been recorded yet.</p>;
  return <ol className="activity-list">
    {[...events].reverse().map((event) => {
      const evidence = Array.isArray(event.payload.evidence_ids)
        ? event.payload.evidence_ids.filter((item): item is string => typeof item === 'string') : [];
      return <li key={event.id}>
        <article>
          <time dateTime={event.created_at}>{new Date(event.created_at).toLocaleString()}</time>
          <h2>{text(event.payload, 'decision', 'Campaign activity')}</h2>
          <section><h3>Why BigEye changed this strategy</h3><p>{text(event.payload, 'motivation', 'No structured motivation was recorded.')}</p></section>
          <section><h3>What changed</h3><p>{text(event.payload, 'change', 'No campaign change was recorded.')}</p></section>
          <section><h3>Next review</h3><p>{text(event.payload, 'next_review_condition', 'Review when new campaign evidence arrives.')}</p></section>
          {evidence.length > 0 && <ul className="evidence-links">{evidence.map((evidenceId) => <li key={evidenceId}>
            <a href={evidenceHref(evidenceId)}>{evidenceId}</a>
          </li>)}</ul>}
          {(event.payload.task_id !== undefined || event.payload.state !== undefined) && <details>
            <summary>Internal task</summary>
            <dl>
              {event.payload.task_id !== undefined && <div><dt>Task</dt><dd>{String(event.payload.task_id)}</dd></div>}
              {event.payload.state !== undefined && <div><dt>State</dt><dd>{String(event.payload.state)}</dd></div>}
            </dl>
          </details>}
        </article>
      </li>;
    })}
  </ol>;
}
