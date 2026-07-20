import { useState } from 'react';
import type { DebugFilter, ProjectEvent } from '../../models/event';

const filters: Array<{ value: DebugFilter; label: string }> = [
  { value: 'all', label: 'All debug evidence' }, { value: 'agent', label: 'Agent calls' },
  { value: 'api', label: 'API calls' }, { value: 'tool', label: 'Tool calls' },
  { value: 'build', label: 'Builds' }, { value: 'fuzzer', label: 'Fuzzer processes' },
  { value: 'coverage', label: 'Coverage' }, { value: 'error', label: 'Errors' },
];

function eventName(event: ProjectEvent): string {
  return typeof event.payload.event === 'string' ? event.payload.event : 'debug.event';
}

function category(event: ProjectEvent): DebugFilter {
  const payload = event.payload;
  const name = eventName(event).toLowerCase();
  if (payload.tool !== undefined || name.includes('tool')) return 'tool';
  if (payload.error !== undefined || name.includes('error')) return 'error';
  if (name.includes('coverage')) return 'coverage';
  if (name.includes('fuzz')) return 'fuzzer';
  if (name.includes('build')) return 'build';
  if (name.includes('api')) return 'api';
  return 'agent';
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function command(value: unknown): string | null {
  return Array.isArray(value) && value.every((item) => typeof item === 'string') ? value.join(' ') : null;
}

function usageText(value: unknown): string[] {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return [];
  const usage = value as Record<string, unknown>;
  const labels = [
    ['input_tokens', 'input tokens'], ['output_tokens', 'output tokens'],
    ['total_tokens', 'total tokens'], ['requests', 'requests'],
  ] as const;
  return labels.flatMap(([key, label]) => typeof usage[key] === 'number' ? [`${usage[key]} ${label}`] : []);
}

function RawJson({ payload }: { payload: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  return <details onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary>Raw sanitized JSON</summary>
    {open && <pre>{JSON.stringify(payload, null, 2)}</pre>}
  </details>;
}

export function DebugLog({ events, filter, onFilter }: {
  events: ProjectEvent[];
  filter: DebugFilter;
  onFilter: (filter: DebugFilter) => void;
}) {
  const visible = events.filter((event) => filter === 'all' || category(event) === filter);
  return <section className="debug-log">
    <header><div><p className="eyebrow">Sanitized local records</p><h2>Advanced local debug evidence</h2></div>
      <label className="field" htmlFor="debug-filter">Debug type
        <select id="debug-filter" onChange={(event) => onFilter(event.target.value as DebugFilter)} value={filter}>
          {filters.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
        </select>
      </label>
    </header>
    <p className="muted-copy">Requests, responses, tool activity and process output are redacted before local storage.</p>
    {visible.length === 0 ? <p className="muted-copy">No debug records match this filter.</p> : <ol className="debug-records">
      {visible.map((event) => {
        const payload = event.payload;
        const invocation = command(payload.command);
        const citations = stringList(payload.web_citations);
        const summaries = stringList(payload.reasoning_summaries);
        return <li key={event.id}>
          <article>
            <header><h3>{eventName(event)}</h3><time dateTime={event.created_at}>{new Date(event.created_at).toLocaleString()}</time></header>
            {usageText(payload.usage).length > 0 && <p className="debug-usage">{usageText(payload.usage).map((item) => <span key={item}>{item}</span>)}</p>}
            {summaries.length > 0 && <section><h4>Reasoning summary</h4>{summaries.map((summary) => <p key={summary}>{summary}</p>)}</section>}
            {invocation && <section><h4>Command</h4><pre>{invocation}</pre></section>}
            {typeof payload.stdout === 'string' && payload.stdout.length > 0 && <section><h4>Standard output</h4><pre>{payload.stdout}</pre></section>}
            {typeof payload.stderr === 'string' && payload.stderr.length > 0 && <section><h4>Standard error</h4><pre>{payload.stderr}</pre></section>}
            {typeof payload.diff === 'string' && payload.diff.length > 0 && <section><h4>Diff</h4><pre>{payload.diff}</pre></section>}
            {citations.length > 0 && <section><h4>Citations</h4><ul>{citations.map((citation) => <li key={citation}><a href={citation}>{citation}</a></li>)}</ul></section>}
            {(payload.input !== undefined || payload.output !== undefined || payload.arguments !== undefined || payload.result !== undefined) && <details>
              <summary>Request and response</summary>
              <pre>{JSON.stringify({ input: payload.input, output: payload.output, arguments: payload.arguments, result: payload.result }, null, 2)}</pre>
            </details>}
            <details>
              <summary>Technical metadata</summary>
              <dl>
                {['trace_id', 'parent_id', 'agent', 'model', 'request_id', 'tool', 'tool_call_id', 'container_id'].map((key) => (
                  payload[key] !== undefined && payload[key] !== null
                    ? <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd><code>{String(payload[key])}</code></dd></div>
                    : null
                ))}
              </dl>
            </details>
            <RawJson payload={payload} />
          </article>
        </li>;
      })}
    </ol>}
  </section>;
}
