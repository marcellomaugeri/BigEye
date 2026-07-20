import type { FuzzingRow } from '../../models/fuzzing';

function title(value: string): string {
  return value.length === 0 ? value : value[0].toUpperCase() + value.slice(1);
}

function cpu(seconds: number): string {
  return `${Number((seconds / 3_600).toFixed(2))} CPU h`;
}

export function FuzzingTable({ rows }: { rows: FuzzingRow[] }) {
  if (rows.length === 0) return <p className="muted-copy">No fuzzing work is active yet.</p>;
  return <div className="table-scroll fuzzing-table-scroll">
    <table aria-label="Autonomous fuzzing campaigns" className="evidence-table fuzzing-table">
      <thead><tr>
        <th scope="col">Target</th><th scope="col">Activity</th><th scope="col">5m change</th>
        <th scope="col">Total reach</th><th scope="col">CPU time</th><th scope="col">Last evidence</th><th scope="col">State</th>
      </tr></thead>
      <tbody>{rows.map((row) => <tr key={row.id}>
        <th scope="row">
          <strong>{row.target}</strong>
          {row.configuration && <span>{row.configuration}</span>}
          {row.purpose && <span>{row.purpose}</span>}
          <small className="technical-metadata">{row.engine}</small>
        </th>
        <td>{title(row.activity)}</td>
        <td>{row.coverageDelta5m === null ? 'Unavailable' : `${row.coverageDelta5m >= 0 ? '+' : ''}${row.coverageDelta5m} lines`}</td>
        <td>{row.totalReach === null ? 'Unavailable' : `${row.totalReach} lines`}</td>
        <td>{cpu(row.cpuExposureSeconds)}</td>
        <td>{row.lastEvidenceAt === null ? 'Unavailable' : new Date(row.lastEvidenceAt).toLocaleString()}</td>
        <td className="campaign-state" data-state={row.state}>{row.state}</td>
      </tr>)}</tbody>
    </table>
  </div>;
}
