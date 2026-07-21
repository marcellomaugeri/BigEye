import type { CoverageFile, CoverageHistoryPoint, CoverageSummary } from '../../models/coverage';
import { CoverageHistoryChart } from './CoverageHistoryChart';

export function formatCpuExposure(seconds: number): string {
  const hours = seconds / 3600;
  const value = Number.isInteger(hours) ? String(hours) : String(Number(hours.toFixed(2)));
  return `${value} CPU exposure ${hours === 1 ? 'hour' : 'hours'}`;
}

function sourceArea(path: string): string {
  const separator = path.lastIndexOf('/');
  return separator === -1 ? path : path.slice(0, separator);
}

function measurement(value: CoverageSummary['lines']): React.ReactNode {
  if (value === null) return <dd>Unavailable</dd>;
  return <dd><strong>{value.covered} / {value.total}</strong><span>{value.percent}%</span></dd>;
}

export function CoverageMap({ files, history = [], summary = null }: {
  files: CoverageFile[];
  history?: CoverageHistoryPoint[];
  summary?: CoverageSummary | null;
}) {
  const areas = files.reduce<Map<string, CoverageFile[]>>((result, file) => {
    const area = sourceArea(file.path);
    result.set(area, [...(result.get(area) ?? []), file]);
    return result;
  }, new Map());

  return <section aria-labelledby="source-coverage-heading" className="coverage-section">
    <div className="section-heading">
      <div>
        <p className="eyebrow">Verified execution</p>
        <h2 id="source-coverage-heading">Source coverage</h2>
      </div>
      <p>{files.length === 0 ? 'No clean coverage has been recorded yet.' : `${files.length} source ${files.length === 1 ? 'file' : 'files'} reached`}</p>
    </div>

    {summary && <dl aria-label="Project coverage totals" className="coverage-totals">
      <div><dt>Lines</dt>{measurement(summary.lines)}</div>
      <div><dt>Branches</dt>{measurement(summary.branches)}</div>
      <div><dt>Functions</dt>{measurement(summary.functions)}</div>
    </dl>}

    <CoverageHistoryChart points={history} />

    {files.length > 0 && <>
      <div aria-label="Source coverage map" className="coverage-map" role="img">
        {[...areas.entries()].map(([area, areaFiles]) => <section className="coverage-area" key={area}>
          <h3>{area}</h3>
          <div className="coverage-area-files">
            {areaFiles.map((file) => <span key={file.path} title={`${file.path}: ${file.covered_lines} covered lines`}>
              {file.path.slice(file.path.lastIndexOf('/') + 1)}
            </span>)}
          </div>
        </section>)}
      </div>

      <div className="table-scroll">
        <table aria-label="Source coverage list" className="evidence-table">
          <thead><tr><th scope="col">Source file</th><th scope="col">Reach</th><th scope="col">Exposure</th></tr></thead>
          <tbody>{files.map((file) => <tr key={file.path}>
            <th scope="row">{file.path}</th>
            <td>{file.covered_lines} covered {file.covered_lines === 1 ? 'line' : 'lines'}</td>
            <td>{formatCpuExposure(file.cpu_exposure_seconds)}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </>}
  </section>;
}
