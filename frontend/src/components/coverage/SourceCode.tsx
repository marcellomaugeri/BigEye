import type { SourceFile } from '../../models/coverage';
import { formatCpuExposure } from './CoverageMap';

export function SourceCode({ source, selectedLine, onSelect }: {
  source: SourceFile | null;
  selectedLine: number | null;
  onSelect: (line: number) => void;
}) {
  const compactExposure = (seconds: number) => `${Number((seconds / 3600).toFixed(2))} CPU h`;
  return <section aria-label="Source code" className="source-code">
    <header>
      <p className="eyebrow">Clean revision</p>
      <h2>{source?.path ?? 'Select a source file'}</h2>
    </header>
    {source && <ol aria-label={`${source.path} source lines`}>
      {source.lines.map((line) => <li key={line.number}>
        <button
          aria-label={`Line ${line.number}, ${line.covered ? 'covered' : 'uncovered'}, ${formatCpuExposure(line.cpu_exposure_seconds)}`}
          aria-pressed={selectedLine === line.number}
          className={selectedLine === line.number ? 'selected' : ''}
          onClick={() => onSelect(line.number)}
          type="button"
        >
          <span aria-hidden="true" className="source-line-number">{line.number}</span>
          <code className="source-line-code">{line.text || ' '}</code>
          <span className="source-line-assurance">
            <span>{line.covered ? 'covered' : 'uncovered'}</span>
            <small>{compactExposure(line.cpu_exposure_seconds)}</small>
          </span>
        </button>
      </li>)}
    </ol>}
  </section>;
}
