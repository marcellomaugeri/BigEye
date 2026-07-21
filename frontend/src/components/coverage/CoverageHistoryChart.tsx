import type { CoverageHistoryPoint } from '../../models/coverage';

function percent(value: number): string {
  return `${Number(value.toFixed(2))}%`;
}

export function CoverageHistoryChart({ points }: { points: CoverageHistoryPoint[] }) {
  if (points.length === 0) {
    return <div aria-label="Absolute line coverage over time" className="coverage-history-empty" role="img">
      Coverage history starts with the next verified clean snapshot.
    </div>;
  }

  const width = 720;
  const height = 220;
  const left = 42;
  const right = 18;
  const top = 18;
  const bottom = 34;
  const times = points.map((point) => new Date(point.observed_at).getTime());
  const firstTime = Math.min(...times);
  const lastTime = Math.max(...times);
  const ceiling = Math.max(10, Math.ceil(Math.max(...points.map((point) => point.percent)) / 10) * 10);
  const x = (time: number, index: number) => (
    firstTime === lastTime
      ? left + (width - left - right) * (points.length === 1 ? 0.5 : index / (points.length - 1))
      : left + ((time - firstTime) / (lastTime - firstTime)) * (width - left - right)
  );
  const y = (value: number) => top + (1 - value / ceiling) * (height - top - bottom);
  const coordinates = points.map((point, index) => `${x(times[index], index)},${y(point.percent)}`).join(' ');
  const first = points[0];
  const latest = points[points.length - 1];

  return <div className="coverage-history-chart">
    <div className="coverage-history-heading">
      <div><p className="eyebrow">Verified trend</p><h3>Absolute line coverage over time</h3></div>
      <strong>{percent(latest.percent)}</strong>
    </div>
    <svg aria-label="Absolute line coverage over time" role="img" viewBox={`0 0 ${width} ${height}`}>
      <line className="coverage-history-axis" x1={left} x2={width - right} y1={height - bottom} y2={height - bottom} />
      <line className="coverage-history-axis" x1={left} x2={left} y1={top} y2={height - bottom} />
      <text x={left - 8} y={height - bottom + 4} textAnchor="end">0%</text>
      <text x={left - 8} y={top + 4} textAnchor="end">{ceiling}%</text>
      {points.length > 1 && <polyline className="coverage-history-line" fill="none" points={coordinates} />}
      {points.map((point, index) => <circle
        className="coverage-history-point"
        cx={x(times[index], index)}
        cy={y(point.percent)}
        key={`${point.observed_at}-${index}`}
        r="4"
      ><title>{`${new Date(point.observed_at).toLocaleString()}: ${point.covered} / ${point.total} lines (${percent(point.percent)})`}</title></circle>)}
      <text x={x(times[0], 0)} y={y(first.percent) - 10} textAnchor="middle">{percent(first.percent)}</text>
      {points.length > 1 && <text x={x(times.at(-1)!, points.length - 1)} y={y(latest.percent) - 10} textAnchor="middle">{percent(latest.percent)}</text>}
    </svg>
    <div className="coverage-history-times"><span>{new Date(first.observed_at).toLocaleString()}</span><span>{new Date(latest.observed_at).toLocaleString()}</span></div>
  </div>;
}
