import type { ReproductionOutput, ReproductionRun } from '../../models/reproduction';

function phase(value: ReproductionRun['phase']): string {
  return value === 'timed_out' ? 'Timed out' : value[0].toUpperCase() + value.slice(1);
}

export function ReproductionTerminal({ run, output }: {
  run: ReproductionRun | null;
  output: ReproductionOutput[];
}) {
  if (run === null) return null;
  return <section aria-label="Finding reproduction" className="reproduction">
    <header><h3>Reproduction</h3><span>{phase(run.phase)}</span></header>
    <pre
      aria-live="polite"
      aria-label="Finding reproduction output"
      className="reproduction-terminal"
      role="log"
      tabIndex={0}
    >{`${output.map((item) => item.text).join('') || 'Waiting for output…\n'}${phase(run.phase)}${run.terminal_reason ? `: ${run.terminal_reason}` : ''}`}</pre>
    {run.terminal_reason && <p>{run.terminal_reason}</p>}
  </section>;
}
