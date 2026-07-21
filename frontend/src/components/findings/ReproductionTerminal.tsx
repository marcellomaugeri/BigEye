import type { ReproductionOutput, ReproductionRun } from '../../models/reproduction';

function phase(value: ReproductionRun['phase']): string {
  return value === 'timed_out' ? 'Timed out' : value[0].toUpperCase() + value.slice(1);
}

function status(run: ReproductionRun): string {
  return run.sanitizer_crash_observed ? 'Reproduced' : phase(run.phase);
}

export function ReproductionTerminal({ run, output }: {
  run: ReproductionRun | null;
  output: ReproductionOutput[];
}) {
  if (run === null) return null;
  const exit = run.exit_code === null ? '' : ` (exit ${run.exit_code})`;
  const invocation = `Running: ${run.command.join(' ')}\n`;
  return <section aria-label="Finding reproduction" className="reproduction">
    <header><h3>Reproduction</h3><span>{status(run)}</span></header>
    <pre
      aria-live="polite"
      aria-label="Finding reproduction output"
      className="reproduction-terminal"
      role="log"
      tabIndex={0}
    >{`${invocation}${output.map((item) => item.text).join('') || 'Waiting for output…\n'}${status(run)}${run.terminal_reason ? `: ${run.terminal_reason}` : ''}${exit}`}</pre>
    {run.terminal_reason && <p>{run.terminal_reason}</p>}
  </section>;
}
