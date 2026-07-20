import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ReproductionTerminal } from './components/findings/ReproductionTerminal';
import { useFindingReproduction } from './controllers/useFindingReproduction';
import type { BigEyeApi } from './services/apiClient';
import type { ProjectEventStream, ReproductionStreamEvent } from './services/eventStream';

const run = {
  run_id: 'a'.repeat(32), phase: 'starting' as const,
  started_at: '2026-07-20T10:00:00Z', completed_at: null,
  image_id: `sha256:${'b'.repeat(64)}`, command: ['/target', '{input}'],
  exit_code: null, terminal_reason: null,
};

describe('finding reproduction', () => {
  it('renders exact streamed output in a read-only log with no input surface', () => {
    render(<ReproductionTerminal run={{ ...run, phase: 'completed', exit_code: 1, terminal_reason: 'exited' }} output={[
      { stream: 'stderr', text: 'AddressSanitizer: heap-buffer-overflow\n' },
    ]} />);

    const terminal = screen.getByRole('log', { name: 'Finding reproduction output' });
    expect(terminal).toHaveTextContent('AddressSanitizer: heap-buffer-overflow');
    expect(terminal).toHaveTextContent('Completed');
    expect(terminal).toHaveAttribute('aria-live', 'polite');
    expect(terminal.querySelector('input, textarea, [contenteditable="true"]')).toBeNull();
  });

  it('starts one run and appends output and terminal lifecycle from SSE', async () => {
    let emit!: (event: ReproductionStreamEvent) => void;
    const events: ProjectEventStream = {
      subscribe: vi.fn().mockReturnValue(() => undefined),
      subscribeReproduction: vi.fn((_url, onEvent) => {
        emit = onEvent;
        return () => undefined;
      }),
    };
    const api = {
      startFindingReproduction: vi.fn().mockResolvedValue(run),
      findingReproductionEventsUrl: vi.fn().mockReturnValue('/events'),
    } as unknown as BigEyeApi;
    const { result } = renderHook(() => useFindingReproduction(api, events, '7', '9'));

    await act(async () => { await result.current.start(); });
    expect(api.startFindingReproduction).toHaveBeenCalledWith('7', '9');
    expect(events.subscribeReproduction).toHaveBeenCalledWith('/events', expect.any(Function), expect.any(Function));

    act(() => emit({ type: 'output', data: { stream: 'stdout', text: 'reproduced\n' } }));
    act(() => emit({ type: 'reproduction', data: { ...run, phase: 'completed', completed_at: '2026-07-20T10:00:01Z', exit_code: 1, terminal_reason: 'exited' } }));
    await waitFor(() => expect(result.current.run?.phase).toBe('completed'));
    expect(result.current.output).toEqual([{ stream: 'stdout', text: 'reproduced\n' }]);
  });

  it('does not capture keyboard input', async () => {
    const user = userEvent.setup();
    render(<ReproductionTerminal run={run} output={[]} />);
    await user.keyboard('kill -9{Enter}');
    expect(screen.queryByDisplayValue(/kill -9/)).not.toBeInTheDocument();
  });
});
