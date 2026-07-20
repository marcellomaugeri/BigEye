import { act, render, renderHook, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FirstVisitIntro } from './components/FirstVisitIntro';
import {
  FIRST_VISIT_INTRO_KEY,
  FIRST_VISIT_INTRO_MILLISECONDS,
  useFirstVisitIntro,
} from './controllers/useFirstVisitIntro';

describe('first-visit introduction', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    window.localStorage.removeItem(FIRST_VISIT_INTRO_KEY);
  });

  afterEach(() => {
    vi.useRealTimers();
    window.localStorage.setItem(FIRST_VISIT_INTRO_KEY, '1');
  });

  it('remains visible for exactly five seconds and then records completion', () => {
    const { result } = renderHook(() => useFirstVisitIntro());

    expect(result.current).toBe(true);
    act(() => vi.advanceTimersByTime(FIRST_VISIT_INTRO_MILLISECONDS - 1));
    expect(result.current).toBe(true);
    expect(window.localStorage.getItem(FIRST_VISIT_INTRO_KEY)).toBeNull();

    act(() => vi.advanceTimersByTime(1));
    expect(result.current).toBe(false);
    expect(window.localStorage.getItem(FIRST_VISIT_INTRO_KEY)).toBe('1');
  });

  it('does not show again after the completed first visit', () => {
    window.localStorage.setItem(FIRST_VISIT_INTRO_KEY, '1');
    const timers = vi.spyOn(window, 'setTimeout');

    const { result } = renderHook(() => useFirstVisitIntro());

    expect(result.current).toBe(false);
    expect(timers.mock.calls.some(([, delay]) => delay === FIRST_VISIT_INTRO_MILLISECONDS)).toBe(false);
    timers.mockRestore();
  });

  it('still opens the application after five seconds when storage writes fail', () => {
    const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('storage unavailable');
    });
    const { result } = renderHook(() => useFirstVisitIntro());

    act(() => vi.advanceTimersByTime(FIRST_VISIT_INTRO_MILLISECONDS));

    expect(result.current).toBe(false);
    write.mockRestore();
  });

  it('renders only the logo slot and one accessible loader', () => {
    render(<FirstVisitIntro visible />);

    const intro = screen.getByRole('status', { name: 'BigEye is starting' });
    expect(intro).toHaveTextContent('BigEye');
    expect(screen.getByLabelText('BigEye logo placeholder')).toBeVisible();
    expect(screen.getByRole('progressbar', { name: 'Loading BigEye' })).toBeVisible();
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
  });

  it('renders nothing after the introduction completes', () => {
    const { container } = render(<FirstVisitIntro visible={false} />);

    expect(container).toBeEmptyDOMElement();
  });
});
