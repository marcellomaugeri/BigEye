import { useEffect, useState } from 'react';

export const FIRST_VISIT_INTRO_KEY = 'bigeye.intro.seen.v1';
export const FIRST_VISIT_INTRO_MILLISECONDS = 5_000;

function introWasSeen(): boolean {
  try {
    return window.localStorage.getItem(FIRST_VISIT_INTRO_KEY) === '1';
  } catch {
    return false;
  }
}

function rememberIntro(): void {
  try {
    window.localStorage.setItem(FIRST_VISIT_INTRO_KEY, '1');
  } catch {
    // Storage availability must never prevent the host application from opening.
  }
}

export function useFirstVisitIntro(): boolean {
  const [visible, setVisible] = useState(() => !introWasSeen());

  useEffect(() => {
    if (!visible) return;
    const timer = window.setTimeout(() => {
      rememberIntro();
      setVisible(false);
    }, FIRST_VISIT_INTRO_MILLISECONDS);
    return () => window.clearTimeout(timer);
  }, [visible]);

  return visible;
}
