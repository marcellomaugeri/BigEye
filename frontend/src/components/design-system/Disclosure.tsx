import { useId } from 'react';
import { Button } from './Button';

export function Disclosure({ children, label, open, onToggle }: { children: React.ReactNode; label: string; open: boolean; onToggle: () => void }) {
  const contentId = useId();
  return <div className="disclosure">
    <Button aria-controls={contentId} aria-expanded={open} onClick={onToggle} type="button" variant="secondary">{label}</Button>
    {open && <div id={contentId}>{children}</div>}
  </div>;
}
