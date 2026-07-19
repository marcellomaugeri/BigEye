export function StatusText({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'neutral' | 'error' }) {
  return <p className={`status-text ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>{children}</p>;
}
