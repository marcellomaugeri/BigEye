export function StatusMessage({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'neutral' | 'error' }) {
  return <p className={`status-message ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>{children}</p>;
}
