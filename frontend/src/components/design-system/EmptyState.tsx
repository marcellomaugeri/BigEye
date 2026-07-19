export function EmptyState({ title, children }: { title: string; children: React.ReactNode }) {
  return <section aria-labelledby={`${title.toLowerCase().replaceAll(' ', '-')}-heading`} className="empty-state">
    <h2 id={`${title.toLowerCase().replaceAll(' ', '-')}-heading`}>{title}</h2>
    <p>{children}</p>
  </section>;
}
