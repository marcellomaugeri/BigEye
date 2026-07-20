export function ManagerActivityFooter({
  message,
  onOpenActivity,
}: {
  message: string | null;
  onOpenActivity: () => void;
}) {
  if (message === null) return null;
  return <footer aria-label="Current manager activity" className="manager-activity-footer">
    <button
      aria-label={`Open Activity: ${message}`}
      onClick={onOpenActivity}
      title={message}
      type="button"
    >
      <span aria-live="polite">{message}</span>
    </button>
  </footer>;
}
