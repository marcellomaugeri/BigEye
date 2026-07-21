export function FirstVisitIntro({ visible }: { visible: boolean }) {
  if (!visible) return null;
  return <section
    aria-atomic="true"
    aria-label="BigEye is starting"
    aria-live="polite"
    className="first-visit-intro"
    role="status"
  >
    <div className="first-visit-intro-content">
      <div className="first-visit-logo">
        <img alt="BigEye" src="/assets/logo.png" />
      </div>
      <div aria-label="Loading BigEye" className="first-visit-progress" role="progressbar">
        <span />
      </div>
    </div>
  </section>;
}
