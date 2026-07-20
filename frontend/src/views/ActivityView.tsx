import { useEffect } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import { ActivityList } from '../components/activity/ActivityList';
import { DebugLog } from '../components/activity/DebugLog';
import { Button } from '../components/design-system/Button';
import { EmptyState } from '../components/design-system/EmptyState';
import { StatusText } from '../components/design-system/StatusText';
import type { ActivityModel } from '../controllers/useActivity';
import type { ActivityTab } from '../models/event';

export function ActivityView({ model }: { model: ActivityModel }) {
  useEffect(() => {
    const focused = document.querySelector<HTMLElement>('[data-evidence-focus="true"]');
    focused?.focus({ preventScroll: true });
    focused?.scrollIntoView?.({ block: 'nearest' });
  }, [model.activeTab, model.activityEvents, model.debugEvents, model.focusedEvidenceId]);
  if (model.project === null) {
    return <EmptyState title="Activity">Select or create a project to review campaign activity.</EmptyState>;
  }
  return <section aria-labelledby="activity-heading" className="activity-view">
    <header className="view-title"><div><p className="eyebrow">Campaign evidence</p><h2 id="activity-heading">Activity</h2></div></header>
    {model.liveError && <StatusText tone="error">{model.liveError}</StatusText>}
    {model.loading && <StatusText>Loading project activity…</StatusText>}
    <Tabs.Root onValueChange={(value) => model.onTabChange(value as ActivityTab)} value={model.activeTab}>
      <Tabs.List aria-label="Project activity views" className="activity-tabs">
        <Tabs.Trigger value="activity">Activity</Tabs.Trigger>
        <Tabs.Trigger value="debug">Debug</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content className="activity-panel" value="activity">
        {model.activityError && <StatusText tone="error">{model.activityError}</StatusText>}
        {(model.activityError === null || model.activityEvents.length > 0) && <ActivityList events={model.activityEvents} focusedEvidenceId={model.focusedEvidenceId} />}
        {model.activityHasMore && <Button disabled={model.loading} onClick={model.onLoadMoreActivity} variant="secondary">Load older activity</Button>}
      </Tabs.Content>
      <Tabs.Content className="activity-panel" value="debug">
        {model.debugError && <StatusText tone="error">{model.debugError}</StatusText>}
        {(model.debugError === null || model.debugEvents.length > 0) && <DebugLog events={model.debugEvents} filter={model.debugFilter} focusedEvidenceId={model.focusedEvidenceId} onFilter={model.onDebugFilter} />}
        {model.debugHasMore && <Button disabled={model.loading} onClick={model.onLoadMoreDebug} variant="secondary">Load older debug records</Button>}
      </Tabs.Content>
    </Tabs.Root>
  </section>;
}
