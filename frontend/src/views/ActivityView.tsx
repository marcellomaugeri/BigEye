import * as Tabs from '@radix-ui/react-tabs';
import { ActivityList } from '../components/activity/ActivityList';
import { DebugLog } from '../components/activity/DebugLog';
import { Button } from '../components/design-system/Button';
import { EmptyState } from '../components/design-system/EmptyState';
import { StatusText } from '../components/design-system/StatusText';
import type { ActivityModel } from '../controllers/useActivity';
import type { ActivityTab } from '../models/event';

export function ActivityView({ model }: { model: ActivityModel }) {
  if (model.project === null) {
    return <EmptyState title="Activity">Select or create a project to review campaign activity.</EmptyState>;
  }
  return <section aria-labelledby="activity-heading" className="activity-view">
    <header className="view-title"><div><p className="eyebrow">Campaign evidence</p><h2 id="activity-heading">Activity</h2></div></header>
    {model.error && <StatusText tone="error">{model.error}</StatusText>}
    {model.loading && <StatusText>Loading project activity…</StatusText>}
    {(model.error === null || model.activityEvents.length > 0 || model.debugEvents.length > 0) && <Tabs.Root onValueChange={(value) => model.onTabChange(value as ActivityTab)} value={model.activeTab}>
      <Tabs.List aria-label="Project activity views" className="activity-tabs">
        <Tabs.Trigger value="activity">Activity</Tabs.Trigger>
        <Tabs.Trigger value="debug">Debug</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content className="activity-panel" value="activity">
        <ActivityList events={model.activityEvents} />
        {model.activityHasMore && <Button disabled={model.loading} onClick={model.onLoadMoreActivity} variant="secondary">Load older activity</Button>}
      </Tabs.Content>
      <Tabs.Content className="activity-panel" value="debug">
        <DebugLog events={model.debugEvents} filter={model.debugFilter} onFilter={model.onDebugFilter} />
        {model.debugHasMore && <Button disabled={model.loading} onClick={model.onLoadMoreDebug} variant="secondary">Load older debug records</Button>}
      </Tabs.Content>
    </Tabs.Root>}
  </section>;
}
