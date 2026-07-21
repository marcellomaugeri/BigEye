"""Read bounded, persisted campaign evidence for the local user interface."""

import asyncio
from dataclasses import dataclass


@dataclass(frozen=True)
class CampaignReadResult:
    campaigns: tuple
    assets: tuple
    summaries: dict[int, dict[str, str | int | None]]


class CampaignReadService:
    """Combine campaign context and clean checkpoints into bounded read evidence."""

    def __init__(self, campaigns, coverage_checkpoints):
        self._campaigns = campaigns
        self._coverage_checkpoints = coverage_checkpoints

    async def read(self, project_id: int) -> CampaignReadResult:
        (campaigns, assets), contexts, histories = await asyncio.gather(
            self._campaigns.list_with_assets_for_project(project_id),
            self._campaigns.list_contexts_for_project(project_id),
            self._coverage_checkpoints.histories(project_id),
        )
        histories_by_campaign = {history.campaign_id: history for history in histories}
        summaries = {
            campaign.id: self._summary(
                contexts.get(campaign.id), histories_by_campaign.get(campaign.id), histories,
            )
            for campaign in campaigns
        }
        return CampaignReadResult(tuple(campaigns), tuple(assets), summaries)

    @staticmethod
    def _summary(context, history, histories):
        context = context or {"configuration_purpose": None, "retirement_reason": None}
        summary = {
            "configuration_purpose": context.get("configuration_purpose"),
            "retirement_reason": context.get("retirement_reason"),
            "reached_line_count": None,
            "unique_line_count": None,
            "overlapping_line_count": None,
            "recent_line_gain": None,
            "total_reached_lines": None,
        }
        if history is None or not history.checkpoints:
            return summary
        reached = history.checkpoints[-1].reached_lines
        comparable_reach = set()
        for other in histories:
            if (
                other.campaign_id != history.campaign_id
                and other.commit_sha == history.commit_sha
                and other.compatibility_group_id == history.compatibility_group_id
                and other.configuration_purpose == history.configuration_purpose
                and other.checkpoints
            ):
                comparable_reach.update(other.checkpoints[-1].reached_lines)
        overlapping = reached & comparable_reach
        summary.update({
            "reached_line_count": len(reached),
            "unique_line_count": len(reached - comparable_reach),
            "overlapping_line_count": len(overlapping),
            "recent_line_gain": len(history.checkpoints[-1].recent_marginal_lines),
            "total_reached_lines": len(reached),
        })
        return summary
