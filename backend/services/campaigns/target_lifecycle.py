"""Conservative application-owned target lifecycle authorisation."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from hashlib import sha256
import inspect
import json

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TargetLifecycleAction(BaseModel):
    """One deterministic lifecycle action; constructing it does not delete an asset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=100)
    project_id: int = Field(ge=1)
    campaign_id: int | None = Field(default=None, ge=1)
    retained_campaign_id: int | None = Field(default=None, ge=1)
    asset_ids: tuple[int, ...] = Field(default=(), max_length=64)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    reproduction_bundle_ids: tuple[str, ...] = Field(default=(), max_length=64)
    reason: str = Field(min_length=1, max_length=1_000)
    reversible: bool

    @model_validator(mode="after")
    def validate_action(self):
        if self.kind not in {"delete-never-functional", "delete-overlapping", "unschedule"}:
            raise ValueError("target lifecycle action kind is invalid")
        if len(self.asset_ids) != len(set(self.asset_ids)) or any(
            type(value) is not int or value <= 0 for value in self.asset_ids
        ):
            raise ValueError("target lifecycle asset identities are invalid")
        if len(self.evidence_ids) != len(set(self.evidence_ids)) or any(
            not isinstance(value, str) or not value.strip() or len(value) > 2_000
            for value in self.evidence_ids
        ):
            raise ValueError("target lifecycle evidence identifiers are invalid")
        if len(self.reproduction_bundle_ids) != len(set(self.reproduction_bundle_ids)) or any(
            not isinstance(value, str) or not value.strip() or len(value) > 200
            for value in self.reproduction_bundle_ids
        ):
            raise ValueError("target lifecycle reproduction bundle identities are invalid")
        if self.kind == "unschedule":
            if self.campaign_id is None or self.asset_ids or self.reversible is not True:
                raise ValueError("target unscheduling must be reversible and preserve assets")
        elif self.reversible is not False or not self.asset_ids:
            raise ValueError("target deletion action is invalid")
        return self


class TargetLifecycleService:
    """Require complete absence or overlap evidence before authorising deletion."""

    def __init__(
        self, *, assets, campaigns, reproduction_bundles=None, coverage_history=None,
    ):
        self._assets = assets
        self._campaigns = campaigns
        self._bundles = reproduction_bundles
        self._coverage_history = coverage_history

    async def never_functional_deletion(
        self, project_id: int, target_asset_id: int,
    ) -> TargetLifecycleAction | None:
        """Return a deletion action only when complete never-functional evidence exists."""
        self._positive(project_id, "project ID")
        self._positive(target_asset_id, "target asset ID")
        provider = getattr(self._assets, "deletion_evidence", None)
        if provider is None:
            return None
        evidence = await self._call(provider, project_id, target_asset_id)
        values = self._mapping(evidence)
        if not (
            values.get("complete") is True
            and values.get("successful_probe") is False
            and values.get("accepted_campaign") is False
            and values.get("useful_clean_coverage") is False
            and tuple(values.get("finding_dependencies", ())) == ()
        ):
            return None
        evidence_ids = self._evidence_ids(values)
        return self._action(
            "delete-never-functional",
            project_id,
            asset_ids=(target_asset_id,),
            evidence_ids=evidence_ids,
            reason="complete deterministic evidence shows that the target never functioned",
            reversible=False,
        )

    async def overlapping_deletion(
        self, project_id: int, campaign_id: int,
    ) -> TargetLifecycleAction | None:
        """Return a deletion action only after two complete comparable checkpoints."""
        self._positive(project_id, "project ID")
        self._positive(campaign_id, "campaign ID")
        provider = getattr(self._campaigns, "overlap_deletion_evidence", None)
        if provider is not None:
            values = self._mapping(await self._call(provider, project_id, campaign_id))
        else:
            values = await self._derived_overlap_evidence(project_id, campaign_id)
        if not (
            values.get("complete") is True
            and values.get("project_id") == project_id
            and values.get("campaign_id") == campaign_id
            and type(values.get("strategy_asset_id")) is int
            and values["strategy_asset_id"] > 0
            and type(values.get("retained_campaign_id")) is int
            and values["retained_campaign_id"] > 0
            and values["retained_campaign_id"] != campaign_id
            and type(values.get("retained_strategy_asset_id")) is int
            and values["retained_strategy_asset_id"] > 0
            and values["retained_strategy_asset_id"] != values["strategy_asset_id"]
            and type(values.get("comparable_clean_checkpoints")) is int
            and values["comparable_clean_checkpoints"] >= 2
            and values.get("fully_subsumed") is True
            and tuple(values.get("unique_crash_groups", ())) == ()
            and values.get("retained_healthy") is True
        ):
            return None
        bundle_ids = await self._freeze_dependencies(
            project_id, tuple(values.get("finding_bundle_requests", ())),
        )
        return self._action(
            "delete-overlapping",
            project_id,
            campaign_id=campaign_id,
            retained_campaign_id=values["retained_campaign_id"],
            asset_ids=(values["strategy_asset_id"],),
            evidence_ids=self._evidence_ids(values),
            reproduction_bundle_ids=bundle_ids,
            reason="clean reach was fully subsumed at two comparable checkpoints",
            reversible=False,
        )

    async def _derived_overlap_evidence(self, project_id: int, campaign_id: int) -> dict:
        """Derive the deletion gate from persisted comparable clean histories."""
        if self._coverage_history is None:
            return {}
        from backend.fuzzing.coverage.overlap import OverlapAnalyzer

        histories = tuple(await self._call(self._coverage_history.histories, project_id))
        candidate = next((
            value for value in OverlapAnalyzer.compare(histories)
            if value.project_id == project_id and value.campaign_id == campaign_id
        ), None)
        if candidate is None:
            return {}
        history = next(value for value in histories if value.campaign_id == campaign_id)
        # A finding-dependent strategy needs exact artifact-to-bundle resolution. Refuse
        # automated deletion when that dependency is not already supplied and frozen.
        if history.crash_group_ids:
            return {}
        selected, retained = await asyncio.gather(
            self._call(self._campaigns.get, candidate.campaign_id),
            self._call(self._campaigns.get, candidate.retained_campaign_id),
        )
        if (
            selected is None
            or retained is None
            or getattr(selected, "project_id", None) != project_id
            or getattr(retained, "project_id", None) != project_id
        ):
            return {}
        return {
            "complete": True,
            "project_id": project_id,
            "campaign_id": campaign_id,
            "strategy_asset_id": candidate.strategy_asset_id,
            "retained_campaign_id": candidate.retained_campaign_id,
            "retained_strategy_asset_id": candidate.retained_strategy_asset_id,
            "comparable_clean_checkpoints": 2,
            "fully_subsumed": True,
            "unique_crash_groups": (),
            "retained_healthy": (
                getattr(retained, "stopped_at", None) is None
                and getattr(retained, "error", None) is None
            ),
            "finding_bundle_requests": (),
            "evidence_ids": candidate.evidence_ids,
        }

    async def unschedule(
        self, project_id: int, campaign_id: int, reason: str,
    ) -> TargetLifecycleAction:
        """Return a reversible unscheduling action for a functional target."""
        self._positive(project_id, "project ID")
        self._positive(campaign_id, "campaign ID")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1_000 or "\x00" in reason:
            raise ValueError("target unscheduling reason is invalid")
        campaign = await self._call(self._campaigns.get, campaign_id)
        if (
            campaign is None
            or getattr(campaign, "project_id", None) != project_id
            or getattr(campaign, "stopped_at", None) is not None
            or getattr(campaign, "error", None) is not None
            or type(getattr(campaign, "target_asset_id", None)) is not int
            or campaign.target_asset_id <= 0
        ):
            raise ValueError("only a healthy active project campaign can be unscheduled")
        evidence_id = f"campaign-health:{project_id}:{campaign_id}:{campaign.target_asset_id}"
        return self._action(
            "unschedule",
            project_id,
            campaign_id=campaign_id,
            evidence_ids=(evidence_id,),
            reason=reason.strip(),
            reversible=True,
        )

    async def _freeze_dependencies(self, project_id: int, requests: tuple) -> tuple[str, ...]:
        if not requests:
            return ()
        if self._bundles is None:
            raise ValueError("finding-dependent deletion requires a reproduction bundle store")
        bundle_ids = []
        for request in requests:
            if getattr(request, "project_id", None) != project_id:
                raise ValueError("reproduction bundle request belongs to another project")
            bundle = await self._call(self._bundles.freeze, request)
            bundle_id = getattr(bundle, "bundle_id", None)
            if getattr(bundle, "verified", None) is not True or not isinstance(bundle_id, str) or not bundle_id:
                raise ValueError("deletion requires a verified reproduction bundle")
            bundle_ids.append(bundle_id)
        if len(bundle_ids) != len(set(bundle_ids)):
            raise ValueError("finding dependencies did not produce unique reproduction bundles")
        return tuple(bundle_ids)

    @classmethod
    def _action(cls, kind: str, project_id: int, **values) -> TargetLifecycleAction:
        identity = {
            "kind": kind,
            "project_id": project_id,
            **{key: value for key, value in values.items() if key != "reason"},
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return TargetLifecycleAction(
            action_id=f"lifecycle:{project_id}:{sha256(encoded).hexdigest()[:32]}",
            kind=kind,
            project_id=project_id,
            **values,
        )

    @staticmethod
    def _mapping(value) -> dict:
        if isinstance(value, Mapping):
            return dict(value)
        if value is None:
            return {}
        fields = (
            "complete", "project_id", "campaign_id", "strategy_asset_id",
            "retained_campaign_id", "retained_strategy_asset_id",
            "comparable_clean_checkpoints", "fully_subsumed", "unique_crash_groups",
            "retained_healthy", "finding_bundle_requests", "successful_probe",
            "accepted_campaign", "useful_clean_coverage", "finding_dependencies",
            "evidence_ids",
        )
        return {name: getattr(value, name) for name in fields if hasattr(value, name)}

    @staticmethod
    def _evidence_ids(values: Mapping) -> tuple[str, ...]:
        evidence_ids = tuple(values.get("evidence_ids", ()))
        if not evidence_ids or len(evidence_ids) != len(set(evidence_ids)) or any(
            not isinstance(value, str) or not value.strip() or len(value) > 2_000
            for value in evidence_ids
        ):
            raise ValueError("lifecycle decision requires complete bounded evidence identities")
        return evidence_ids

    @staticmethod
    def _positive(value: int, label: str) -> None:
        if type(value) is not int or value <= 0:
            raise ValueError(f"{label} must be positive")

    @staticmethod
    async def _call(method, *arguments):
        value = method(*arguments)
        return await value if inspect.isawaitable(value) else value
