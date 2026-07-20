"""Deterministic restart reconciliation for exact campaign identities."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

from backend.fuzzing.docker.campaign_workspace import CampaignWorkspace


_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_CAMPAIGNS = 256
_MAX_CONTAINERS = 512
_MAX_ASSETS = 64
_MAX_EVIDENCE_IDS = 256
_MAX_CORPUS_ENTRIES = 20_000
_MANAGED_CAMPAIGN = "fuzz-campaign"


@dataclass(frozen=True, order=True)
class RecoveryAssetIdentity:
    asset_id: int
    content_hash: str

    def __post_init__(self) -> None:
        if (
            type(self.asset_id) is not int
            or self.asset_id <= 0
            or not isinstance(self.content_hash, str)
            or _SHA256.fullmatch(self.content_hash) is None
        ):
            raise ValueError("recovery asset identity is invalid")


@dataclass(frozen=True)
class RecoverableCampaign:
    project_id: int
    campaign_id: int
    commit_sha: str
    image_id: str
    asset_identities: tuple[RecoveryAssetIdentity, ...]
    healthy: bool
    pending_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _positive(self.project_id, "project ID")
        _positive(self.campaign_id, "campaign ID")
        _commit(self.commit_sha)
        _image(self.image_id)
        object.__setattr__(self, "asset_identities", _assets(self.asset_identities))
        if not isinstance(self.healthy, bool):
            raise ValueError("campaign health must be boolean")
        object.__setattr__(
            self, "pending_evidence_ids", _evidence_ids(self.pending_evidence_ids),
        )


@dataclass(frozen=True)
class RecoveryContainer:
    container_id: str
    managed_as: str
    project_id: int
    campaign_id: int
    commit_sha: str
    image_id: str
    asset_identities: tuple[RecoveryAssetIdentity, ...]
    platform: str
    state: str

    def __post_init__(self) -> None:
        if not _bounded(self.container_id, 256) or not _bounded(self.managed_as, 64):
            raise ValueError("recovery container identity is invalid")
        _positive(self.project_id, "project ID")
        _positive(self.campaign_id, "campaign ID")
        _commit(self.commit_sha)
        _image(self.image_id)
        object.__setattr__(self, "asset_identities", _assets(self.asset_identities))
        if self.platform not in {"linux/amd64", "linux/arm64"}:
            raise ValueError("recovery container platform is invalid")
        if self.state not in {"created", "running", "restarting", "paused", "exited", "dead"}:
            raise ValueError("recovery container state is invalid")


@dataclass(frozen=True)
class RecoveryRecord:
    project_id: int
    campaign_id: int
    action: str
    container_id: str | None
    reason: str
    pending_evidence_ids: tuple[str, ...]


class CampaignRecovery:
    """Adopt, restart, or quarantine without invoking an agent."""

    def __init__(self, workspace_root: Path, control):
        self._workspace = CampaignWorkspace(Path(workspace_root))
        self._control = control

    def recover(self, project_id: int, campaigns, containers) -> tuple[RecoveryRecord, ...]:
        _positive(project_id, "project ID")
        campaigns = _bounded_collection(campaigns, _MAX_CAMPAIGNS, RecoverableCampaign, "campaigns")
        containers = _bounded_collection(containers, _MAX_CONTAINERS, RecoveryContainer, "containers")
        if any(campaign.project_id != project_id for campaign in campaigns):
            raise ValueError("recoverable campaign belongs to another project")
        if len({campaign.campaign_id for campaign in campaigns}) != len(campaigns):
            raise ValueError("recoverable campaign IDs must be unique")
        if len({container.container_id for container in containers}) != len(containers):
            raise ValueError("recovery container IDs must be unique")

        records: list[RecoveryRecord] = []
        for campaign in sorted(campaigns, key=lambda item: item.campaign_id):
            same_campaign = [
                container for container in containers
                if container.project_id == project_id
                and container.campaign_id == campaign.campaign_id
                and container.managed_as == _MANAGED_CAMPAIGN
            ]
            exact = []
            for container in same_campaign:
                if self._matches(campaign, container):
                    exact.append(container)
                    continue
                reason = "container identity does not match durable campaign evidence"
                self._control.quarantine(campaign, container, reason)
                records.append(self._record(campaign, "quarantined", container.container_id, reason))

            if len(exact) > 1:
                reason = "multiple exact containers cannot be adopted safely"
                for container in exact:
                    self._control.quarantine(campaign, container, reason)
                    records.append(self._record(campaign, "quarantined", container.container_id, reason))
                records.append(self._record(campaign, "retained", None, reason))
                continue

            container = exact[0] if exact else None
            if container is not None and container.state == "running":
                self._control.adopt(campaign, container)
                records.append(self._record(
                    campaign, "adopted", container.container_id,
                    "exact running campaign container adopted",
                ))
                continue
            if (
                campaign.healthy
                and (container is None or container.state in {"created", "exited", "dead"})
                and self._has_durable_corpus(campaign)
            ):
                self._control.restart(campaign, container)
                records.append(self._record(
                    campaign, "restarted", None if container is None else container.container_id,
                    "healthy campaign restarted from its durable corpus",
                ))
                continue
            records.append(self._record(
                campaign, "retained", None if container is None else container.container_id,
                "campaign retained without an unsafe adoption or restart",
            ))
        return tuple(records)

    @staticmethod
    def _matches(campaign: RecoverableCampaign, container: RecoveryContainer) -> bool:
        return (
            container.managed_as == _MANAGED_CAMPAIGN
            and container.project_id == campaign.project_id
            and container.campaign_id == campaign.campaign_id
            and container.commit_sha == campaign.commit_sha
            and container.image_id == campaign.image_id
            and container.asset_identities == campaign.asset_identities
            and container.platform == "linux/amd64"
        )

    def _has_durable_corpus(self, campaign: RecoverableCampaign) -> bool:
        try:
            with self._workspace.open_campaign(
                campaign.project_id, campaign.campaign_id, create=False,
            ) as directory:
                self._workspace.existing_mounts(directory)
                descriptor = os.open(
                    "corpus", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory.descriptor,
                )
                try:
                    found = False
                    with os.scandir(descriptor) as entries:
                        for index, entry in enumerate(entries, start=1):
                            if index > _MAX_CORPUS_ENTRIES:
                                return False
                            current = entry.stat(follow_symlinks=False)
                            if not stat.S_ISREG(current.st_mode):
                                return False
                            found = True
                    return found
                finally:
                    os.close(descriptor)
        except (FileNotFoundError, NotADirectoryError, OSError, ValueError):
            return False

    @staticmethod
    def _record(
        campaign: RecoverableCampaign, action: str, container_id: str | None, reason: str,
    ) -> RecoveryRecord:
        return RecoveryRecord(
            project_id=campaign.project_id,
            campaign_id=campaign.campaign_id,
            action=action,
            container_id=container_id,
            reason=reason,
            pending_evidence_ids=campaign.pending_evidence_ids,
        )


def _assets(values) -> tuple[RecoveryAssetIdentity, ...]:
    if (
        not isinstance(values, tuple)
        or not 1 <= len(values) <= _MAX_ASSETS
        or any(not isinstance(value, RecoveryAssetIdentity) for value in values)
    ):
        raise ValueError("recovery asset identities are invalid or exceed their bound")
    ordered = tuple(sorted(values))
    if len({value.asset_id for value in ordered}) != len(ordered):
        raise ValueError("recovery asset IDs must be unique")
    return ordered


def _evidence_ids(values) -> tuple[str, ...]:
    if (
        not isinstance(values, tuple)
        or len(values) > _MAX_EVIDENCE_IDS
        or len(set(values)) != len(values)
        or any(not _bounded(value, 256) for value in values)
    ):
        raise ValueError("pending recovery evidence is invalid or exceeds its bound")
    return values


def _bounded_collection(values, maximum: int, item_type, name: str) -> tuple:
    if not isinstance(values, (tuple, list)) or len(values) > maximum:
        raise ValueError(f"recovery {name} are invalid or exceed their bound")
    result = tuple(values)
    if any(not isinstance(value, item_type) for value in result):
        raise ValueError(f"recovery {name} are invalid or exceed their bound")
    return result


def _positive(value, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"recovery {name} must be positive")


def _commit(value) -> None:
    if not isinstance(value, str) or _OBJECT_ID.fullmatch(value) is None:
        raise ValueError("recovery commit must be a lowercase hexadecimal object ID")


def _image(value) -> None:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise ValueError("recovery image must be an immutable SHA-256 ID")


def _bounded(value, limit: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit and "\x00" not in value
