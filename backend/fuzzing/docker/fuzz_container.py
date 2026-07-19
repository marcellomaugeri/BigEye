"""Own persistent fuzz containers using service-derived runtime evidence."""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from backend.fuzzing.docker.bounded_logs import persist_bounded_logs
from backend.fuzzing.docker.campaign_workspace import CampaignDirectory, CampaignWorkspace
from backend.fuzzing.docker.fuzz_contract import (
    CAMPAIGN_LABEL,
    MANAGED_LABEL,
    TMPFS,
    ContainerContractMismatch,
    RuntimeContract,
    build_runtime_contract,
    verify_runtime,
)
from backend.fuzzing.docker.image_builder import PLATFORM
from backend.fuzzing.engines.contracts import ContainerInvocation


ACTIVE_STATES = frozenset({"created", "running", "restarting", "paused"})


class ContainerOwnershipMismatch(RuntimeError):
    """Raised before an identity without service-owned evidence can control Docker."""


class ContainerStillRunning(RuntimeError):
    """Raised when bounded graceful and forced stops do not stop a container."""


@dataclass(frozen=True)
class FuzzCampaign:
    id: int
    project_id: int
    commit_sha: str


@dataclass(frozen=True)
class ContainerIdentity:
    container_id: str
    campaign_id: int
    project_id: int
    state: str


class FuzzContainerService:
    """Create, adopt, inspect, stream, and stop exact campaign containers."""

    def __init__(
        self,
        client,
        workspace_root: Path,
        stop_timeout_seconds: int = 10,
        final_log_max_bytes: int = 1_048_576,
        final_log_timeout_seconds: float = 2.0,
    ):
        if isinstance(stop_timeout_seconds, bool) or not 1 <= stop_timeout_seconds <= 30:
            raise ValueError("stop_timeout_seconds must be between 1 and 30")
        if isinstance(final_log_max_bytes, bool) or not 1 <= final_log_max_bytes <= 16 * 1_048_576:
            raise ValueError("final_log_max_bytes must be between 1 and 16777216")
        if isinstance(final_log_timeout_seconds, bool) or not 0 < final_log_timeout_seconds <= 10:
            raise ValueError("final_log_timeout_seconds must be between 0 and 10")
        self._client = client
        self._workspace = CampaignWorkspace(workspace_root)
        self._stop_timeout_seconds = stop_timeout_seconds
        self._final_log_max_bytes = final_log_max_bytes
        self._final_log_timeout_seconds = final_log_timeout_seconds
        self._owned: dict[str, RuntimeContract] = {}

    def start(self, campaign: FuzzCampaign, invocation: ContainerInvocation) -> ContainerIdentity:
        self._validate_campaign(campaign)
        existing = self.inspect(campaign, invocation)
        if existing is not None:
            if existing.state == "running":
                return existing
            raise ContainerOwnershipMismatch(
                f"campaign {campaign.id} already has a managed container in state {existing.state}"
            )
        with self._workspace.open_campaign(campaign.project_id, campaign.id, create=True) as directory:
            self._after_campaign_opened(directory.descriptor, directory.path)
            self._require_canonical(campaign, directory)
            volumes = self._workspace.prepare_mounts(directory, root_fallback=os.getuid() == 0)
            self._require_canonical(campaign, directory)
            user_id, group_id = _unprivileged_user()
            contract = build_runtime_contract(
                self._client,
                campaign,
                invocation,
                volumes,
                f"{user_id}:{group_id}",
                (directory.device, directory.inode),
                directory.path,
            )
            container = self._client.containers.create(
                invocation.image_id,
                list(invocation.command),
                name=f"bigeye-campaign-{campaign.id}",
                platform=PLATFORM,
                network_disabled=True,
                network_mode="none",
                privileged=False,
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                user=contract.user,
                pids_limit=256,
                mem_limit=f"{invocation.memory_limit_mb}m",
                nano_cpus=1_000_000_000,
                tmpfs=dict(TMPFS),
                volumes=volumes,
                environment=dict(invocation.environment),
                labels=_service_labels(contract),
                auto_remove=False,
                detach=True,
            )
            try:
                self._require_canonical(campaign, directory)
                container.start()
                container.reload()
                verify_runtime(container, contract)
                if _container_state(container) != "running":
                    raise ContainerContractMismatch("started fuzz container is not running")
                self._require_canonical(campaign, directory)
            except BaseException as error:
                try:
                    self._cleanup_created(container, campaign, directory)
                except BaseException as cleanup_error:
                    error.add_note(f"start-failure cleanup also failed: {cleanup_error}")
                raise
            return self._register(container, contract, "running")

    def inspect(self, campaign: FuzzCampaign, invocation: ContainerInvocation) -> ContainerIdentity | None:
        return self._find(campaign, invocation, running_only=False)

    def recover(self, campaign: FuzzCampaign, invocation: ContainerInvocation) -> ContainerIdentity | None:
        return self._find(campaign, invocation, running_only=True)

    def stream_logs(self, identity: ContainerIdentity, sink, follow: bool = True) -> None:
        contract = self._known_contract(identity)
        with self._open_owned_campaign(contract) as directory:
            container = self._owned_container(identity, contract)
            for chunk in container.logs(stream=True, follow=follow, stdout=True, stderr=True):
                sink(_text(chunk))

    def log_path(self, identity: ContainerIdentity) -> Path:
        contract = self._known_contract(identity)
        with self._open_owned_campaign(contract):
            return Path(contract.campaign_path) / "logs" / "container.log"

    def stop(self, identity: ContainerIdentity) -> None:
        contract = self._known_contract(identity)
        with self._open_owned_campaign(contract) as directory:
            self._workspace.validate_log_destination(directory)
            container = self._owned_container(identity, contract)
            state = _container_state(container)
            if state in ACTIVE_STATES:
                container.stop(timeout=self._stop_timeout_seconds)
                container.reload()
                state = _container_state(container)
                if state in ACTIVE_STATES:
                    container.kill()
                    container.reload()
                    state = _container_state(container)
            if state in ACTIVE_STATES:
                raise ContainerStillRunning(f"container {identity.container_id} did not stop")
            log_descriptor = self._workspace.open_log(directory)
            try:
                persist_bounded_logs(
                    container,
                    log_descriptor,
                    self._final_log_max_bytes,
                    self._final_log_timeout_seconds,
                )
            finally:
                os.close(log_descriptor)
            self._require_contract_canonical(contract)
            container.remove(force=False)
            del self._owned[identity.container_id]

    def _find(self, campaign: FuzzCampaign, invocation: ContainerInvocation, running_only: bool) -> ContainerIdentity | None:
        self._validate_campaign(campaign)
        filters = {"label": [f"{MANAGED_LABEL}=fuzz-campaign", f"{CAMPAIGN_LABEL}={campaign.id}"]}
        candidates = self._client.containers.list(all=True, filters=filters)
        if not candidates:
            return None
        with self._workspace.open_campaign(campaign.project_id, campaign.id, create=False) as directory:
            volumes = self._workspace.existing_mounts(directory)
            self._workspace.prepare_logs(directory)
            user_id, group_id = _unprivileged_user()
            contract = build_runtime_contract(
                self._client,
                campaign,
                invocation,
                volumes,
                f"{user_id}:{group_id}",
                (directory.device, directory.inode),
                directory.path,
            )
            self._require_canonical(campaign, directory)
            matches = []
            for container in candidates:
                container.reload()
                verify_runtime(container, contract)
                state = _container_state(container)
                if not running_only or state == "running":
                    matches.append((container, state))
            if len(matches) > 1:
                raise ContainerOwnershipMismatch(f"campaign {campaign.id} has multiple managed containers")
            if not matches:
                return None
            container, state = matches[0]
            return self._register(container, contract, state)

    def _register(self, container, contract: RuntimeContract, state: str) -> ContainerIdentity:
        self._owned[str(container.id)] = contract
        return ContainerIdentity(str(container.id), contract.campaign_id, contract.project_id, state)

    def _known_contract(self, identity: ContainerIdentity) -> RuntimeContract:
        contract = self._owned.get(identity.container_id)
        if contract is None:
            raise ContainerOwnershipMismatch(f"container identity {identity.container_id} is unknown to this service")
        if identity.campaign_id != contract.campaign_id or identity.project_id != contract.project_id:
            raise ContainerOwnershipMismatch("container identity does not match service-owned campaign evidence")
        return contract

    def _owned_container(self, identity: ContainerIdentity, contract: RuntimeContract):
        container = self._client.containers.get(identity.container_id)
        container.reload()
        verify_runtime(container, contract)
        return container

    @contextmanager
    def _open_owned_campaign(self, contract: RuntimeContract):
        with self._workspace.open_campaign(contract.project_id, contract.campaign_id, create=False) as directory:
            if (directory.device, directory.inode) != (contract.device, contract.inode):
                raise ValueError("canonical campaign workspace changed after ownership was established")
            yield directory

    def _cleanup_created(self, container, campaign: FuzzCampaign, directory: CampaignDirectory) -> None:
        try:
            container.reload()
        except Exception:
            pass
        state = _container_state(container)
        if state == "created":
            container.remove(force=False)
            return
        if state in ACTIVE_STATES:
            try:
                container.stop(timeout=self._stop_timeout_seconds)
            except Exception:
                try:
                    container.kill()
                except Exception:
                    pass
            try:
                container.reload()
            except Exception:
                pass
            state = _container_state(container)
        if state in ACTIVE_STATES:
            raise ContainerStillRunning(f"failed start left container {container.id} running")
        if self._workspace.is_canonical(campaign.project_id, campaign.id, (directory.device, directory.inode)):
            log_descriptor = self._workspace.open_log(directory)
            try:
                persist_bounded_logs(container, log_descriptor, self._final_log_max_bytes, self._final_log_timeout_seconds)
            finally:
                os.close(log_descriptor)
        container.remove(force=False)

    def _require_canonical(self, campaign: FuzzCampaign, directory: CampaignDirectory) -> None:
        if not self._workspace.is_canonical(campaign.project_id, campaign.id, (directory.device, directory.inode)):
            raise ValueError("canonical campaign workspace changed while its descriptor was held")

    def _require_contract_canonical(self, contract: RuntimeContract) -> None:
        if not self._workspace.is_canonical(contract.project_id, contract.campaign_id, (contract.device, contract.inode)):
            raise ValueError("canonical campaign workspace changed during log persistence")

    @staticmethod
    def _validate_campaign(campaign: FuzzCampaign) -> None:
        if isinstance(campaign.id, bool) or not isinstance(campaign.id, int) or campaign.id <= 0:
            raise ValueError("campaign id must be positive")
        if isinstance(campaign.project_id, bool) or not isinstance(campaign.project_id, int) or campaign.project_id <= 0:
            raise ValueError("project id must be positive")
        if len(campaign.commit_sha) not in {40, 64} or any(character not in "0123456789abcdef" for character in campaign.commit_sha):
            raise ValueError("commit_sha must be a lowercase hexadecimal object ID")

    @staticmethod
    def _after_campaign_opened(_descriptor: int, _campaign_path: Path) -> None:
        """Test seam for proving path swaps cannot redirect descriptor-owned work."""


def _service_labels(contract: RuntimeContract) -> dict[str, str]:
    return dict(contract.requested_labels)


def _container_state(container) -> str:
    return str(container.attrs.get("State", {}).get("Status") or getattr(container, "status", "unknown"))


def _text(chunk) -> str:
    return chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk)


def _unprivileged_user() -> tuple[int, int]:
    user_id, group_id = os.getuid(), os.getgid()
    return (65534, 65534) if user_id == 0 else (user_id, group_id)
