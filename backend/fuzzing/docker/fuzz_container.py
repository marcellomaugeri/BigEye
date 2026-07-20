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
    PROJECT_LABEL,
    TMPFS,
    ContainerContractMismatch,
    RuntimeContract,
    build_runtime_contract,
    verify_runtime,
)
from backend.fuzzing.docker.image_builder import PLATFORM
from backend.fuzzing.engines.contracts import ContainerInvocation


ACTIVE_STATES = frozenset({"created", "running", "restarting", "paused"})
_OBSERVABLE_STATES = ACTIVE_STATES | frozenset({"exited", "dead"})
_MAX_RECOVERY_CANDIDATES = 64


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


@dataclass(frozen=True)
class ContainerCandidateObservation:
    """One bounded, label-owned recovery candidate without implicit adoption."""

    container_id: str
    campaign_id: int
    project_id: int
    state: str
    runtime_contract_matches: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.container_id, str)
            or not self.container_id
            or len(self.container_id) > 256
            or "\x00" in self.container_id
            or type(self.campaign_id) is not int
            or self.campaign_id <= 0
            or type(self.project_id) is not int
            or self.project_id <= 0
            or self.state not in _OBSERVABLE_STATES
            or not isinstance(self.runtime_contract_matches, bool)
        ):
            raise ValueError("container candidate observation is invalid")


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
        if type(stop_timeout_seconds) is not int or not 1 <= stop_timeout_seconds <= 30:
            raise ValueError("stop_timeout_seconds must be between 1 and 30")
        if type(final_log_max_bytes) is not int or not 1 <= final_log_max_bytes <= 16 * 1_048_576:
            raise ValueError("final_log_max_bytes must be between 1 and 16777216")
        if type(final_log_timeout_seconds) is not float or not 0 < final_log_timeout_seconds <= 10:
            raise ValueError("final_log_timeout_seconds must be between 0 and 10")
        self._client = client
        self._workspace = CampaignWorkspace(workspace_root)
        self._stop_timeout_seconds = stop_timeout_seconds
        self._final_log_max_bytes = final_log_max_bytes
        self._final_log_timeout_seconds = final_log_timeout_seconds
        self._owned: dict[str, RuntimeContract] = {}
        self._observed: dict[str, tuple[ContainerCandidateObservation, RuntimeContract]] = {}

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
            mounts = self._workspace.prepare_mounts(directory, root_fallback=os.getuid() == 0)
            self._require_canonical(campaign, directory)
            user_id, group_id = _unprivileged_user()
            contract = build_runtime_contract(
                self._client,
                campaign,
                invocation,
                mounts.volumes,
                mounts.identities,
                f"{user_id}:{group_id}",
                (directory.device, directory.inode),
                directory.path,
            )
            self._require_runtime_paths(campaign, directory, contract)
            container = self._client.containers.create(
                invocation.image_id,
                list(invocation.command),
                name=f"bigeye-campaign-{campaign.id}",
                platform=PLATFORM,
                network_disabled=True,
                network_mode="none",
                ipc_mode="private",
                cgroupns="private",
                runtime="runc",
                restart_policy={"Name": "no"},
                publish_all_ports=False,
                privileged=False,
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                user=contract.user,
                pids_limit=256,
                mem_limit=f"{invocation.memory_limit_mb}m",
                nano_cpus=1_000_000_000,
                tmpfs=dict(TMPFS),
                volumes=mounts.volumes,
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
                self._require_runtime_paths(campaign, directory, contract)
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

    def observe_candidates(
        self, campaign: FuzzCampaign, invocation: ContainerInvocation,
    ) -> tuple[ContainerCandidateObservation, ...]:
        """Classify bounded BigEye-owned candidates without adopting mismatches."""

        self._validate_campaign(campaign)
        filters = {
            "label": [
                f"{MANAGED_LABEL}=fuzz-campaign",
                f"{CAMPAIGN_LABEL}={campaign.id}",
                f"{PROJECT_LABEL}={campaign.project_id}",
            ],
        }
        listed = tuple(self._client.containers.list(all=True, filters=filters))
        if len(listed) > _MAX_RECOVERY_CANDIDATES:
            raise ContainerOwnershipMismatch(
                f"campaign {campaign.id} recovery candidates exceed their bound"
            )
        with self._workspace.open_campaign(
            campaign.project_id, campaign.id, create=False,
        ) as directory:
            mounts = self._workspace.existing_mounts(directory)
            self._workspace.prepare_logs(directory)
            user_id, group_id = _unprivileged_user()
            contract = build_runtime_contract(
                self._client,
                campaign,
                invocation,
                mounts.volumes,
                mounts.identities,
                f"{user_id}:{group_id}",
                (directory.device, directory.inode),
                directory.path,
            )
            self._require_runtime_paths(campaign, directory, contract)
            observations = []
            seen_ids = set()
            for container in listed:
                try:
                    container.reload()
                    container_id = str(container.id)
                    if container_id in seen_ids:
                        continue
                    self._require_quarantine_ownership(container, contract, container_id)
                    state = _container_state(container)
                    if state not in _OBSERVABLE_STATES:
                        continue
                    try:
                        verify_runtime(container, contract)
                    except ContainerContractMismatch:
                        exact = False
                    else:
                        self._require_runtime_paths(campaign, directory, contract)
                        exact = True
                    observation = ContainerCandidateObservation(
                        container_id,
                        campaign.id,
                        campaign.project_id,
                        state,
                        exact,
                    )
                except Exception:
                    # One uninspectable result cannot become evidence or hide a valid peer.
                    continue
                seen_ids.add(container_id)
                self._observed[container_id] = (observation, contract)
                if exact:
                    self._register(container, contract, state)
                observations.append(observation)
            return tuple(sorted(observations, key=lambda item: item.container_id))

    def adopt_candidate(
        self, observation: ContainerCandidateObservation,
    ) -> ContainerIdentity:
        """Re-inspect and adopt one previously classified exact candidate."""

        known, contract = self._known_observation(observation)
        if not known.runtime_contract_matches:
            raise ContainerOwnershipMismatch("a mismatched recovery candidate cannot be adopted")
        container = self._client.containers.get(known.container_id)
        container.reload()
        verify_runtime(container, contract)
        state = _container_state(container)
        if state not in _OBSERVABLE_STATES:
            raise ContainerOwnershipMismatch("recovery candidate state is unsupported")
        return self._register(container, contract, state)

    def quarantine_candidate(self, observation: ContainerCandidateObservation) -> None:
        """Boundedly remove one re-inspected BigEye-owned recovery candidate."""

        known, contract = self._known_observation(observation)
        container = self._client.containers.get(known.container_id)
        container.reload()
        self._require_quarantine_ownership(container, contract, known.container_id)
        state = _container_state(container)
        if state not in _OBSERVABLE_STATES:
            raise ContainerOwnershipMismatch("recovery candidate state is unsupported")
        primary_error = None
        if state in ACTIVE_STATES:
            try:
                container.stop(timeout=self._stop_timeout_seconds)
            except Exception as error:
                primary_error = error
            try:
                container.reload()
            except Exception as error:
                if primary_error is not None:
                    primary_error.add_note(f"state reload after graceful stop also failed: {error}")
                    raise primary_error
                raise
            state = _container_state(container)
            if state in ACTIVE_STATES:
                try:
                    container.kill()
                except Exception as error:
                    if primary_error is not None:
                        primary_error.add_note(f"forced kill also failed: {error}")
                    else:
                        primary_error = error
                container.reload()
                state = _container_state(container)
        if state in ACTIVE_STATES:
            still_running = ContainerStillRunning(
                f"container {known.container_id} did not stop during quarantine"
            )
            if primary_error is not None:
                primary_error.add_note(str(still_running))
                raise primary_error
            raise still_running
        container.remove(force=False)
        self._observed.pop(known.container_id, None)
        self._owned.pop(known.container_id, None)
        if primary_error is not None:
            raise primary_error

    def resume_candidate(
        self, observation: ContainerCandidateObservation,
    ) -> ContainerIdentity:
        """Resume one exact paused candidate through the verified service contract."""

        identity = self.adopt_candidate(observation)
        if identity.state != "paused":
            raise ContainerOwnershipMismatch("only an exact paused candidate can be resumed")
        _known, contract = self._known_observation(observation)
        container = self._client.containers.get(identity.container_id)
        container.reload()
        verify_runtime(container, contract)
        container.unpause()
        container.reload()
        verify_runtime(container, contract)
        if _container_state(container) != "running":
            raise ContainerContractMismatch("resumed recovery candidate is not running")
        return self._register(container, contract, "running")

    def inspect_owned(self, identity: ContainerIdentity) -> ContainerIdentity:
        """Inspect a previously verified runtime while its corpus path is quiesced."""
        contract = self._known_contract(identity)
        container = self._client.containers.get(identity.container_id)
        container.reload()
        verify_runtime(container, contract)
        return ContainerIdentity(
            identity.container_id,
            contract.campaign_id,
            contract.project_id,
            _container_state(container),
        )

    def replace_owned(
        self,
        identity: ContainerIdentity,
        campaign: FuzzCampaign,
        invocation: ContainerInvocation,
        committed_corpus_identity: tuple[int, int],
    ) -> ContainerIdentity:
        """Replace one verified writer after its canonical corpus inode changed."""
        contract = self._known_contract(identity)
        self._validate_campaign(campaign)
        if (
            campaign.id != contract.campaign_id
            or campaign.project_id != contract.project_id
            or campaign.commit_sha != contract.commit_sha
        ):
            raise ContainerOwnershipMismatch(
                "replacement campaign does not match service-owned evidence"
            )
        _validate_filesystem_identity(committed_corpus_identity)
        container = self._client.containers.get(identity.container_id)
        container.reload()
        verify_runtime(container, contract)

        with self._workspace.open_campaign(
            contract.project_id, contract.campaign_id, create=False,
        ) as directory:
            if (directory.device, directory.inode) != (contract.device, contract.inode):
                raise ContainerOwnershipMismatch(
                    "canonical campaign workspace changed before writer replacement"
                )
            self._workspace.validate_log_destination(directory)
            mounts = self._workspace.existing_mounts(directory)
            current_identities = dict(
                (name, (device, inode)) for name, device, inode in mounts.identities
            )
            previous_identities = dict(
                (name, (device, inode)) for name, device, inode in contract.mount_identities
            )
            if (
                current_identities.get("corpus") != committed_corpus_identity
                or current_identities.get("corpus") == previous_identities.get("corpus")
                or current_identities.get("output") != previous_identities.get("output")
                or current_identities.get("config") != previous_identities.get("config")
            ):
                raise ContainerOwnershipMismatch(
                    "only the committed canonical corpus may change during writer replacement"
                )
            user_id, group_id = _unprivileged_user()
            replacement_contract = build_runtime_contract(
                self._client,
                campaign,
                invocation,
                mounts.volumes,
                mounts.identities,
                f"{user_id}:{group_id}",
                (directory.device, directory.inode),
                directory.path,
            )
            _require_same_campaign_contract(contract, replacement_contract)

            primary_error = None
            state = _container_state(container)
            if state == "paused":
                try:
                    container.unpause()
                    container.reload()
                    state = _container_state(container)
                except Exception as error:
                    primary_error = error
            if state in ACTIVE_STATES:
                try:
                    container.stop(timeout=self._stop_timeout_seconds)
                except Exception as error:
                    if primary_error is not None:
                        primary_error.add_note(f"graceful stop also failed: {error}")
                    else:
                        primary_error = error
                try:
                    container.reload()
                except Exception as error:
                    if primary_error is not None:
                        primary_error.add_note(
                            f"state reload after graceful stop also failed: {error}"
                        )
                        raise primary_error
                    raise
                state = _container_state(container)
                if state in ACTIVE_STATES:
                    try:
                        container.kill()
                    except Exception as error:
                        if primary_error is not None:
                            primary_error.add_note(f"forced kill also failed: {error}")
                        else:
                            primary_error = error
                    container.reload()
                    state = _container_state(container)
            if state in ACTIVE_STATES:
                still_running = ContainerStillRunning(
                    f"container {identity.container_id} did not stop for replacement"
                )
                if primary_error is not None:
                    primary_error.add_note(str(still_running))
                    raise primary_error
                raise still_running

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
            container.remove(force=False)
            del self._owned[identity.container_id]
            if primary_error is not None:
                raise primary_error

        replacement = self.start(campaign, invocation)
        observed = self.inspect_owned(replacement)
        replacement_contract = self._known_contract(replacement)
        if (
            observed.state != "running"
            or dict(
                (name, (device, inode))
                for name, device, inode in replacement_contract.mount_identities
            ).get("corpus") != committed_corpus_identity
        ):
            raise ContainerContractMismatch(
                "replacement writer does not own the committed corpus"
            )
        return observed

    def stream_logs(self, identity: ContainerIdentity, sink, follow: bool = True) -> None:
        contract = self._known_contract(identity)
        with self._open_owned_campaign(contract) as directory:
            container = self._owned_container(identity, contract, directory)
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
            container = self._owned_container(identity, contract, directory)
            state = _container_state(container)
            primary_error = None
            if state in ACTIVE_STATES:
                try:
                    container.stop(timeout=self._stop_timeout_seconds)
                except Exception as error:
                    primary_error = error
                try:
                    container.reload()
                except Exception as error:
                    if primary_error is not None:
                        primary_error.add_note(f"state reload after graceful stop also failed: {error}")
                        raise primary_error
                    raise
                state = _container_state(container)
                if state in ACTIVE_STATES:
                    try:
                        container.kill()
                    except Exception as error:
                        if primary_error is not None:
                            primary_error.add_note(f"forced kill also failed: {error}")
                        else:
                            primary_error = error
                    try:
                        container.reload()
                    except Exception as error:
                        if primary_error is not None:
                            primary_error.add_note(f"state reload after forced kill also failed: {error}")
                            raise primary_error
                        raise
                    state = _container_state(container)
            if state in ACTIVE_STATES:
                still_running = ContainerStillRunning(f"container {identity.container_id} did not stop")
                if primary_error is not None:
                    primary_error.add_note(str(still_running))
                    raise primary_error
                raise still_running
            try:
                self._require_contract_paths(contract, directory)
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
                self._require_contract_paths(contract, directory)
                container.remove(force=False)
            except Exception as error:
                if primary_error is not None:
                    primary_error.add_note(f"post-stop cleanup also failed: {error}")
                    raise primary_error
                raise
            del self._owned[identity.container_id]
            if primary_error is not None:
                raise primary_error

    def _find(self, campaign: FuzzCampaign, invocation: ContainerInvocation, running_only: bool) -> ContainerIdentity | None:
        self._validate_campaign(campaign)
        filters = {
            "label": [
                f"{MANAGED_LABEL}=fuzz-campaign",
                f"{CAMPAIGN_LABEL}={campaign.id}",
                f"{PROJECT_LABEL}={campaign.project_id}",
            ],
        }
        candidates = self._client.containers.list(all=True, filters=filters)
        if not candidates:
            return None
        with self._workspace.open_campaign(campaign.project_id, campaign.id, create=False) as directory:
            mounts = self._workspace.existing_mounts(directory)
            self._workspace.prepare_logs(directory)
            user_id, group_id = _unprivileged_user()
            contract = build_runtime_contract(
                self._client,
                campaign,
                invocation,
                mounts.volumes,
                mounts.identities,
                f"{user_id}:{group_id}",
                (directory.device, directory.inode),
                directory.path,
            )
            self._require_runtime_paths(campaign, directory, contract)
            matches = []
            for container in candidates:
                container.reload()
                verify_runtime(container, contract)
                self._require_runtime_paths(campaign, directory, contract)
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

    def _known_observation(
        self, observation: ContainerCandidateObservation,
    ) -> tuple[ContainerCandidateObservation, RuntimeContract]:
        if not isinstance(observation, ContainerCandidateObservation):
            raise ContainerOwnershipMismatch("recovery candidate observation is invalid")
        value = self._observed.get(observation.container_id)
        if value is None or value[0] != observation:
            raise ContainerOwnershipMismatch("recovery candidate was not issued by this service")
        return value

    @staticmethod
    def _require_quarantine_ownership(
        container, contract: RuntimeContract, expected_id: str,
    ) -> None:
        attrs = container.attrs
        config = attrs.get("Config") or {}
        labels = config.get("Labels") or {}
        if (
            not isinstance(labels, dict)
            or str(getattr(container, "id", "")) != expected_id
            or str(attrs.get("Id", "")) != expected_id
            or attrs.get("Name") != contract.name
            or labels.get(MANAGED_LABEL) != "fuzz-campaign"
            or labels.get(CAMPAIGN_LABEL) != str(contract.campaign_id)
            or labels.get(PROJECT_LABEL) != str(contract.project_id)
        ):
            raise ContainerOwnershipMismatch(
                "container does not retain exact BigEye recovery ownership"
            )

    def _owned_container(self, identity: ContainerIdentity, contract: RuntimeContract, directory: CampaignDirectory):
        self._require_contract_paths(contract, directory)
        container = self._client.containers.get(identity.container_id)
        container.reload()
        verify_runtime(container, contract)
        self._require_contract_paths(contract, directory)
        return container

    @contextmanager
    def _open_owned_campaign(self, contract: RuntimeContract):
        with self._workspace.open_campaign(contract.project_id, contract.campaign_id, create=False) as directory:
            if (directory.device, directory.inode) != (contract.device, contract.inode):
                raise ValueError("canonical campaign workspace changed after ownership was established")
            self._workspace.require_mount_identities(directory, contract.mount_identities)
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

    def _require_runtime_paths(
        self,
        campaign: FuzzCampaign,
        directory: CampaignDirectory,
        contract: RuntimeContract,
    ) -> None:
        self._require_canonical(campaign, directory)
        self._workspace.require_mount_identities(directory, contract.mount_identities)

    def _require_contract_paths(self, contract: RuntimeContract, directory: CampaignDirectory) -> None:
        self._require_contract_canonical(contract)
        self._workspace.require_mount_identities(directory, contract.mount_identities)

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


def _validate_filesystem_identity(identity: tuple[int, int]) -> None:
    if (
        not isinstance(identity, tuple)
        or len(identity) != 2
        or any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in identity)
    ):
        raise ValueError("committed corpus identity must contain two positive integers")


def _require_same_campaign_contract(
    previous: RuntimeContract,
    replacement: RuntimeContract,
) -> None:
    stable_fields = (
        "campaign_id", "project_id", "commit_sha", "image_id", "engine",
        "command", "environment", "mounts", "user", "memory_bytes",
        "device", "inode", "campaign_path", "name",
    )
    if any(getattr(previous, field) != getattr(replacement, field) for field in stable_fields):
        raise ContainerOwnershipMismatch(
            "replacement invocation changed the verified campaign contract"
        )
    corpus_label = "com.bigeye.mount.corpus"
    previous_labels = previous.labels_dict()
    replacement_labels = replacement.labels_dict()
    previous_labels.pop(corpus_label, None)
    replacement_labels.pop(corpus_label, None)
    if previous_labels != replacement_labels:
        raise ContainerOwnershipMismatch(
            "replacement invocation changed campaign ownership labels"
        )
