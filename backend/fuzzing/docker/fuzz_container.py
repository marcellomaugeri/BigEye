"""Own persistent, isolated fuzzing containers through the Docker SDK."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from backend.fuzzing.docker.image_builder import PLATFORM
from backend.fuzzing.engines.contracts import ContainerInvocation
from backend.fuzzing.engines.validation import validate_environment, validate_image_id, validate_labels


MANAGED_LABEL = "com.bigeye.managed"
CAMPAIGN_LABEL = "com.bigeye.campaign-id"
PROJECT_LABEL = "com.bigeye.project-id"
COMMIT_LABEL = "com.bigeye.commit-sha"
IMAGE_LABEL = "com.bigeye.image-id"
ENGINE_LABEL = "com.bigeye.engine"
RESERVED_LABELS = frozenset({MANAGED_LABEL, CAMPAIGN_LABEL, PROJECT_LABEL, COMMIT_LABEL, IMAGE_LABEL, ENGINE_LABEL})
ACTIVE_STATES = frozenset({"created", "running", "restarting", "paused"})


class ContainerOwnershipMismatch(RuntimeError):
    """Raised rather than operating on a container BigEye cannot prove it owns."""


class ContainerStillRunning(RuntimeError):
    """Raised when a bounded graceful stop and kill did not stop the container."""


@dataclass(frozen=True)
class FuzzCampaign:
    id: int
    project_id: int
    commit_sha: str
    workspace: Path


@dataclass(frozen=True)
class ContainerIdentity:
    container_id: str
    campaign_id: int
    project_id: int
    image_id: str
    engine: str
    expected_labels: Mapping[str, str]
    log_path: Path
    state: str


class FuzzContainerService:
    """Create, adopt, inspect, stream, and stop one campaign container."""

    def __init__(self, client, stop_timeout_seconds: int = 10):
        if isinstance(stop_timeout_seconds, bool) or not 1 <= stop_timeout_seconds <= 30:
            raise ValueError("stop_timeout_seconds must be between 1 and 30")
        self._client = client
        self._stop_timeout_seconds = stop_timeout_seconds

    def start(self, campaign: FuzzCampaign, invocation: ContainerInvocation) -> ContainerIdentity:
        workspace = self._validate(campaign, invocation)
        self._prepare_log_path(workspace)
        existing = self.inspect(campaign, invocation)
        if existing is not None:
            if existing.state == "running":
                return existing
            raise ContainerOwnershipMismatch(
                f"campaign {campaign.id} already has a managed container in state {existing.state}"
            )

        labels = self._expected_labels(campaign, invocation)
        user_id, group_id = _unprivileged_user()
        volumes = self._prepare_mounts(workspace, root_fallback=os.getuid() == 0)
        container = self._client.containers.create(
            invocation.image_id,
            list(invocation.command),
            name=f"bigeye-campaign-{campaign.id}",
            platform=PLATFORM,
            network_disabled=True,
            privileged=False,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            user=f"{user_id}:{group_id}",
            pids_limit=256,
            mem_limit=f"{invocation.memory_limit_mb}m",
            nano_cpus=1_000_000_000,
            tmpfs={"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"},
            volumes=volumes,
            environment=dict(invocation.environment),
            labels=labels,
            auto_remove=False,
            detach=True,
        )
        container.start()
        return self._identity(container, campaign, invocation, workspace, "running")

    def inspect(self, campaign: FuzzCampaign, invocation: ContainerInvocation) -> ContainerIdentity | None:
        return self._find(campaign, invocation, running_only=False)

    def recover(self, campaign: FuzzCampaign, invocation: ContainerInvocation) -> ContainerIdentity | None:
        return self._find(campaign, invocation, running_only=True)

    def stream_logs(self, identity: ContainerIdentity, sink, follow: bool = True) -> None:
        container = self._owned_container(identity)
        for chunk in container.logs(stream=True, follow=follow, stdout=True, stderr=True):
            sink(_text(chunk))

    def stop(self, identity: ContainerIdentity) -> None:
        container = self._owned_container(identity)
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
        self._persist_final_logs(container, identity.log_path)
        container.remove(force=False)

    def _find(
        self,
        campaign: FuzzCampaign,
        invocation: ContainerInvocation,
        running_only: bool,
    ) -> ContainerIdentity | None:
        workspace = self._validate(campaign, invocation)
        filters = {"label": [f"{MANAGED_LABEL}=fuzz-campaign", f"{CAMPAIGN_LABEL}={campaign.id}"]}
        candidates = self._client.containers.list(all=True, filters=filters)
        if not candidates:
            return None
        expected = self._expected_labels(campaign, invocation)
        matches = []
        for container in candidates:
            container.reload()
            if not _has_exact_ownership(container, expected, invocation.image_id):
                raise ContainerOwnershipMismatch(
                    f"container {container.id} does not match campaign {campaign.id} ownership labels"
                )
            state = _container_state(container)
            if not running_only or state == "running":
                matches.append((container, state))
        if len(matches) > 1:
            raise ContainerOwnershipMismatch(f"campaign {campaign.id} has multiple managed containers")
        if not matches:
            return None
        container, state = matches[0]
        return self._identity(container, campaign, invocation, workspace, state)

    def _owned_container(self, identity: ContainerIdentity):
        container = self._client.containers.get(identity.container_id)
        container.reload()
        if not _has_exact_ownership(container, identity.expected_labels, identity.image_id):
            raise ContainerOwnershipMismatch(
                f"container {identity.container_id} no longer matches its adopted ownership"
            )
        return container

    @staticmethod
    def _validate(campaign: FuzzCampaign, invocation: ContainerInvocation) -> Path:
        if isinstance(campaign.id, bool) or campaign.id <= 0:
            raise ValueError("campaign id must be positive")
        if isinstance(campaign.project_id, bool) or campaign.project_id <= 0:
            raise ValueError("project id must be positive")
        if len(campaign.commit_sha) not in {40, 64} or any(character not in "0123456789abcdef" for character in campaign.commit_sha):
            raise ValueError("commit_sha must be a lowercase hexadecimal object ID")
        workspace = Path(campaign.workspace)
        if workspace.is_symlink() or not workspace.is_dir():
            raise ValueError("campaign workspace must be an existing real directory")
        workspace = workspace.resolve(strict=True)
        if not invocation.network_disabled or not invocation.read_only_source:
            raise ValueError("fuzz invocations must disable networking and keep the image read-only")
        if invocation.engine not in {"afl", "libfuzzer"}:
            raise ValueError("unsupported fuzz engine")
        validate_image_id(invocation.image_id)
        if not invocation.command or any(not isinstance(item, str) or not item or "\x00" in item for item in invocation.command):
            raise ValueError("fuzz command entries must be non-empty strings without NUL bytes")
        if invocation.engine == "afl" and invocation.command[0] != "afl-fuzz":
            raise ValueError("AFL++ invocation must begin with afl-fuzz")
        if invocation.engine == "libfuzzer" and not invocation.command[0].startswith("/opt/bigeye/"):
            raise ValueError("libFuzzer invocation must begin with an /opt/bigeye target")
        if isinstance(invocation.memory_limit_mb, bool) or not 64 <= invocation.memory_limit_mb <= 65_536:
            raise ValueError("memory_limit_mb must be between 64 and 65536")
        if isinstance(invocation.timeout_ms, bool) or invocation.timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        validate_environment(invocation.environment)
        validate_labels(invocation.campaign_labels)
        if any(key in RESERVED_LABELS or key.startswith("com.bigeye.") for key in invocation.campaign_labels):
            raise ValueError("campaign labels cannot override reserved BigEye labels")
        return workspace

    @staticmethod
    def _prepare_mounts(workspace: Path, root_fallback: bool = False) -> dict[str, dict[str, str]]:
        volumes = {}
        for name, mode in (("corpus", "rw"), ("output", "rw"), ("config", "ro")):
            path = workspace / name
            if path.exists() and (path.is_symlink() or not path.is_dir()):
                raise ValueError(f"campaign {name} path must be a real directory")
            path.mkdir(mode=0o700, exist_ok=True)
            if path.resolve(strict=True).parent != workspace:
                raise ValueError(f"campaign {name} path escapes the workspace")
            if root_fallback:
                path.chmod(0o755 if mode == "ro" else 0o777)
            volumes[str(path)] = {"bind": f"/campaign/{name}", "mode": mode}
        return volumes

    @staticmethod
    def _expected_labels(campaign: FuzzCampaign, invocation: ContainerInvocation) -> dict[str, str]:
        labels = {
            MANAGED_LABEL: "fuzz-campaign",
            CAMPAIGN_LABEL: str(campaign.id),
            PROJECT_LABEL: str(campaign.project_id),
            COMMIT_LABEL: campaign.commit_sha,
            IMAGE_LABEL: invocation.image_id,
            ENGINE_LABEL: invocation.engine,
        }
        labels.update(invocation.campaign_labels)
        return labels

    def _identity(
        self,
        container,
        campaign: FuzzCampaign,
        invocation: ContainerInvocation,
        workspace: Path,
        state: str,
    ) -> ContainerIdentity:
        log_path = self._prepare_log_path(workspace)
        return ContainerIdentity(
            container_id=str(container.id),
            campaign_id=campaign.id,
            project_id=campaign.project_id,
            image_id=invocation.image_id,
            engine=invocation.engine,
            expected_labels=self._expected_labels(campaign, invocation),
            log_path=log_path,
            state=state,
        )

    @staticmethod
    def _prepare_log_path(workspace: Path) -> Path:
        log_directory = workspace / "logs"
        if log_directory.exists() and (log_directory.is_symlink() or not log_directory.is_dir()):
            raise ValueError("campaign log path must be a real directory")
        log_directory.mkdir(mode=0o700, exist_ok=True)
        if log_directory.resolve(strict=True).parent != workspace:
            raise ValueError("campaign log path escapes the workspace")
        return log_directory / "container.log"

    @staticmethod
    def _persist_final_logs(container, log_path: Path) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(log_path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("campaign log destination must be a regular file")
            for chunk in container.logs(stream=True, follow=False, stdout=True, stderr=True):
                data = chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8", errors="replace")
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _has_exact_ownership(container, expected: Mapping[str, str], image_id: str) -> bool:
    labels = container.attrs.get("Config", {}).get("Labels") or {}
    return (
        isinstance(labels, dict)
        and all(labels.get(key) == value for key, value in expected.items())
        and container.attrs.get("Image") == image_id
    )


def _container_state(container) -> str:
    return str(container.attrs.get("State", {}).get("Status") or getattr(container, "status", "unknown"))


def _text(chunk) -> str:
    return chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk)


def _unprivileged_user() -> tuple[int, int]:
    user_id, group_id = os.getuid(), os.getgid()
    return (65534, 65534) if user_id == 0 else (user_id, group_id)
