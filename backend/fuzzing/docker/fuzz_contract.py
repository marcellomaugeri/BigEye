"""Strict command and Docker-inspection contract for one fuzzing container."""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from pathlib import PurePosixPath
from typing import Mapping

from backend.fuzzing.engines.contracts import ContainerInvocation
from backend.fuzzing.engines.validation import (
    ROLE_PATTERN,
    validate_afl_asan_environment,
    validate_environment,
    validate_image_id,
    validate_labels,
)


MANAGED_LABEL = "com.bigeye.managed"
CAMPAIGN_LABEL = "com.bigeye.campaign-id"
PROJECT_LABEL = "com.bigeye.project-id"
COMMIT_LABEL = "com.bigeye.commit-sha"
IMAGE_LABEL = "com.bigeye.image-id"
ENGINE_LABEL = "com.bigeye.engine"
RESERVED_LABELS = frozenset({MANAGED_LABEL, CAMPAIGN_LABEL, PROJECT_LABEL, COMMIT_LABEL, IMAGE_LABEL, ENGINE_LABEL})
TMPFS = {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"}
SHELL_NAMES = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish", "env"})


class ContainerContractMismatch(RuntimeError):
    """Raised when Docker inspection does not reproduce BigEye's exact contract."""


@dataclass(frozen=True)
class RuntimeContract:
    campaign_id: int
    project_id: int
    commit_sha: str
    image_id: str
    engine: str
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    labels: tuple[tuple[str, str], ...]
    requested_labels: tuple[tuple[str, str], ...]
    mounts: tuple[tuple[str, str, str], ...]
    user: str
    memory_bytes: int
    device: int
    inode: int
    campaign_path: str
    name: str

    def environment_dict(self) -> dict[str, str]:
        return dict(self.environment)

    def labels_dict(self) -> dict[str, str]:
        return dict(self.labels)


def build_runtime_contract(client, campaign, invocation: ContainerInvocation, volumes, user: str, identity, campaign_path) -> RuntimeContract:
    validate_invocation(invocation)
    image = client.api.inspect_image(invocation.image_id)
    if image.get("Id") != invocation.image_id or image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise ContainerContractMismatch("fuzz image must be the exact inspected linux/amd64 image")
    image_config = image.get("Config") or {}
    environment = _environment(image_config.get("Env") or [])
    environment.update(invocation.environment)
    requested_labels = _required_labels(campaign, invocation)
    labels = dict(image_config.get("Labels") or {})
    labels.update(requested_labels)
    mounts = tuple(sorted((source, mount["bind"], mount["mode"]) for source, mount in volumes.items()))
    return RuntimeContract(
        campaign_id=campaign.id,
        project_id=campaign.project_id,
        commit_sha=campaign.commit_sha,
        image_id=invocation.image_id,
        engine=invocation.engine,
        command=tuple(invocation.command),
        environment=tuple(sorted(environment.items())),
        labels=tuple(sorted(labels.items())),
        requested_labels=tuple(sorted(requested_labels.items())),
        mounts=mounts,
        user=user,
        memory_bytes=invocation.memory_limit_mb * 1024 * 1024,
        device=identity[0],
        inode=identity[1],
        campaign_path=str(campaign_path),
        name=f"/bigeye-campaign-{campaign.id}",
    )


def verify_runtime(container, contract: RuntimeContract) -> None:
    attrs = container.attrs
    config = attrs.get("Config") or {}
    host = attrs.get("HostConfig") or {}
    if attrs.get("Image") != contract.image_id or attrs.get("Platform") != "linux" or attrs.get("Name") != contract.name:
        raise ContainerContractMismatch("container runtime contract has the wrong image or platform")
    if tuple(config.get("Cmd") or ()) != contract.command:
        raise ContainerContractMismatch("container runtime contract command changed")
    if config.get("NetworkDisabled") is not True:
        raise ContainerContractMismatch("container runtime contract networking is not disabled")
    if _environment(config.get("Env") or []) != contract.environment_dict():
        raise ContainerContractMismatch("container runtime contract environment changed")
    actual_labels = config.get("Labels") or {}
    if not isinstance(actual_labels, dict) or actual_labels != contract.labels_dict():
        raise ContainerContractMismatch("container runtime contract ownership labels changed")
    if config.get("User") != contract.user or _user_id(contract.user) == 0:
        raise ContainerContractMismatch("container runtime contract user is not the expected non-root user")
    exact_host = (
        host.get("NetworkMode") == "none"
        and host.get("Privileged") is False
        and host.get("ReadonlyRootfs") is True
        and host.get("CapDrop") == ["ALL"]
        and (host.get("CapAdd") or []) == []
        and host.get("SecurityOpt") == ["no-new-privileges"]
        and host.get("PidsLimit") == 256
        and host.get("Memory") == contract.memory_bytes
        and host.get("NanoCpus") == 1_000_000_000
        and host.get("Tmpfs") == TMPFS
        and host.get("AutoRemove") is False
    )
    if not exact_host:
        raise ContainerContractMismatch("container runtime contract isolation or resources changed")
    networks = (attrs.get("NetworkSettings") or {}).get("Networks")
    if networks not in ({}, None):
        raise ContainerContractMismatch("container runtime contract unexpectedly has a network")
    actual_mounts = []
    for mount in attrs.get("Mounts") or []:
        if mount.get("Type") != "bind":
            raise ContainerContractMismatch("container runtime contract has a non-bind mount")
        source, destination, mode = mount.get("Source"), mount.get("Destination"), mount.get("Mode")
        if not all(isinstance(value, str) for value in (source, destination, mode)):
            raise ContainerContractMismatch("container runtime contract has malformed mount paths")
        if mount.get("RW") is not (mode == "rw"):
            raise ContainerContractMismatch("container runtime contract mount mode changed")
        actual_mounts.append((source, destination, mode))
    if tuple(sorted(actual_mounts)) != contract.mounts:
        raise ContainerContractMismatch("container runtime contract mounts changed")


def validate_invocation(invocation: ContainerInvocation) -> None:
    if not invocation.network_disabled or not invocation.read_only_source:
        raise ValueError("fuzz invocations must disable networking and keep the image read-only")
    validate_image_id(invocation.image_id)
    validate_environment(invocation.environment)
    validate_labels(invocation.campaign_labels)
    if any(key in RESERVED_LABELS or key.startswith("com.bigeye.") for key in invocation.campaign_labels):
        raise ValueError("campaign labels cannot override reserved BigEye labels")
    if isinstance(invocation.memory_limit_mb, bool) or not 64 <= invocation.memory_limit_mb <= 65_536:
        raise ValueError("memory_limit_mb must be between 64 and 65536")
    if isinstance(invocation.timeout_ms, bool) or invocation.timeout_ms <= 0:
        raise ValueError("timeout_ms must be positive")
    if not invocation.command or any(
        not isinstance(item, str) or not item or "\x00" in item or "\n" in item for item in invocation.command
    ):
        raise ValueError("fuzz command entries must be non-empty single-line strings")
    if invocation.engine == "afl":
        _validate_afl(invocation)
    elif invocation.engine == "libfuzzer":
        _validate_libfuzzer(invocation)
    else:
        raise ValueError("unsupported fuzz engine")


def _validate_afl(invocation: ContainerInvocation) -> None:
    command = invocation.command
    try:
        separator = command.index("--")
    except ValueError as error:
        raise ValueError("AFL command must contain one target separator") from error
    if command.count("--") != 1 or separator not in {11, 13}:
        raise ValueError("AFL command has an invalid target separator")
    expected_prefix = ["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output"]
    if command[:5] != expected_prefix or command[5] not in {"-M", "-S"} or not ROLE_PATTERN.fullmatch(command[6]):
        raise ValueError("AFL command has an invalid input, output, or role contract")
    if command[7:11] != ["-t", f"{invocation.timeout_ms}+", "-m", "0"]:
        raise ValueError("AFL command must use the exact timeout and Docker-managed memory contract")
    if separator == 13:
        if command[11] != "-x" or not _contained_path(command[12], "/campaign/config"):
            raise ValueError("AFL dictionary must be a normalized campaign configuration path")
    target = command[separator + 1:]
    if not target or not _safe_target(target[0]) or target.count("@@") > 1:
        raise ValueError("AFL target must be a normalized non-shell /opt/bigeye executable")
    validate_afl_asan_environment(invocation.environment)
    if "AFL_CUSTOM_MUTATOR_ONLY" in invocation.environment:
        raise ValueError("AFL native mutations must remain enabled")


def _validate_libfuzzer(invocation: ContainerInvocation) -> None:
    command = invocation.command
    if not _safe_target(command[0]) or command.count("/campaign/corpus") != 1:
        raise ValueError("libFuzzer target and corpus paths are invalid")
    corpus_index = command.index("/campaign/corpus")
    suffix = command[corpus_index + 1:]
    expected = [
        "-artifact_prefix=/campaign/output/",
        f"-timeout={ceil(invocation.timeout_ms / 1_000)}",
        f"-rss_limit_mb={invocation.memory_limit_mb}",
    ]
    if len(suffix) == 4 and suffix[-1].startswith("-dict=") and _contained_path(suffix[-1][6:], "/campaign/config"):
        expected.append(suffix[-1])
    if suffix != expected:
        raise ValueError("libFuzzer runtime flags must match the contained campaign contract")


def _safe_target(path: str) -> bool:
    return _contained_path(path, "/opt/bigeye") and PurePosixPath(path).name not in SHELL_NAMES


def _contained_path(path: str, root: str) -> bool:
    if not path.startswith("/") or "//" in path:
        return False
    parsed = PurePosixPath(path)
    root_path = PurePosixPath(root)
    return parsed.as_posix() == path and parsed != root_path and parsed.parts[:len(root_path.parts)] == root_path.parts and ".." not in parsed.parts


def _required_labels(campaign, invocation) -> dict[str, str]:
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


def _environment(entries) -> dict[str, str]:
    result = {}
    for entry in entries:
        if not isinstance(entry, str) or "=" not in entry:
            raise ContainerContractMismatch("container runtime contract has an invalid environment")
        key, value = entry.split("=", 1)
        if key in result:
            raise ContainerContractMismatch("container runtime contract has duplicate environment entries")
        result[key] = value
    return result


def _user_id(user: str) -> int:
    try:
        return int(user.split(":", 1)[0])
    except (ValueError, AttributeError) as error:
        raise ContainerContractMismatch("container runtime contract user is invalid") from error
