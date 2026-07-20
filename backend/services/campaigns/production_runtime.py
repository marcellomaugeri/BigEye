"""Production adapters for deterministic campaign observation and exact container control."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
import inspect
import json
import os
from pathlib import Path
import stat
from hashlib import sha256
import math

from backend.agents.context import AgentContext
from backend.agents.outputs.campaign_review import (
    ProgressionActionRecord,
    RetirementActionRecord,
)
from backend.fuzzing.discovery.inventory import RepositoryInventory
from backend.fuzzing.discovery.retrieval import EvidenceRetriever
from backend.fuzzing.campaigns.monitor import (
    CampaignArtifactObservation,
    collect_campaign_sample,
)
from backend.fuzzing.campaigns.coverage_contract import (
    CampaignCoverageContract,
    valid_replay_environment,
)
from backend.fuzzing.campaigns.recovery import (
    CampaignRecovery,
    RecoverableCampaign,
    RecoveryAssetIdentity,
    RecoveryContainer,
)
from backend.fuzzing.campaigns.cleanup import (
    CleanupAssetIdentity,
    CleanupImageIdentity,
    ProjectCleaner,
)
from backend.fuzzing.docker.campaign_workspace import CampaignWorkspace
from backend.fuzzing.docker.client import DockerClient
from backend.fuzzing.docker.fuzz_container import (
    ContainerCandidateObservation,
    FuzzCampaign,
    FuzzContainerService,
)
from backend.fuzzing.docker.fuzz_contract import validate_invocation
from backend.fuzzing.engines.contracts import ContainerInvocation
from backend.fuzzing.coverage.overlap import OverlapAnalyzer
from backend.services.campaigns.production_progression import ProductionProgression
from backend.services.campaigns.wake_rules import CampaignSnapshot
from backend.services.projects.clone_repository import contained_path


_INITIAL_TASKS = frozenset({"repository clone", "LLVM toolchain preparation"})
_MAX_CONTAINER_EVIDENCE = 512
_MAX_REVIEW_EVIDENCE = 64
_MAX_INVOCATION_BYTES = 64 * 1024
_MAX_VARIANT_CORPUS_FILES = 4_096
_MAX_VARIANT_CORPUS_FILE_BYTES = 16 * 1024 * 1024
_MAX_VARIANT_CORPUS_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class CampaignProgressObservation:
    """Bounded cumulative facts from one exact service-owned fuzz container."""

    campaign_id: int
    cpu_seconds: float
    heartbeat_at: datetime
    queue_files: int
    crash_files: int
    evidence_id: str
    container_id: str
    executions: int = 0
    executions_per_second: float = 0.0
    artifacts: tuple[CampaignArtifactObservation, ...] = ()
    next_artifact_cursors: tuple[tuple[str, int, str], ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.campaign_id) is not int or self.campaign_id <= 0
            or isinstance(self.cpu_seconds, bool)
            or not isinstance(self.cpu_seconds, (int, float))
            or not math.isfinite(self.cpu_seconds) or self.cpu_seconds < 0
            or not isinstance(self.heartbeat_at, datetime) or self.heartbeat_at.tzinfo is None
            or type(self.queue_files) is not int or not 0 <= self.queue_files <= 100_000
            or type(self.crash_files) is not int or not 0 <= self.crash_files <= 10_000
            or not isinstance(self.evidence_id, str) or not self.evidence_id
            or len(self.evidence_id) > 256
            or not isinstance(self.container_id, str) or not self.container_id
            or len(self.container_id) > 128
            or type(self.executions) is not int or self.executions < 0
            or isinstance(self.executions_per_second, bool)
            or not isinstance(self.executions_per_second, (int, float))
            or not math.isfinite(self.executions_per_second)
            or self.executions_per_second < 0
            or not isinstance(self.artifacts, tuple)
            or len(self.artifacts) > 1_024
            or any(not isinstance(item, CampaignArtifactObservation) for item in self.artifacts)
            or not isinstance(self.next_artifact_cursors, tuple)
            or len(self.next_artifact_cursors) > 2
            or any(
                not isinstance(item, tuple) or len(item) != 3
                or item[0] not in {"queue", "crashes"}
                or type(item[1]) is not int or item[1] < 0
                or not isinstance(item[2], str)
                or (not item[2] and item[1] != 0)
                for item in self.next_artifact_cursors
            )
        ):
            raise ValueError("campaign progress observation is invalid")


@dataclass(frozen=True)
class ContainerObservation:
    """Exact worker identities observed through the Docker contract service."""

    active_campaign_ids: tuple[int, ...] = ()
    unhealthy_campaign_ids: tuple[int, ...] = ()
    evidence: tuple[dict, ...] = ()
    progress: tuple[CampaignProgressObservation, ...] = ()

    def __post_init__(self) -> None:
        for name in ("active_campaign_ids", "unhealthy_campaign_ids"):
            values = getattr(self, name)
            if (
                not isinstance(values, tuple)
                or len(values) != len(set(values))
                or any(type(value) is not int or value <= 0 for value in values)
            ):
                raise ValueError(f"container {name.replace('_', ' ')} are invalid")
        if (
            not isinstance(self.evidence, tuple)
            or len(self.evidence) > _MAX_CONTAINER_EVIDENCE
            or any(not isinstance(item, dict) for item in self.evidence)
        ):
            raise ValueError("container evidence is invalid or exceeds its bound")
        if (
            not isinstance(self.progress, tuple)
            or len(self.progress) > 256
            or any(not isinstance(item, CampaignProgressObservation) for item in self.progress)
            or len({item.campaign_id for item in self.progress}) != len(self.progress)
            or set(item.campaign_id for item in self.progress) - set(self.active_campaign_ids)
        ):
            raise ValueError("container progress is invalid or exceeds its bound")


class DockerCampaignMonitor:
    """Read cumulative Docker CPU and bounded durable queue/crash counts."""

    def __init__(self, workspace: Path, clock=None):
        self._workspace = CampaignWorkspace(Path(workspace))
        self._clock = clock or (lambda: datetime.now(UTC))

    def observe(
        self, client, project, campaign, identity, invocation, artifact_cursors=None,
    ) -> CampaignProgressObservation:
        container = client.containers.get(identity.container_id)
        statistics = container.stats(stream=False)
        try:
            total_usage = statistics["cpu_stats"]["cpu_usage"]["total_usage"]
        except (KeyError, TypeError) as error:
            raise ValueError("Docker campaign CPU statistics are incomplete") from error
        if type(total_usage) is not int or total_usage < 0:
            raise ValueError("Docker campaign CPU statistics are invalid")
        with self._workspace.open_campaign(project.id, campaign.id, create=False) as directory:
            logs_reader = getattr(container, "logs", None)
            logs = logs_reader(tail=200, stdout=True, stderr=True) if logs_reader is not None else b""
            sample = collect_campaign_sample(
                directory.descriptor,
                invocation.engine,
                logs,
                artifact_cursors or {},
            )
        digest = sha256(
            (
                f"{project.id}\0{campaign.id}\0{identity.container_id}\0{total_usage}\0"
                f"{sample.executions}\0{sample.executions_per_second}\0"
                + "\0".join(
                    f"{item.kind}:{item.relative_path}:{item.content_sha256}"
                    for item in sample.artifacts
                )
            ).encode()
        ).hexdigest()
        return CampaignProgressObservation(
            campaign.id, total_usage / 1_000_000_000, self._clock(),
            sample.queue_files, sample.crash_files,
            f"campaign-progress:{campaign.id}:{digest}", identity.container_id,
            sample.executions, sample.executions_per_second, sample.artifacts,
            sample.next_artifact_cursors,
        )


class ProjectDiscovery:
    """Build bounded deterministic repository evidence for the resolved project commit."""

    def __init__(self, workspace: Path):
        self._workspace = Path(os.path.abspath(workspace)).resolve(strict=True)
        self._contexts: dict[int, AgentContext] = {}
        self._evidence: dict[int, tuple[dict, ...]] = {}

    async def discover(self, project) -> AgentContext:
        if project.commit_sha is None:
            raise ValueError("repository commit must be resolved before discovery")
        project_root = contained_path(self._workspace, "projects", str(project.id))
        repository_root = contained_path(project_root, "repository").resolve(strict=True)
        generated_assets_root = contained_path(project_root, "assets")
        inventory = RepositoryInventory().collect(repository_root)
        retriever = EvidenceRetriever(repository_root, inventory)
        context = AgentContext(
            project.id, project.commit_sha, repository_root, generated_assets_root, retriever,
        )
        excerpts = retriever.search(
            "build executable library parser input test example configuration", 12,
        )
        evidence = [excerpt.as_dict() for excerpt in excerpts]
        inventory_id = f"repository-inventory:{project.id}:{project.commit_sha}"
        evidence.insert(0, {
            "evidence_id": inventory_id,
            "kind": "repository_inventory",
            "commit_sha": project.commit_sha,
            "inventory": inventory.as_dict(),
            "provenance": "deterministic_repository_inventory",
            "trusted_instructions": False,
        })
        self._contexts[project.id] = context
        self._evidence[project.id] = tuple(evidence)
        return context

    def context(self, project_id: int) -> AgentContext:
        try:
            return self._contexts[project_id]
        except KeyError as error:
            raise RuntimeError("project discovery has not completed") from error

    def evidence(self, project_id: int) -> tuple[dict, ...]:
        try:
            return self._evidence[project_id]
        except KeyError as error:
            raise RuntimeError("project discovery has not completed") from error


class CampaignInvocationStore:
    """Load a validated shell-free invocation from one descriptor-contained campaign."""

    def __init__(self, workspace: Path):
        self._workspace = CampaignWorkspace(Path(workspace))

    def load(self, project_id: int, campaign_id: int) -> ContainerInvocation:
        with self._workspace.open_campaign(project_id, campaign_id, create=False) as campaign:
            config = os.open(
                "config", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=campaign.descriptor,
            )
            try:
                descriptor = os.open(
                    "invocation.json", os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=config,
                )
                try:
                    details = os.fstat(descriptor)
                    if not stat.S_ISREG(details.st_mode) or details.st_size > _MAX_INVOCATION_BYTES:
                        raise ValueError("campaign invocation file is invalid or too large")
                    content = os.read(descriptor, _MAX_INVOCATION_BYTES + 1)
                finally:
                    os.close(descriptor)
            finally:
                os.close(config)
        if len(content) > _MAX_INVOCATION_BYTES:
            raise ValueError("campaign invocation file exceeds its size limit")
        try:
            document = json.loads(content)
            invocation = ContainerInvocation(**document)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise ValueError("campaign invocation file is invalid") from error
        validate_invocation(invocation)
        return invocation

    def load_coverage(self, project_id: int, campaign_id: int) -> CampaignCoverageContract:
        content = self._read_config(project_id, campaign_id, "coverage.json")
        try:
            document = json.loads(content)
            if not isinstance(document, dict) or not isinstance(document.get("replay_command"), list):
                raise TypeError("coverage contract must be a JSON object with a command list")
            environment = document.get("replay_environment", [])
            if not isinstance(environment, list) or any(
                not isinstance(item, list) or len(item) != 2
                for item in environment
            ):
                raise TypeError("replay environment must be a list of two-item lists")
            document["replay_command"] = tuple(document["replay_command"])
            document["replay_environment"] = tuple(
                tuple(item) for item in environment
            )
            contract = CampaignCoverageContract(**document)
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise ValueError("campaign clean-coverage contract file is invalid") from error
        if contract.project_id != project_id:
            raise ValueError("campaign clean-coverage contract belongs to another project")
        return contract

    async def publish_coverage(
        self, project_id: int, campaign_id: int, commit_sha: str, prepared,
    ) -> None:
        if (
            getattr(prepared, "project_id", None) != project_id
            or getattr(prepared, "commit_sha", None) != commit_sha
        ):
            raise ValueError("prepared coverage contract belongs to another project revision")
        target_labels = getattr(getattr(prepared, "target_manifest", None), "labels", None)
        coverage_manifest = getattr(prepared, "coverage_manifest", None)
        coverage_labels = getattr(coverage_manifest, "labels", None)
        try:
            target_asset_id = int(target_labels["bigeye.target-asset"])
            configuration_asset_id = int(coverage_labels["bigeye.configuration-asset-id"])
            coverage_asset_id = int(coverage_labels["bigeye.coverage-asset-id"])
            parent_image_id = coverage_labels["bigeye.parent-image"]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("prepared coverage contract provenance is incomplete") from error
        commands = []
        for probe in getattr(prepared, "probe_invocations", ()):
            if getattr(probe, "role", None) != "seed":
                continue
            command = tuple(getattr(probe, "command", ()))
            if not command:
                raise ValueError("prepared coverage probe has no explicit input")
            if command[-1] == "{stdin}":
                commands.append(command)
            elif command[-1].startswith(("/src/", "/bigeye/target/")):
                commands.append((*command[:-1], "{input}"))
            else:
                raise ValueError("prepared coverage probe has no explicit input")
        if not commands or len(set(commands)) != 1:
            raise ValueError("prepared coverage probes do not share one replay contract")
        replay_command = commands[0]
        contract = CampaignCoverageContract(
            project_id=project_id,
            commit_sha=commit_sha,
            clean_image_id=getattr(prepared, "coverage_image_id", ""),
            clean_content_hash=getattr(coverage_manifest, "content_hash", ""),
            clean_parent_image_id=parent_image_id,
            target_asset_id=target_asset_id,
            configuration_asset_id=configuration_asset_id,
            clean_build_configuration_asset_id=configuration_asset_id,
            coverage_asset_id=coverage_asset_id,
            binary_path=replay_command[0],
            replay_command=replay_command,
        )
        encoded = json.dumps(
            asdict(contract), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > _MAX_INVOCATION_BYTES:
            raise ValueError("campaign clean-coverage contract exceeds its size limit")
        with self._workspace.open_campaign(project_id, campaign_id, create=True) as campaign:
            config = self._open_directory(campaign.descriptor, "config")
            try:
                self._publish_exact(config, "coverage.json", encoded)
            finally:
                os.close(config)

    def _read_config(self, project_id: int, campaign_id: int, name: str) -> bytes:
        with self._workspace.open_campaign(project_id, campaign_id, create=False) as campaign:
            config = os.open(
                "config", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=campaign.descriptor,
            )
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=config)
                try:
                    details = os.fstat(descriptor)
                    if not stat.S_ISREG(details.st_mode) or details.st_size > _MAX_INVOCATION_BYTES:
                        raise ValueError("campaign configuration file is invalid or too large")
                    content = os.read(descriptor, _MAX_INVOCATION_BYTES + 1)
                finally:
                    os.close(descriptor)
            finally:
                os.close(config)
        if len(content) > _MAX_INVOCATION_BYTES:
            raise ValueError("campaign configuration file exceeds its size limit")
        return content

    async def publish(
        self,
        project_id: int,
        campaign_id: int,
        invocation: ContainerInvocation,
        probe_invocations,
        *,
        configuration_files: dict[str, bytes] | None = None,
    ) -> None:
        validate_invocation(invocation)
        configuration_files = dict(configuration_files or {})
        if (
            set(configuration_files) - {"tokens.dict", "sanitizer-intent.json"}
            or any(
                not isinstance(value, bytes) or not value or len(value) > _MAX_INVOCATION_BYTES
                for value in configuration_files.values()
            )
        ):
            raise ValueError("campaign configuration publication is invalid")
        uses_dictionary = (
            "/campaign/config/tokens.dict" in invocation.command
            or "-dict=/campaign/config/tokens.dict" in invocation.command
        )
        if uses_dictionary != ("tokens.dict" in configuration_files):
            raise ValueError("campaign dictionary file does not match the invocation")
        seeds = tuple(
            item.testcase_bytes for item in probe_invocations
            if getattr(item, "role", None) == "seed"
        )
        if not seeds or any(not isinstance(value, bytes) for value in seeds):
            raise ValueError("campaign publication requires validated probe seed bytes")
        encoded = json.dumps(
            asdict(invocation), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > _MAX_INVOCATION_BYTES:
            raise ValueError("campaign invocation exceeds its size limit")
        with self._workspace.open_campaign(project_id, campaign_id, create=True) as campaign:
            config = self._open_directory(campaign.descriptor, "config")
            corpus = self._open_directory(campaign.descriptor, "corpus")
            try:
                self._publish_exact(config, "invocation.json", encoded)
                for name, content in sorted(configuration_files.items()):
                    self._publish_exact(config, name, content)
                for value in seeds:
                    self._publish_exact(corpus, sha256(value).hexdigest(), value)
            finally:
                os.close(corpus)
                os.close(config)

    async def clone_variant(
        self,
        project_id: int,
        base_campaign_id: int,
        campaign_id: int,
        invocation: ContainerInvocation,
        *,
        configuration_files: dict[str, bytes] | None = None,
        coverage_arguments: tuple[str, ...] = (),
        coverage_environment: tuple[tuple[str, str], ...] = (),
        configuration_asset_id: int | None = None,
    ) -> None:
        """Clone durable corpus/coverage while changing only a bounded runtime configuration."""
        if base_campaign_id == campaign_id:
            raise ValueError("campaign variant requires a different campaign identity")
        validate_invocation(invocation)
        configuration_files = dict(configuration_files or {})
        if (
            set(configuration_files) - {"tokens.dict"}
            or any(
                not isinstance(value, bytes) or not value or len(value) > _MAX_INVOCATION_BYTES
                for value in configuration_files.values()
            )
        ):
            raise ValueError("campaign variant configuration is invalid")
        encoded = json.dumps(
            asdict(invocation), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > _MAX_INVOCATION_BYTES:
            raise ValueError("campaign variant invocation exceeds its size limit")
        coverage = self._variant_coverage(
            project_id, base_campaign_id, coverage_arguments, coverage_environment,
            configuration_asset_id,
        )
        copied_config = {}
        for name in ("sanitizer-intent.json", "tokens.dict"):
            value = self._read_optional_config(project_id, base_campaign_id, name)
            if value is not None:
                copied_config[name] = value
        copied_config.update(configuration_files)
        uses_dictionary = (
            "/campaign/config/tokens.dict" in invocation.command
            or "-dict=/campaign/config/tokens.dict" in invocation.command
        )
        if uses_dictionary != ("tokens.dict" in copied_config):
            raise ValueError("campaign variant dictionary does not match its invocation")
        corpus_files = self._read_corpus(project_id, base_campaign_id)
        if not corpus_files:
            raise ValueError("campaign variant requires a durable base corpus")
        with self._workspace.open_campaign(project_id, campaign_id, create=True) as campaign:
            config = self._open_directory(campaign.descriptor, "config")
            corpus = self._open_directory(campaign.descriptor, "corpus")
            try:
                self._publish_exact(config, "invocation.json", encoded)
                self._publish_exact(config, "coverage.json", coverage)
                for name, content in sorted(copied_config.items()):
                    self._publish_exact(config, name, content)
                for name, content in corpus_files:
                    self._publish_exact(corpus, name, content)
            finally:
                os.close(corpus)
                os.close(config)

    def _read_optional_config(
        self, project_id: int, campaign_id: int, name: str,
    ) -> bytes | None:
        try:
            return self._read_config(project_id, campaign_id, name)
        except FileNotFoundError:
            return None

    def _read_corpus(self, project_id: int, campaign_id: int) -> tuple[tuple[str, bytes], ...]:
        values: list[tuple[str, bytes]] = []
        total = 0
        with self._workspace.open_campaign(project_id, campaign_id, create=False) as campaign:
            corpus = os.open(
                "corpus", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=campaign.descriptor,
            )
            try:
                names = sorted(os.listdir(corpus))
                if len(names) > _MAX_VARIANT_CORPUS_FILES:
                    raise OverflowError("campaign variant corpus exceeds its file limit")
                for name in names:
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=corpus)
                    try:
                        details = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(details.st_mode)
                            or details.st_size > _MAX_VARIANT_CORPUS_FILE_BYTES
                        ):
                            raise ValueError("campaign variant corpus contains an unsafe file")
                        content = os.read(descriptor, _MAX_VARIANT_CORPUS_FILE_BYTES + 1)
                    finally:
                        os.close(descriptor)
                    total += len(content)
                    if total > _MAX_VARIANT_CORPUS_BYTES:
                        raise OverflowError("campaign variant corpus exceeds its byte limit")
                    values.append((name, content))
            finally:
                os.close(corpus)
        return tuple(values)

    def _variant_coverage(
        self,
        project_id: int,
        campaign_id: int,
        arguments: tuple[str, ...],
        environment: tuple[tuple[str, str], ...],
        configuration_asset_id: int | None,
    ) -> bytes:
        base = self.load_coverage(project_id, campaign_id)
        if (
            not isinstance(arguments, tuple)
            or any(not isinstance(value, str) or not value for value in arguments)
            or not isinstance(environment, tuple)
        ):
            raise ValueError("campaign coverage variant is invalid")
        command = [*base.replay_command, *arguments]
        merged_environment = dict(base.replay_environment)
        merged_environment.update(dict(environment))
        if configuration_asset_id is not None and (
            type(configuration_asset_id) is not int or configuration_asset_id <= 0
        ):
            raise ValueError("campaign coverage variant configuration asset is invalid")
        contract = replace(
            base,
            replay_command=tuple(command),
            replay_environment=tuple(sorted(merged_environment.items())),
            configuration_asset_id=(
                configuration_asset_id
                if configuration_asset_id is not None
                else base.configuration_asset_id
            ),
        )
        encoded = json.dumps(
            asdict(contract), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > _MAX_INVOCATION_BYTES:
            raise ValueError("campaign coverage variant exceeds its size limit")
        return encoded

    @staticmethod
    def _open_directory(parent: int, name: str) -> int:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)

    @staticmethod
    def _publish_exact(parent: int, name: str, content: bytes) -> None:
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=parent,
            )
            try:
                view = memoryview(content)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("campaign file publication did not progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent)
            return
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size != len(content):
                raise ValueError("existing campaign file does not match publication")
            existing = os.read(descriptor, len(content) + 1)
            if existing != content:
                raise ValueError("existing campaign file does not match publication")
        finally:
            os.close(descriptor)


class DeferredCampaignContainers:
    """Open Docker only for active campaigns and delegate to the exact contract service."""

    def __init__(
        self,
        workspace: Path,
        *,
        docker_client=None,
        invocation_store=None,
        service_factory=FuzzContainerService,
        monitor=None,
    ):
        self._workspace = Path(workspace)
        self._docker_client = docker_client or DockerClient()
        self._invocations = invocation_store or CampaignInvocationStore(workspace)
        self._service_factory = service_factory
        self._monitor = monitor or DockerCampaignMonitor(workspace)

    async def reconcile(
        self, project, campaigns, assets=(), artifact_cursors=None,
    ) -> ContainerObservation:
        active = tuple(
            campaign for campaign in campaigns
            if campaign.stopped_at is None and campaign.error is None
        )
        if not active:
            return ContainerObservation()
        client = self._docker_client.connect()
        active_ids: list[int] = []
        unhealthy_ids: list[int] = []
        evidence: list[dict] = []
        progress: list[CampaignProgressObservation] = []
        try:
            service = self._service_factory(client, self._workspace)
            evidence.extend(self._recover_lifecycle(
                client, service, project, active, assets,
            ))
            for campaign in active:
                try:
                    invocation = self._invocations.load(project.id, campaign.id)
                    identity = service.recover(
                        self._fuzz_campaign(project, campaign),
                        invocation,
                    )
                    if identity is None:
                        unhealthy_ids.append(campaign.id)
                        state = "missing"
                    elif identity.state != "running":
                        unhealthy_ids.append(campaign.id)
                        state = identity.state
                    else:
                        active_ids.append(campaign.id)
                        state = identity.state
                        current = self._monitor.observe(
                            client, project, campaign, identity, invocation,
                            (artifact_cursors or {}).get(campaign.id, {}),
                        )
                        progress.append(current)
                        evidence.append({
                            "evidence_id": current.evidence_id,
                            "project_id": project.id,
                            "campaign_id": campaign.id,
                            "cpu_seconds": current.cpu_seconds,
                            "queue_files": current.queue_files,
                            "crash_files": current.crash_files,
                            "provenance": "docker_campaign_monitor",
                            "trusted_instructions": False,
                        })
                except Exception as error:
                    unhealthy_ids.append(campaign.id)
                    state = f"invalid:{type(error).__name__}"
                evidence.append(self._evidence(project, campaign, state))
            evidence.extend(self._cleanup_lifecycle(client, project, campaigns, assets))
        finally:
            self._close(client)
        return ContainerObservation(
            tuple(active_ids), tuple(unhealthy_ids), tuple(evidence), tuple(progress),
        )

    def _cleanup_lifecycle(self, client, project, campaigns, assets) -> list[dict]:
        assets_by_id = {asset.id: asset for asset in assets}
        identities: dict[str, CleanupImageIdentity] = {}
        referenced = set()
        for campaign in campaigns:
            if campaign.error is not None and campaign.stopped_at is None:
                continue
            invocation = self._invocations.load(project.id, campaign.id)
            target = assets_by_id.get(campaign.target_asset_id)
            if (
                target is None or target.project_id != project.id
                or target.validated_at is None or target.error is not None
            ):
                raise ValueError("campaign cleanup requires an exact validated target asset")
            target_image = client.images.get(invocation.image_id)
            target_labels = (target_image.attrs.get("Config") or {}).get("Labels") or {}
            target_identity = CleanupImageIdentity(
                invocation.image_id,
                "target",
                target_labels.get("bigeye.content-hash", ""),
                target_labels.get("bigeye.parent-image", ""),
                (CleanupAssetIdentity("target", target.id, target.content_hash),),
            )
            self._unique_cleanup_identity(identities, target_identity)
            if campaign.stopped_at is None:
                referenced.add(invocation.image_id)
            try:
                coverage = self._invocations.load_coverage(project.id, campaign.id)
            except FileNotFoundError:
                continue
            coverage_assets = []
            strategy = assets_by_id.get(coverage.configuration_asset_id)
            if (
                strategy is None or strategy.project_id != project.id
                or strategy.validated_at is None or strategy.error is not None
            ):
                raise ValueError("campaign cleanup strategy asset identity is unavailable")
            for role, asset_id in (
                ("target", coverage.target_asset_id),
                ("configuration", coverage.clean_build_configuration_asset_id),
                ("coverage", coverage.coverage_asset_id),
            ):
                asset = assets_by_id.get(asset_id)
                if (
                    asset is None or asset.project_id != project.id
                    or asset.validated_at is None or asset.error is not None
                ):
                    raise ValueError("campaign cleanup coverage asset identity is unavailable")
                coverage_assets.append(CleanupAssetIdentity(role, asset.id, asset.content_hash))
            coverage_identity = CleanupImageIdentity(
                coverage.clean_image_id,
                "coverage",
                coverage.clean_content_hash,
                coverage.clean_parent_image_id,
                tuple(coverage_assets),
            )
            self._unique_cleanup_identity(identities, coverage_identity)
            if campaign.stopped_at is None:
                referenced.add(coverage.clean_image_id)
        result = ProjectCleaner(
            client, self._workspace, clock=lambda: datetime.now(UTC),
        ).clean(
            project.id,
            project.commit_sha,
            referenced_image_ids=tuple(referenced),
            persisted_image_identities=tuple(identities.values()),
        )
        if not any((
            result.removed_contexts,
            result.removed_container_ids,
            result.removed_image_ids,
            result.removed_raw_corpus_copies,
            result.removed_duplicate_crash_copies,
        )):
            return []
        digest = sha256(json.dumps(asdict(result), sort_keys=True).encode()).hexdigest()
        return [{
            "evidence_id": f"campaign-cleanup:{project.id}:{digest}",
            "project_id": project.id,
            "removed_contexts": list(result.removed_contexts),
            "removed_container_ids": list(result.removed_container_ids),
            "removed_image_ids": list(result.removed_image_ids),
            "removed_raw_corpus_copies": list(result.removed_raw_corpus_copies),
            "removed_duplicate_crash_copies": list(result.removed_duplicate_crash_copies),
            "provenance": "deterministic_project_cleanup",
            "trusted_instructions": False,
        }]

    @staticmethod
    def _unique_cleanup_identity(values, identity) -> None:
        previous = values.get(identity.image_id)
        if previous is not None and previous != identity:
            raise ValueError("cleanup image ID has conflicting persisted identities")
        values[identity.image_id] = identity

    def _recover_lifecycle(self, client, service, project, campaigns, assets) -> list[dict]:
        asset_by_id = {asset.id: asset for asset in assets}
        recoverable = []
        containers = []
        controls = {}
        for campaign in campaigns:
            invocation = self._invocations.load(project.id, campaign.id)
            identities = []
            for asset_id in (campaign.target_asset_id, campaign.configuration_asset_id):
                if asset_id is None:
                    continue
                asset = asset_by_id.get(asset_id)
                if (
                    asset is None or asset.project_id != project.id
                    or asset.validated_at is None or asset.error is not None
                ):
                    raise ValueError("campaign recovery requires exact validated assets")
                identities.append(RecoveryAssetIdentity(asset.id, asset.content_hash))
            pending = ()
            if campaign.next_review_reason:
                pending = (f"campaign-review:{campaign.id}:" + sha256(
                    campaign.next_review_reason.encode("utf-8")
                ).hexdigest(),)
            observed = service.observe_candidates(
                self._fuzz_campaign(project, campaign), invocation,
            )
            recoverable.append(RecoverableCampaign(
                project.id,
                campaign.id,
                project.commit_sha,
                invocation.image_id,
                tuple(identities),
                campaign.error is None,
                pending,
            ))
            controls[campaign.id] = (
                campaign,
                invocation,
                {candidate.container_id: candidate for candidate in observed},
            )
            if observed:
                image = client.api.inspect_image(invocation.image_id)
                if image.get("Id") != invocation.image_id:
                    raise ValueError("campaign recovery image identity changed")
            for candidate in observed:
                containers.append(RecoveryContainer(
                    candidate.container_id,
                    "fuzz-campaign",
                    project.id,
                    campaign.id,
                    project.commit_sha,
                    invocation.image_id,
                    tuple(identities),
                    f"{image.get('Os')}/{image.get('Architecture')}",
                    candidate.state,
                    candidate.runtime_contract_matches,
                ))
        if not recoverable:
            return []
        records = CampaignRecovery(
            self._workspace,
            _ProductionRecoveryControl(client, service, project, controls),
        ).recover(project.id, tuple(recoverable), tuple(containers))
        return [{
            "evidence_id": (
                f"campaign-recovery:{record.campaign_id}:{record.action}:"
                f"{record.container_id or 'none'}"
            ),
            "project_id": record.project_id,
            "campaign_id": record.campaign_id,
            "action": record.action,
            "reason": record.reason,
            "pending_evidence_ids": list(record.pending_evidence_ids),
            "provenance": "deterministic_campaign_recovery",
            "trusted_instructions": False,
        } for record in records]

    async def stop_exact(self, project, campaign) -> None:
        """Recover service ownership evidence, then stop that exact campaign container."""
        client = self._docker_client.connect()
        try:
            service = self._service_factory(client, self._workspace)
            identity = service.recover(
                self._fuzz_campaign(project, campaign),
                self._invocations.load(project.id, campaign.id),
            )
            if identity is not None:
                service.stop(identity)
        finally:
            self._close(client)

    async def start_exact(self, project, campaign) -> None:
        client = self._docker_client.connect()
        try:
            service = self._service_factory(client, self._workspace)
            fuzz_campaign = self._fuzz_campaign(project, campaign)
            invocation = self._invocations.load(project.id, campaign.id)
            if service.recover(fuzz_campaign, invocation) is None:
                service.start(fuzz_campaign, invocation)
        finally:
            self._close(client)

    async def verify_exact(self, project, campaigns) -> None:
        for campaign in campaigns:
            self._fuzz_campaign(project, campaign)
            self._invocations.load(project.id, campaign.id)

    @staticmethod
    def _fuzz_campaign(project, campaign) -> FuzzCampaign:
        if campaign.project_id != project.id or project.commit_sha is None:
            raise ValueError("campaign does not match the resolved project identity")
        return FuzzCampaign(campaign.id, project.id, project.commit_sha)

    @staticmethod
    def _evidence(project, campaign, state: str) -> dict:
        return {
            "evidence_id": f"container:{project.id}:{campaign.id}:{state}",
            "project_id": project.id,
            "campaign_id": campaign.id,
            "state": state,
            "provenance": "docker_contract_inspection",
            "trusted_instructions": False,
        }

    @staticmethod
    def _close(client) -> None:
        close = getattr(client, "close", None)
        if close is not None:
            close()


class _ProductionRecoveryControl:
    """Apply only service-verified recovery actions selected by CampaignRecovery."""

    def __init__(self, client, service, project, controls):
        self._client = client
        self._service = service
        self._project = project
        self._controls = controls

    def adopt(self, campaign, container) -> None:
        self._service.adopt_candidate(self._candidate(campaign, container))

    def restart(self, campaign, container) -> None:
        persisted, invocation, _observed = self._record(campaign)
        current = None
        if container is not None:
            candidate = self._candidate(campaign, container)
            if candidate.state == "paused":
                self._service.resume_candidate(candidate)
                return
            current = self._service.adopt_candidate(candidate)
        fuzz_campaign = DeferredCampaignContainers._fuzz_campaign(self._project, persisted)
        if current is not None:
            self._service.stop(current)
        self._service.start(fuzz_campaign, invocation)

    def quarantine(self, campaign, container, _reason) -> None:
        self._service.quarantine_candidate(self._candidate(campaign, container))

    def _candidate(self, campaign, container) -> ContainerCandidateObservation:
        _persisted, _invocation, observed = self._record(campaign)
        current = observed.get(container.container_id)
        if current is None:
            raise ValueError("campaign recovery control identity changed")
        return current

    def _record(self, campaign):
        try:
            value = self._controls[campaign.campaign_id]
        except KeyError as error:
            raise ValueError("campaign recovery control is unavailable") from error
        persisted, invocation, _current = value
        if (
            campaign.project_id != self._project.id
            or persisted.id != campaign.campaign_id
            or invocation.image_id != campaign.image_id
        ):
            raise ValueError("campaign recovery control does not match persisted evidence")
        return value


class RepositoryCampaignRuntime:
    """Reconcile persisted facts and perform only exact, reversible campaign controls."""

    def __init__(
        self, *, tasks, assets, campaigns, discovery, containers, events=None, clock=None,
        exposure=None, coverage_history=None, overlap=None, invocations=None,
        cpu_counters=None, crash_groups=None, campaign_contexts=None,
        monitor_interval_seconds: float = 5.0,
        evidence_processor=None,
        artifact_state=None,
        progression=None,
        progression_assets=None,
    ):
        if (
            isinstance(monitor_interval_seconds, bool)
            or not isinstance(monitor_interval_seconds, (int, float))
            or not math.isfinite(monitor_interval_seconds)
            or not 0 < monitor_interval_seconds <= 300
        ):
            raise ValueError("campaign monitor interval must be between zero and 300 seconds")
        self._tasks = tasks
        self._assets = assets
        self._campaigns = campaigns
        self._discovery = discovery
        self._containers = containers
        self._events = events
        self._clock = clock or (lambda: datetime.now(UTC))
        self._exposure = exposure
        self._coverage_history = coverage_history
        self._overlap = overlap or OverlapAnalyzer()
        self._invocations = invocations
        self._cpu_counters = cpu_counters
        self._crash_groups = crash_groups
        self._campaign_contexts = campaign_contexts
        self._monitor_interval_seconds = float(monitor_interval_seconds)
        self._evidence_processor = evidence_processor
        self._artifact_state = artifact_state
        self._progression = progression or ProductionProgression()
        self._progression_assets = progression_assets
        if evidence_processor is not None and invocations is None:
            raise ValueError("campaign evidence processing requires the invocation store")
        self._observations: dict[int, ContainerObservation] = {}
        self._persisted_campaigns: dict[int, tuple] = {}
        self._persisted_assets: dict[int, dict[int, object]] = {}
        self._campaign_state: dict[int, tuple] = {}
        self._review_evidence: dict[int, tuple[dict, ...]] = {}
        self._contexts: dict[int, dict[int, dict[str, str | None]]] = {}
        self._progression_actions: dict[int, dict[str, object]] = {}
        self._progression_records: dict[int, tuple[ProgressionActionRecord, ...]] = {}

    async def reconcile(self, project) -> CampaignSnapshot:
        tasks, assets, campaigns = await asyncio.gather(
            self._tasks.list_for_project(project.id),
            self._assets.list_for_project(project.id),
            self._campaigns.list_for_project(project.id),
        )
        artifact_cursors = None
        if self._artifact_state is not None:
            artifact_cursors = {
                campaign.id: await _await(self._artifact_state.cursors(project.id, campaign.id))
                for campaign in campaigns if campaign.stopped_at is None
            }
        if artifact_cursors is None:
            observation = await _await(self._containers.reconcile(project, campaigns, assets))
        else:
            observation = await _await(
                self._containers.reconcile(project, campaigns, assets, artifact_cursors)
            )
        if not isinstance(observation, ContainerObservation):
            raise TypeError("container reconciliation must return a ContainerObservation")
        if self._cpu_counters is not None and observation.progress:
            cumulative = []
            for item in observation.progress:
                value = await self._cpu_counters.cumulative_cpu_seconds(
                    item.campaign_id, item.container_id, item.cpu_seconds,
                )
                cumulative.append(replace(item, cpu_seconds=value))
            cumulative_by_campaign = {item.campaign_id: item.cpu_seconds for item in cumulative}
            evidence = tuple(
                dict(item, cpu_seconds=cumulative_by_campaign[item["campaign_id"]])
                if item.get("provenance") == "docker_campaign_monitor"
                and item.get("campaign_id") in cumulative_by_campaign
                else item
                for item in observation.evidence
            )
            observation = replace(
                observation, progress=tuple(cumulative), evidence=evidence,
            )
        processing_evidence: list[dict] = []
        processing_corpus = False
        processing_crashes = False
        processing_failures: set[int] = set()
        if self._evidence_processor is not None:
            from backend.services.campaigns.production_evidence import CampaignProcessingResult

            campaign_by_id = {campaign.id: campaign for campaign in campaigns}
            for progress in observation.progress:
                campaign = campaign_by_id.get(progress.campaign_id)
                if campaign is None:
                    raise ValueError("observed campaign is absent from persisted project state")
                try:
                    result = await _await(self._evidence_processor.process(
                        project=project,
                        campaign=campaign,
                        invocation=self._invocations.load(project.id, campaign.id),
                        progress=progress,
                        assets=tuple(assets),
                    ))
                    if not isinstance(result, CampaignProcessingResult):
                        raise TypeError("campaign evidence processor returned an invalid result")
                except Exception as error:
                    processing_failures.add(campaign.id)
                    processing_evidence.append({
                        "evidence_id": f"campaign-processing-error:{campaign.id}:{type(error).__name__}",
                        "project_id": project.id,
                        "campaign_id": campaign.id,
                        "error_type": type(error).__name__,
                        "provenance": "deterministic_campaign_artifact_processing",
                        "trusted_instructions": False,
                    })
                    if self._events is not None:
                        await self._events.append(project.id, "debug", {
                            "event": "campaign.artifact_processing_failed",
                            "campaign_id": campaign.id,
                            "error_type": type(error).__name__,
                        })
                    continue
                processing_corpus = result.corpus_opportunity or processing_corpus
                processing_crashes = result.replayed_crash or processing_crashes
                processing_evidence.extend(result.evidence)
                if self._artifact_state is not None and progress.next_artifact_cursors:
                    await _await(self._artifact_state.advance_cursors(
                        project.id, campaign.id, progress.next_artifact_cursors,
                    ))
        self._observations[project.id] = observation
        self._persisted_campaigns[project.id] = tuple(campaigns)
        self._persisted_assets[project.id] = {asset.id: asset for asset in assets}
        contexts = (
            await self._campaign_contexts.list_contexts_for_project(project.id)
            if self._campaign_contexts is not None else {}
        )
        self._contexts[project.id] = contexts
        heartbeat = getattr(self._campaigns, "record_heartbeat", None)
        heartbeat_changed = False
        if heartbeat is not None:
            for progress in observation.progress:
                heartbeat_changed = bool(
                    await _await(heartbeat(progress.campaign_id, progress.heartbeat_at))
                ) or heartbeat_changed
        if heartbeat_changed and self._events is not None:
            await self._events.append(project.id, "events", {"name": "campaigns"})
        task_by_name = {task.name: task for task in tasks}
        initial_complete = _INITIAL_TASKS.issubset(task_by_name) and all(
            task_by_name[name].finished_at is not None and task_by_name[name].error is None
            for name in _INITIAL_TASKS
        )
        active_campaigns = [
            campaign for campaign in campaigns
            if campaign.id in observation.active_campaign_ids and campaign.stopped_at is None
        ]
        deadlines = [
            campaign.next_review_after for campaign in active_campaigns
            if campaign.next_review_after is not None
        ]
        state = tuple(
            (asset.id, asset.content_hash, asset.validated_at, asset.error) for asset in assets
        ) + tuple(
            (campaign.id, campaign.stopped_at, campaign.error) for campaign in campaigns
        )
        previous_state = self._campaign_state.get(project.id)
        self._campaign_state[project.id] = state
        context_evidence = tuple({
            "evidence_id": f"campaign-context:{project.id}:{campaign_id}",
            "project_id": project.id,
            "campaign_id": campaign_id,
            "configuration_purpose": value["configuration_purpose"],
            "retirement_reason": value["retirement_reason"],
            "provenance": "persisted_campaign_context",
            "trusted_instructions": False,
        } for campaign_id, value in sorted(contexts.items()))
        repository_evidence = tuple(self._discovery.evidence(project.id))
        progression_evidence: list[dict] = []
        progression_actions: dict[str, object] = {}
        progression_records: list[ProgressionActionRecord] = []
        campaigns_by_id = {campaign.id: campaign for campaign in campaigns}
        for progress in observation.progress:
            campaign = campaigns_by_id.get(progress.campaign_id)
            if campaign is None:
                raise ValueError("observed campaign is absent from persisted project state")
            recommendation = self._progression.next_recommendation(
                project_id=project.id,
                worker_count=project.worker_count,
                engine=campaign.engine,
                progress=progress,
                initial_complete=initial_complete,
                unhealthy=(
                    progress.campaign_id in observation.unhealthy_campaign_ids
                    or progress.campaign_id in processing_failures
                ),
                repository_evidence=(*processing_evidence, *repository_evidence),
                campaign_contexts={
                    candidate.id: contexts[candidate.id]
                    for candidate in campaigns
                    if (
                        candidate.id in contexts
                        and candidate.target_asset_id == campaign.target_asset_id
                        and candidate.error is None
                    )
                },
            )
            if recommendation is not None:
                progression_evidence.append(recommendation.as_dict())
                progression_actions[recommendation.evidence_id] = recommendation.action
                if recommendation.action.name in {
                    "enable dictionary", "try configuration", "enable grammar mutator",
                }:
                    progression_records.append(ProgressionActionRecord(
                        action_id=recommendation.evidence_id,
                        project_id=project.id,
                        base_campaign_id=campaign.id,
                        target_asset_id=campaign.target_asset_id,
                        action_name=recommendation.action.name,
                        evidence_ids=recommendation.action.evidence_ids,
                        arguments=recommendation.action.arguments,
                        environment=recommendation.action.environment,
                        detail=recommendation.action.detail,
                        dictionary_content=recommendation.dictionary_content,
                    ))
        self._progression_actions[project.id] = progression_actions
        self._progression_records[project.id] = tuple(progression_records)
        evidence = (
            tuple(processing_evidence)
            + tuple(progression_evidence)
            + repository_evidence
            + context_evidence
            + observation.evidence
        )
        if len(evidence) > _MAX_REVIEW_EVIDENCE:
            evidence = evidence[:_MAX_REVIEW_EVIDENCE]
        self._review_evidence[project.id] = evidence
        progression_names = {
            action.name for action in progression_actions.values()
        }
        return CampaignSnapshot(
            evidence_ids=tuple(dict.fromkeys(
                item["evidence_id"] for item in evidence
                if isinstance(item.get("evidence_id"), str) and item["evidence_id"].strip()
            )),
            active_workers=len(active_campaigns),
            initial_supervision_complete=initial_complete,
            review_due=any(deadline <= self._now() for deadline in deadlines),
            next_review_after=min(deadlines) if deadlines else None,
            corpus_opportunity=(
                processing_corpus or "enable dictionary" in progression_names
            ),
            replayed_crash=processing_crashes,
            unhealthy_worker=bool(observation.unhealthy_campaign_ids or processing_failures),
            documented_configuration="try configuration" in progression_names,
            system_gap="prepare component gap target" in progression_names,
            free_slots=max(project.worker_count - len(active_campaigns), 0),
            material_change=(
                previous_state is not None and previous_state != state
            ) or processing_corpus or processing_crashes or bool(
                progression_names - {
                    "enable dictionary", "try configuration", "prepare component gap target",
                }
            ),
        )

    async def review_context(self, project, _snapshot: CampaignSnapshot) -> AgentContext:
        context = self._discovery.context(project.id)
        if context.commit_sha != project.commit_sha:
            raise ValueError("agent context does not match the current project commit")
        return context

    async def review_evidence(self, project, _snapshot, _trigger) -> list[dict]:
        return [dict(item) for item in self._review_evidence.get(project.id, ())]

    def progression_actions(self, project_id: int) -> tuple[ProgressionActionRecord, ...]:
        return self._progression_records.get(project_id, ())

    async def pause(self, project_id: int) -> None:
        await self._stop_observed(project_id)

    async def stop_campaigns(self, project, _evidence_ids) -> None:
        await self._stop_observed(project.id, project)

    async def resume(self, project) -> None:
        campaigns = await self._active_campaigns(project.id)
        for campaign in campaigns:
            await _await(self._containers.start_exact(project, campaign))

    async def verify_resume(self, project) -> None:
        context = self._discovery.context(project.id)
        if context.commit_sha != project.commit_sha:
            raise ValueError("repository commit changed before campaign resume")
        campaigns = await self._active_campaigns(project.id)
        await _await(self._containers.verify_exact(project, campaigns))

    async def enforce_worker_count(self, project, overflow: int) -> None:
        if type(overflow) is not int or overflow < 0:
            raise ValueError("worker overflow must be a non-negative integer")
        running = set(self._observations.get(project.id, ContainerObservation()).active_campaign_ids)
        campaigns = sorted(
            (
                item for item in await self._active_campaigns(project.id)
                if item.id in running
            ),
            key=lambda item: (float(getattr(item, "cpu_seconds", 0.0)), -item.id),
        )
        for campaign in campaigns[:overflow]:
            await _await(self._containers.stop_exact(project, campaign))
            stopped = await _await(self._campaigns.stop_for_worker_limit(
                project.id, campaign.id, "worker limit retained higher-investment campaigns",
            ))
            if stopped is not True:
                raise RuntimeError("worker-limit campaign identity changed before persistence")
        if campaigns[:overflow] and self._events is not None:
            await self._events.append(project.id, "events", {"name": "campaigns"})

    async def schedule_next_review(self, project, deadline, reason: str) -> None:
        changed = await _await(self._campaigns.schedule_next_reviews(
            project.id, deadline, reason,
        ))
        if changed and self._events is not None:
            await self._events.append(project.id, "events", {"name": "campaigns"})

    async def progress(self, project, record: ProgressionActionRecord):
        """Start one configuration-only sibling without rebuilding its exact target image."""
        if not isinstance(record, ProgressionActionRecord) or record.project_id != project.id:
            raise ValueError("progression action belongs to another project")
        if not valid_replay_environment(record.environment):
            raise ValueError("progression action replay environment is invalid")
        if self._invocations is None:
            raise ValueError("campaign invocation store is unavailable")
        if self._progression_assets is None:
            raise ValueError("progression asset publisher is unavailable")
        base = await self._campaigns.get(record.base_campaign_id)
        if (
            base is None
            or base.project_id != project.id
            or base.target_asset_id != record.target_asset_id
            or base.stopped_at is not None
        ):
            raise ValueError("progression base campaign identity changed")
        existing = await self._campaigns.get_progression(record.action_id)
        observed = self._observations.get(project.id, ContainerObservation())
        if existing is None and len(observed.active_campaign_ids) >= project.worker_count:
            raise ValueError("progression requires one free project worker slot")
        invocation = _progression_invocation(
            self._invocations.load(project.id, base.id), record,
        )
        configuration_asset = await _await(self._progression_assets.publish(
            self._discovery.context(project.id), base, record,
        ))
        campaign = await self._campaigns.create_progression(
            action_id=record.action_id,
            project_id=project.id,
            base_campaign_id=base.id,
            target_asset_id=base.target_asset_id,
            configuration_asset_id=configuration_asset.id,
            engine=base.engine,
            next_review_after=self._now() + timedelta(minutes=5),
            next_review_reason="initial campaign supervision",
            configuration_purpose=record.key,
        )
        files = {}
        if record.dictionary_content is not None:
            files["tokens.dict"] = record.dictionary_content.encode("utf-8")
        try:
            await self._invocations.clone_variant(
                project.id, base.id, campaign.id, invocation,
                configuration_files=files,
                coverage_arguments=(
                    record.arguments if record.action_name == "try configuration" else ()
                ),
                coverage_environment=(
                    record.environment if record.action_name == "try configuration" else ()
                ),
                configuration_asset_id=configuration_asset.id,
            )
            await _await(self._containers.start_exact(project, campaign))
            cleared = await _await(self._campaigns.clear_progression_error(
                record.action_id, campaign.id,
            ))
            if cleared is not True:
                raise RuntimeError("progression campaign error identity changed before recovery")
        except BaseException as error:
            message = (
                "campaign progression was cancelled"
                if isinstance(error, asyncio.CancelledError)
                else (str(error) or type(error).__name__)
            )
            try:
                recorded = await _await(self._campaigns.record_progression_error(
                    record.action_id, campaign.id, message[:2_000],
                ))
                if recorded is not True:
                    raise RuntimeError("progression campaign identity changed before error persistence")
            except BaseException as persistence_error:
                error.add_note(f"progression error persistence also failed: {persistence_error}")
            raise
        if self._events is not None:
            await self._events.append(project.id, "events", {"name": "campaigns"})
        return campaign

    async def retire(self, project, record: RetirementActionRecord) -> str:
        if not isinstance(record, RetirementActionRecord) or record.project_id != project.id:
            raise ValueError("retirement action belongs to another project")
        campaign, retained = await asyncio.gather(
            self._campaigns.get(record.campaign_id),
            self._campaigns.get(record.retained_campaign_id),
        )
        if campaign is None or retained is None:
            raise ValueError("retirement campaign identity is unavailable")
        self._validate_retirement_campaign(project, campaign, record.campaign_id, record.strategy_asset_id)
        self._validate_retirement_campaign(
            project, retained, record.retained_campaign_id, record.retained_strategy_asset_id,
        )
        if campaign.stopped_at is not None or retained.stopped_at is not None:
            raise ValueError("retirement requires two active campaign records")
        await _await(self._containers.stop_exact(project, campaign))
        stopped = await self._campaigns.stop_redundant(
            project_id=record.project_id,
            campaign_id=record.campaign_id,
            strategy_asset_id=record.strategy_asset_id,
            retained_campaign_id=record.retained_campaign_id,
            retained_strategy_asset_id=record.retained_strategy_asset_id,
            retirement_reason=record.reason,
        )
        if stopped is not True:
            raise RuntimeError("retirement identity changed before persistence")
        if self._events is not None:
            await self._events.append(project.id, "events", {"name": "campaigns"})
        return record.action_id

    async def apply_cpu_checkpoint(self, project, _snapshot) -> None:
        """Account exact observed CPU against persisted clean reachability and checkpoint it."""
        if self._exposure is None or self._coverage_history is None or self._invocations is None:
            return
        progress_by_id = {
            item.campaign_id: item
            for item in self._observations.get(project.id, ContainerObservation()).progress
        }
        assets = self._persisted_assets.get(project.id, {})
        durable_change = False
        for campaign in self._persisted_campaigns.get(project.id, ()):
            progress = progress_by_id.get(campaign.id)
            if progress is None or campaign.stopped_at is not None:
                continue
            try:
                strategy_asset_id, reached = await self._coverage_history.reached_lines(
                    project, campaign,
                )
            except KeyError:
                continue
            allowed_strategies = {campaign.target_asset_id, campaign.configuration_asset_id}
            if strategy_asset_id not in allowed_strategies:
                raise ValueError("clean coverage strategy does not match its campaign")
            compatibility = self._compatibility_group(
                project, campaign, assets, self._invocations.load(project.id, campaign.id),
            )
            exposure_changed = await self._exposure.apply(
                campaign.id, progress.cpu_seconds, reached,
            )
            crash_group_ids = (
                await self._crash_groups.groups_for_campaign(campaign.id)
                if self._crash_groups is not None else ()
            )
            context = self._contexts.get(project.id, {}).get(campaign.id)
            checkpoint_changed = await self._coverage_history.append(
                project_id=project.id,
                campaign_id=campaign.id,
                strategy_asset_id=strategy_asset_id,
                commit_sha=project.commit_sha,
                compatibility_group_id=compatibility,
                observed_cpu_seconds=progress.cpu_seconds,
                reached_lines=reached,
                configuration_purpose=(
                    context["configuration_purpose"] if context is not None else None
                ),
                crash_group_ids=crash_group_ids,
                crash_evidence_complete=progress.crash_files == 0,
            )
            durable_change = bool(exposure_changed or checkpoint_changed) or durable_change
        if durable_change and self._events is not None:
            await self._events.append(project.id, "events", {"name": "campaigns"})

    async def retirement_candidates(self, project, _snapshot):
        """Compare only persisted, identity-compatible clean checkpoint histories."""
        if self._coverage_history is None:
            return ()
        histories = await self._coverage_history.histories(project.id)
        return tuple(self._overlap.compare(histories))

    async def wait_for_change(self, _project_id: int, signal: asyncio.Event, deadline) -> None:
        timeout = self._monitor_interval_seconds
        if deadline is not None:
            timeout = min(timeout, max((deadline - self._now()).total_seconds(), 0.0))
        try:
            async with asyncio.timeout(timeout):
                await signal.wait()
        except TimeoutError:
            pass

    async def _active_campaigns(self, project_id: int):
        return [
            campaign for campaign in await self._campaigns.list_for_project(project_id)
            if campaign.stopped_at is None and campaign.error is None
        ]

    async def _stop_observed(self, project_id: int, project=None) -> None:
        observation = self._observations.get(project_id, ContainerObservation())
        if project is None:
            context = self._discovery.context(project_id)
            project = type("ResolvedProject", (), {
                "id": project_id, "commit_sha": context.commit_sha,
            })()
        campaigns = {
            campaign.id: campaign for campaign in await self._active_campaigns(project_id)
        }
        for campaign_id in observation.active_campaign_ids:
            campaign = campaigns.get(campaign_id)
            if campaign is not None:
                await _await(self._containers.stop_exact(project, campaign))

    @staticmethod
    def _validate_retirement_campaign(project, campaign, campaign_id: int, strategy_id: int) -> None:
        strategy_ids = {campaign.target_asset_id}
        if campaign.configuration_asset_id is not None:
            strategy_ids.add(campaign.configuration_asset_id)
        if (
            campaign.id != campaign_id
            or campaign.project_id != project.id
            or strategy_id not in strategy_ids
        ):
            raise ValueError("retirement campaign strategy identity changed")

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("campaign runtime clock must be timezone-aware")
        return value

    @staticmethod
    def _compatibility_group(project, campaign, assets, invocation) -> str:
        target = assets.get(campaign.target_asset_id)
        configuration = assets.get(campaign.configuration_asset_id)
        if (
            target is None or getattr(target, "validated_at", None) is None
            or getattr(target, "error", None) is not None
            or campaign.configuration_asset_id is not None and (
                configuration is None or getattr(configuration, "validated_at", None) is None
                or getattr(configuration, "error", None) is not None
            )
        ):
            raise ValueError("campaign compatibility requires validated target and configuration assets")
        validate_invocation(invocation)
        input_contract = json.dumps({
            "engine": invocation.engine,
            "command": list(invocation.command),
            "environment": dict(sorted(invocation.environment.items())),
            "timeout_ms": invocation.timeout_ms,
            "memory_limit_mb": invocation.memory_limit_mb,
        }, sort_keys=True, separators=(",", ":"))
        fields = (
            project.commit_sha,
            str(target.content_hash),
            sha256(input_contract.encode()).hexdigest(),
            str(configuration.content_hash) if configuration is not None else "none",
            invocation.image_id,
        )
        return sha256("\0".join(fields).encode()).hexdigest()


async def _await(value):
    return await value if inspect.isawaitable(value) else value


def _progression_invocation(
    invocation: ContainerInvocation, record: ProgressionActionRecord,
) -> ContainerInvocation:
    validate_invocation(invocation)
    command = list(invocation.command)
    environment = dict(invocation.environment)
    if record.action_name == "enable dictionary":
        if invocation.engine == "afl":
            separator = command.index("--")
            if "-x" in command[:separator]:
                raise ValueError("base AFL campaign already uses a dictionary")
            command[separator:separator] = ["-x", "/campaign/config/tokens.dict"]
        elif invocation.engine == "libfuzzer":
            if any(value.startswith("-dict=") for value in command):
                raise ValueError("base libFuzzer campaign already uses a dictionary")
            command.append("-dict=/campaign/config/tokens.dict")
        else:
            raise ValueError("dictionary progression requires a supported engine")
    elif record.action_name == "try configuration":
        if invocation.engine == "afl":
            command.extend(record.arguments)
        elif invocation.engine == "libfuzzer":
            corpus_index = command.index("/campaign/corpus")
            command[corpus_index:corpus_index] = list(record.arguments)
        else:
            raise ValueError("configuration progression requires a supported engine")
        environment.update(dict(record.environment))
    elif record.action_name == "enable grammar mutator":
        if invocation.engine != "afl":
            raise ValueError("grammar progression requires AFL++")
        environment.update(dict(record.environment))
    else:
        raise ValueError("progression action does not have deterministic invocation mechanics")
    result = replace(invocation, command=command, environment=environment)
    validate_invocation(result)
    return result


def _count_files(
    root: int, parts: tuple[str, ...], limit: int, *, ignored: frozenset[str] = frozenset(),
) -> int:
    """Count regular files without following links; a missing engine directory is empty."""
    descriptor = os.dup(root)
    try:
        for part in parts:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor,
                )
            except FileNotFoundError:
                return 0
            os.close(descriptor)
            descriptor = child
        count = 0
        for name in os.listdir(descriptor):
            if name in ignored:
                continue
            details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISREG(details.st_mode):
                count += 1
            elif not stat.S_ISDIR(details.st_mode):
                raise ValueError("campaign output contains an unsafe entry")
            if count > limit:
                raise OverflowError("campaign output file count exceeds its bound")
        return count
    finally:
        os.close(descriptor)
