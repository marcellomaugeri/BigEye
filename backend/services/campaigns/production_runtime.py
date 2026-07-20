"""Production adapters for deterministic campaign observation and exact container control."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
import inspect
import json
import os
from pathlib import Path
import stat
from hashlib import sha256
import math

from backend.agents.context import AgentContext
from backend.agents.outputs.campaign_review import RetirementActionRecord
from backend.fuzzing.discovery.inventory import RepositoryInventory
from backend.fuzzing.discovery.retrieval import EvidenceRetriever
from backend.fuzzing.docker.campaign_workspace import CampaignWorkspace
from backend.fuzzing.docker.client import DockerClient
from backend.fuzzing.docker.fuzz_container import FuzzCampaign, FuzzContainerService
from backend.fuzzing.docker.fuzz_contract import validate_invocation
from backend.fuzzing.engines.contracts import ContainerInvocation
from backend.fuzzing.coverage.overlap import OverlapAnalyzer
from backend.services.campaigns.wake_rules import CampaignSnapshot
from backend.services.projects.clone_repository import contained_path


_INITIAL_TASKS = frozenset({"repository clone", "LLVM toolchain preparation"})
_MAX_CONTAINER_EVIDENCE = 512
_MAX_REVIEW_EVIDENCE = 64
_MAX_INVOCATION_BYTES = 64 * 1024


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
        if set(self.unhealthy_campaign_ids) - set(self.active_campaign_ids):
            raise ValueError("unhealthy campaigns must be part of the active campaign set")
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

    def observe(self, client, project, campaign, identity, invocation) -> CampaignProgressObservation:
        container = client.containers.get(identity.container_id)
        statistics = container.stats(stream=False)
        try:
            total_usage = statistics["cpu_stats"]["cpu_usage"]["total_usage"]
        except (KeyError, TypeError) as error:
            raise ValueError("Docker campaign CPU statistics are incomplete") from error
        if type(total_usage) is not int or total_usage < 0:
            raise ValueError("Docker campaign CPU statistics are invalid")
        with self._workspace.open_campaign(project.id, campaign.id, create=False) as directory:
            if invocation.engine == "afl":
                queue = _count_files(directory.descriptor, ("output", "main", "queue"), 100_000)
                crashes = _count_files(
                    directory.descriptor, ("output", "main", "crashes"), 10_000,
                    ignored=frozenset({"README.txt"}),
                )
            else:
                queue = _count_files(directory.descriptor, ("corpus",), 100_000)
                crashes = _count_files(directory.descriptor, ("output",), 10_000)
        digest = sha256(
            f"{project.id}\0{campaign.id}\0{identity.container_id}\0{total_usage}\0{queue}\0{crashes}".encode()
        ).hexdigest()
        return CampaignProgressObservation(
            campaign.id, total_usage / 1_000_000_000, self._clock(), queue, crashes,
            f"campaign-progress:{campaign.id}:{digest}", identity.container_id,
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

    async def publish(
        self,
        project_id: int,
        campaign_id: int,
        invocation: ContainerInvocation,
        probe_invocations,
    ) -> None:
        validate_invocation(invocation)
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
                for value in seeds:
                    self._publish_exact(corpus, sha256(value).hexdigest(), value)
            finally:
                os.close(corpus)
                os.close(config)

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

    async def reconcile(self, project, campaigns) -> ContainerObservation:
        active = tuple(campaign for campaign in campaigns if campaign.stopped_at is None)
        if not active:
            return ContainerObservation()
        client = self._docker_client.connect()
        active_ids: list[int] = []
        unhealthy_ids: list[int] = []
        evidence: list[dict] = []
        progress: list[CampaignProgressObservation] = []
        try:
            service = self._service_factory(client, self._workspace)
            for campaign in active:
                active_ids.append(campaign.id)
                try:
                    invocation = self._invocations.load(project.id, campaign.id)
                    identity = service.recover(
                        self._fuzz_campaign(project, campaign),
                        invocation,
                    )
                    if identity is None:
                        unhealthy_ids.append(campaign.id)
                        state = "missing"
                    else:
                        state = identity.state
                        current = self._monitor.observe(
                            client, project, campaign, identity, invocation,
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
        finally:
            self._close(client)
        return ContainerObservation(
            tuple(active_ids), tuple(unhealthy_ids), tuple(evidence), tuple(progress),
        )

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


class RepositoryCampaignRuntime:
    """Reconcile persisted facts and perform only exact, reversible campaign controls."""

    def __init__(
        self, *, tasks, assets, campaigns, discovery, containers, events=None, clock=None,
        exposure=None, coverage_history=None, overlap=None, invocations=None,
        cpu_counters=None, crash_groups=None, campaign_contexts=None,
    ):
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
        self._observations: dict[int, ContainerObservation] = {}
        self._persisted_campaigns: dict[int, tuple] = {}
        self._persisted_assets: dict[int, dict[int, object]] = {}
        self._campaign_state: dict[int, tuple] = {}
        self._review_evidence: dict[int, tuple[dict, ...]] = {}
        self._contexts: dict[int, dict[int, dict[str, str | None]]] = {}

    async def reconcile(self, project) -> CampaignSnapshot:
        tasks, assets, campaigns = await asyncio.gather(
            self._tasks.list_for_project(project.id),
            self._assets.list_for_project(project.id),
            self._campaigns.list_for_project(project.id),
        )
        observation = await _await(self._containers.reconcile(project, campaigns))
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
        evidence = tuple(self._discovery.evidence(project.id)) + context_evidence + observation.evidence
        if len(evidence) > _MAX_REVIEW_EVIDENCE:
            evidence = evidence[:_MAX_REVIEW_EVIDENCE]
        self._review_evidence[project.id] = evidence
        return CampaignSnapshot(
            evidence_ids=tuple(dict.fromkeys(
                item["evidence_id"] for item in evidence
                if isinstance(item.get("evidence_id"), str) and item["evidence_id"].strip()
            )),
            active_workers=len(active_campaigns),
            initial_supervision_complete=initial_complete,
            review_due=any(deadline <= self._now() for deadline in deadlines),
            next_review_after=min(deadlines) if deadlines else None,
            unhealthy_worker=bool(observation.unhealthy_campaign_ids),
            free_slots=max(project.worker_count - len(active_campaigns), 0),
            material_change=previous_state is not None and previous_state != state,
        )

    async def review_context(self, project, _snapshot: CampaignSnapshot) -> AgentContext:
        context = self._discovery.context(project.id)
        if context.commit_sha != project.commit_sha:
            raise ValueError("agent context does not match the current project commit")
        return context

    async def review_evidence(self, project, _snapshot, _trigger) -> list[dict]:
        return [dict(item) for item in self._review_evidence.get(project.id, ())]

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
        campaigns = sorted(await self._active_campaigns(project.id), key=lambda item: item.id, reverse=True)
        for campaign in campaigns[:overflow]:
            await _await(self._containers.stop_exact(project, campaign))

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
        if deadline is None:
            await signal.wait()
            return
        timeout = max((deadline - self._now()).total_seconds(), 0.0)
        try:
            async with asyncio.timeout(timeout):
                await signal.wait()
        except TimeoutError:
            pass

    async def _active_campaigns(self, project_id: int):
        return [
            campaign for campaign in await self._campaigns.list_for_project(project_id)
            if campaign.stopped_at is None
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
