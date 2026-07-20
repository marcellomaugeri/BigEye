"""Injectable application service container."""

from dataclasses import dataclass
from pathlib import Path

from backend.repositories.project_repository import ProjectRepository
from backend.repositories.asset_repository import AssetRepository
from backend.repositories.campaign_repository import CampaignRepository
from backend.repositories.campaign_artifact_repository import CampaignArtifactRepository
from backend.repositories.coverage_repository import CoverageRepository
from backend.repositories.coverage_checkpoint_repository import CoverageCheckpointRepository
from backend.repositories.finding_repository import FindingRepository
from backend.repositories.task_repository import TaskRepository
from backend.services.check_settings import SettingsService
from backend.services.projects.create_project import CreateProjectService
from backend.services.projects.clone_repository import CloneRepositoryService
from backend.services.projects.project_settings import ProjectSettingsService
from backend.services.read_analysis import AnalysisReader
from backend.services.run_project_backbone import ProjectBackboneService
from backend.services.observability.event_store import ProjectEventStore
from backend.services.observability.event_stream import ProjectEventStream
from backend.services.stream_task_output import TaskLogReader
from backend.services.stream_task_output import TaskLogWriter
from backend.services.execute_project_backbone import ExecuteProjectBackbone
from backend.services.campaigns.decision_executor import DecisionExecutor
from backend.services.campaigns.production_preparation import (
    CampaignTargetPreparation,
    DeferredTargetPreparationGraph,
)
from backend.services.campaigns.execution_slots import ProjectExecutionSlots
from backend.services.campaigns.production_runtime import (
    CampaignInvocationStore,
    DeferredCampaignContainers,
    ProjectDiscovery,
    RepositoryCampaignRuntime,
)
from backend.services.campaigns.production_evidence_factory import (
    DeferredCampaignEvidenceProcessor,
    ProductionCampaignEvidenceFactory,
)
from backend.services.campaigns.project_coordinator import PostgresProjectLock, ProjectCoordinator
from backend.services.campaigns.read_campaigns import CampaignReadService
from backend.agents.workflow import CampaignWorkflow, RepositoryAnalysisWorkflow
from backend.fuzzing.toolchain.deferred import DeferredToolchain
from backend.fuzzing.coverage.traceability import ProjectCheckoutRegistry, TraceabilityService
from backend.fuzzing.coverage.replay_verifier import (
    CleanCoverageTargetResolver,
    DeferredLlvmCoverage,
    FirstHitReplayVerifier,
)
from backend.fuzzing.crashes.artifacts import FindingArtifactStore
from backend.fuzzing.crashes.quarantine import CrashQuarantine
from backend.fuzzing.campaigns.production_factory import (
    DeferredRepositoryLayerBootstrap,
    ProductionTargetPreparationFactory,
)
from backend.services.initial_tasks import InitialTaskService
from backend.fuzzing.coverage.exposure import ExposureAccountant
from backend.fuzzing.docker.client import DockerClient
from backend.fuzzing.assets.store import AssetStore
from backend.services.campaigns.production_progression import ProgressionAssetPublisher


@dataclass
class Services:
    project_creator: object
    projects: object
    tasks: object
    logs: object
    events: object
    settings: object
    recovery: object
    analysis: object | None = None
    project_settings: object | None = None
    observability: object | None = None
    campaigns: object | None = None
    campaign_reader: object | None = None
    coverage: object | None = None
    findings: object | None = None
    finding_artifacts: object | None = None

    async def close(self) -> None:
        close = getattr(self.recovery, "close", None)
        if close is not None:
            await close()


def build_services(pool, workspace: Path) -> Services:
    workspace = Path(workspace)
    if workspace.is_symlink():
        raise ValueError("workspace root must not be a symlink")
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace = workspace.resolve(strict=True)
    projects = ProjectRepository(pool)
    assets = AssetRepository(pool)
    campaigns = CampaignRepository(pool)
    campaign_artifacts = CampaignArtifactRepository(pool)
    coverage_repository = CoverageRepository(pool)
    coverage_history = CoverageCheckpointRepository(pool, coverage_repository)
    findings = FindingRepository(pool)
    tasks = TaskRepository(pool)
    observability = ProjectEventStore(workspace)
    logs = TaskLogWriter(workspace, observability)
    clone = CloneRepositoryService(workspace, projects=projects, logs=logs)
    toolchain_dockerfile = Path(__file__).parents[1] / "fuzzing/images/Dockerfile"
    toolchain = DeferredToolchain(toolchain_dockerfile, logs)
    analysis = RepositoryAnalysisWorkflow(workspace, event_store=observability)
    repository_layer = DeferredRepositoryLayerBootstrap(
        workspace, toolchain_dockerfile, logs,
    )
    executor = ExecuteProjectBackbone(
        projects, tasks, clone, toolchain, analysis, logs, workspace, observability,
        repository_layer=repository_layer,
    )
    discovery = ProjectDiscovery(workspace)
    invocation_store = CampaignInvocationStore(workspace)
    execution_slots = ProjectExecutionSlots()
    campaign_containers = DeferredCampaignContainers(
        workspace, invocation_store=invocation_store, execution_slots=execution_slots,
    )
    checkout_registry = ProjectCheckoutRegistry(workspace, projects)
    replay_verifier = FirstHitReplayVerifier(
        CleanCoverageTargetResolver(checkout_registry, campaigns, assets),
        DeferredLlvmCoverage(workspace / "coverage-replay"),
    )
    coverage = TraceabilityService(
        workspace,
        coverage_repository,
        replay_verifier=replay_verifier,
        checkout_registry=checkout_registry,
        events=observability,
    )
    evidence_processor = DeferredCampaignEvidenceProcessor(
        ProductionCampaignEvidenceFactory(
            workspace=workspace,
            contracts=invocation_store,
            assets=assets,
            artifacts=campaign_artifacts,
            traceability=coverage,
            findings=findings,
            discovery=discovery,
            events=observability,
        ),
        DockerClient(),
    )
    campaign_runtime = RepositoryCampaignRuntime(
        tasks=tasks,
        assets=assets,
        campaigns=campaigns,
        discovery=discovery,
        containers=campaign_containers,
        events=observability,
        exposure=ExposureAccountant(coverage_repository),
        coverage_history=coverage_history,
        invocations=invocation_store,
        cpu_counters=campaigns,
        crash_groups=findings,
        campaign_contexts=campaigns,
        evidence_processor=evidence_processor,
        artifact_state=campaign_artifacts,
        progression_assets=ProgressionAssetPublisher(AssetStore(workspace, assets)),
        execution_slots=execution_slots,
    )
    campaign_manager = CampaignWorkflow(observability)
    preparation_graph = DeferredTargetPreparationGraph(
        ProductionTargetPreparationFactory(
            workspace=workspace,
            discovery=discovery,
            assets=assets,
            dockerfile=toolchain_dockerfile,
            events=observability,
        ),
    )
    campaign_preparation = CampaignTargetPreparation(
        preparation=preparation_graph,
        campaigns=campaigns,
        invocation_store=invocation_store,
        containers=campaign_containers,
        events=observability,
        execution_slots=execution_slots,
    )
    decision_executor = DecisionExecutor(
        campaign_preparation, campaign_control=campaign_runtime,
    )
    advisory_lock = PostgresProjectLock(pool)
    backbone = ProjectBackboneService(
        projects,
        executor,
        advisory_lock,
        coordinator_factory=lambda _project_id: ProjectCoordinator(
            projects=projects,
            bootstrap=executor,
            discovery=discovery,
            manager=campaign_manager,
            decision_executor=decision_executor,
            runtime=campaign_runtime,
            advisory_lock=advisory_lock,
            events=observability,
            execution_slots=execution_slots,
        ),
    )
    finding_artifacts = FindingArtifactStore(CrashQuarantine(workspace))
    return Services(
        project_creator=CreateProjectService(
            projects, backbone, InitialTaskService(repository_analysis=False),
        ), projects=projects, tasks=tasks,
        logs=logs, events=ProjectEventStream(observability),
        settings=SettingsService(pool, toolchain.docker_available, toolchain.toolchain_available),
        recovery=backbone, analysis=AnalysisReader(workspace),
        project_settings=ProjectSettingsService(
            projects, backbone, execution_slots=execution_slots,
        ), observability=observability,
        campaigns=campaigns, campaign_reader=CampaignReadService(campaigns, coverage_history),
        coverage=coverage, findings=findings, finding_artifacts=finding_artifacts,
    )
