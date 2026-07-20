"""Injectable application service container."""

from dataclasses import dataclass
from pathlib import Path

from backend.repositories.project_repository import ProjectRepository
from backend.repositories.asset_repository import AssetRepository
from backend.repositories.campaign_repository import CampaignRepository
from backend.repositories.coverage_repository import CoverageRepository
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
from backend.services.campaigns.project_coordinator import PostgresProjectLock
from backend.agents.workflow import RepositoryAnalysisWorkflow
from backend.fuzzing.toolchain.deferred import DeferredToolchain
from backend.fuzzing.coverage.traceability import ProjectCheckoutRegistry, TraceabilityService
from backend.fuzzing.coverage.replay_verifier import (
    CleanCoverageTargetResolver,
    DeferredLlvmCoverage,
    FirstHitReplayVerifier,
)
from backend.fuzzing.crashes.artifacts import FindingArtifactStore
from backend.fuzzing.crashes.quarantine import CrashQuarantine


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
    coverage: object | None = None
    findings: object | None = None
    finding_artifacts: object | None = None

    async def close(self) -> None:
        close = getattr(self.recovery, "close", None)
        if close is not None:
            await close()


def build_services(pool, workspace: Path) -> Services:
    projects = ProjectRepository(pool)
    assets = AssetRepository(pool)
    campaigns = CampaignRepository(pool)
    coverage_repository = CoverageRepository(pool)
    findings = FindingRepository(pool)
    tasks = TaskRepository(pool)
    observability = ProjectEventStore(workspace)
    logs = TaskLogWriter(workspace, observability)
    clone = CloneRepositoryService(workspace, projects=projects, logs=logs)
    toolchain = DeferredToolchain(Path(__file__).parents[1] / "fuzzing/images/Dockerfile", logs)
    analysis = RepositoryAnalysisWorkflow(workspace, event_store=observability)
    executor = ExecuteProjectBackbone(projects, tasks, clone, toolchain, analysis, logs, workspace, observability)
    backbone = ProjectBackboneService(projects, executor, PostgresProjectLock(pool))
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
    )
    finding_artifacts = FindingArtifactStore(CrashQuarantine(workspace))
    return Services(
        project_creator=CreateProjectService(projects, backbone), projects=projects, tasks=tasks,
        logs=logs, events=ProjectEventStream(observability),
        settings=SettingsService(pool, toolchain.docker_available, toolchain.toolchain_available),
        recovery=backbone, analysis=AnalysisReader(workspace),
        project_settings=ProjectSettingsService(projects, backbone), observability=observability,
        campaigns=campaigns, coverage=coverage, findings=findings, finding_artifacts=finding_artifacts,
    )
