"""Production replay of retained first-hit inputs in their exact clean coverage image."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from backend.fuzzing.coverage.llvm_coverage import (
    CoverageIntegrityError,
    DockerCoverageExecutor,
    LlvmCoverage,
)
from backend.fuzzing.docker.client import DockerClient


@dataclass(frozen=True)
class ResolvedCoverageTarget:
    id: int
    project_id: int
    commit_sha: str
    clean_image: str
    clean_image_id: str
    clean_content_hash: str
    clean_parent_image_id: str
    binary_path: str
    replay_command: tuple[str, ...]
    target_asset_id: int
    configuration_asset_id: int | None
    strategy_asset_id: int
    coverage_asset_id: int
    cpu_exposure_seconds: float
    repository_root: Path
    source_root: str = "/src"
    replay_environment: tuple[tuple[str, str], ...] = ()


class CleanCoverageTargetResolver:
    """Resolve host source and immutable clean-image inputs from application evidence."""

    def __init__(self, checkout_registry, campaigns, assets):
        self._checkouts = checkout_registry
        self._campaigns = campaigns
        self._assets = assets

    async def resolve(self, request) -> ResolvedCoverageTarget:
        campaign = await self._campaigns.get(request.campaign_id)
        if (
            campaign is None
            or campaign.project_id != request.project_id
            or campaign.target_asset_id != request.target_asset_id
            or campaign.configuration_asset_id != request.configuration_asset_id
        ):
            raise CoverageIntegrityError("first-hit replay does not match its persisted campaign target")
        asset_ids = {
            request.target_asset_id,
            request.strategy_asset_id,
            request.coverage_asset_id,
        }
        if request.configuration_asset_id is not None:
            asset_ids.add(request.configuration_asset_id)
        for asset_id in asset_ids:
            asset = await self._assets.get(asset_id)
            if (
                asset is None
                or asset.project_id != request.project_id
                or asset.validated_at is None
                or asset.error is not None
            ):
                raise CoverageIntegrityError("first-hit replay references an unvalidated project asset")
        checkout = await self._checkouts.resolve(request.project_id, request.commit_sha)
        command = request.replay_command
        if not isinstance(command, tuple) or not command:
            raise CoverageIntegrityError("first-hit replay command is invalid")
        return ResolvedCoverageTarget(
            id=request.campaign_id,
            project_id=request.project_id,
            commit_sha=request.commit_sha,
            clean_image=request.clean_image_id,
            clean_image_id=request.clean_image_id,
            clean_content_hash=request.clean_content_hash,
            clean_parent_image_id=request.clean_parent_image_id,
            binary_path=command[0],
            replay_command=command,
            target_asset_id=request.target_asset_id,
            configuration_asset_id=request.configuration_asset_id,
            strategy_asset_id=request.strategy_asset_id,
            coverage_asset_id=request.coverage_asset_id,
            cpu_exposure_seconds=0.0,
            repository_root=checkout.root,
            replay_environment=tuple(getattr(request, "replay_environment", ())),
        )


class DeferredLlvmCoverage:
    """Connect to Docker only for one replay and close that exact SDK client."""

    def __init__(self, workspace: Path, docker_client=None):
        self._workspace = Path(workspace)
        self._docker_client = docker_client or DockerClient()

    async def replay(self, target: ResolvedCoverageTarget, inputs: tuple[Path, ...]):
        client = await asyncio.to_thread(self._docker_client.connect)
        try:
            coverage = LlvmCoverage(
                client,
                DockerCoverageExecutor(client),
                self._workspace,
                max_inputs=1,
            )
            return await asyncio.to_thread(coverage.replay, target, inputs)
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                await asyncio.to_thread(close)


class FirstHitReplayVerifier:
    """Accept evidence only when one exact retained input reproduces the exact source line."""

    def __init__(self, target_resolver, coverage_replay):
        self._targets = target_resolver
        self._coverage = coverage_replay

    async def __call__(self, request) -> bool:
        target = await self._targets.resolve(request)
        snapshot = await self._coverage.replay(target, (request.testcase_path,))
        expected = (
            request.project_id,
            request.commit_sha,
            request.campaign_id,
            request.strategy_asset_id,
            request.target_asset_id,
            request.configuration_asset_id,
            request.coverage_asset_id,
            request.clean_image_id,
            request.clean_content_hash,
            request.clean_parent_image_id,
            request.replay_command,
        )
        actual = (
            snapshot.project_id,
            snapshot.commit_sha,
            snapshot.campaign_id,
            snapshot.strategy_asset_id,
            snapshot.target_asset_id,
            snapshot.configuration_asset_id,
            snapshot.coverage_asset_id,
            snapshot.clean_image_id,
            snapshot.clean_content_hash,
            snapshot.clean_parent_image_id,
            snapshot.replay_command,
        )
        if actual != expected or snapshot.build_kind != "clean":
            raise CoverageIntegrityError("first-hit replay changed immutable coverage identity")
        if not any(
            hit.source_path == request.source_path
            and hit.line_number == request.line_number
            and hit.testcase_sha256 == request.testcase_sha256
            for hit in snapshot.hits
        ):
            raise CoverageIntegrityError("retained testcase did not reproduce the exact clean source line")
        return True
