"""Prepare a validated target, publish its campaign, and start its exact worker."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import inspect
import shlex

from backend.agents.outputs.campaign_review import TargetProposalRecord
from backend.fuzzing.docker.client import DockerClient
from backend.fuzzing.engines.afl.command import AflCommand
from backend.fuzzing.engines.contracts import EngineSpec
from backend.fuzzing.engines.libfuzzer.command import LibFuzzerCommand


_INITIAL_REVIEW_DELAY = timedelta(minutes=5)
_SANITIZER_ENVIRONMENT = {
    "ASAN_OPTIONS": "abort_on_error=1:symbolize=0",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}
_SHELL_OPERATOR_TOKENS = frozenset({";", "|", "||", "&&", ">", ">>", "<", "<<", "2>", "2>>"})


class DeferredTargetPreparationGraph:
    """Connect to Docker only while the concrete target-preparation graph is active."""

    def __init__(self, service_factory, docker_client=None):
        if not callable(service_factory):
            raise TypeError("target preparation service factory must be callable")
        self._service_factory = service_factory
        self._docker_client = docker_client or DockerClient()

    async def prepare(self, project, proposal):
        client = await asyncio.to_thread(self._docker_client.connect)
        try:
            service = self._service_factory(client)
            result = service.prepare(project, proposal)
            return await result if inspect.isawaitable(result) else result
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                await asyncio.to_thread(close)


class CampaignTargetPreparation:
    """Publish only a concretely prepared target and start its exact campaign contract."""

    def __init__(
        self,
        *,
        preparation,
        campaigns,
        invocation_store,
        containers,
        events=None,
        clock=None,
    ):
        self._preparation = preparation
        self._campaigns = campaigns
        self._invocations = invocation_store
        self._containers = containers
        self._events = events
        self._clock = clock or (lambda: datetime.now(UTC))

    async def prepare(self, project, record: TargetProposalRecord):
        if not isinstance(record, TargetProposalRecord):
            raise TypeError("campaign preparation requires a validated target proposal record")
        prepared = await self._preparation.prepare(project, record)
        target_asset_id, configuration_asset_id, _coverage_asset_id = self._identity(
            project, prepared,
        )
        engine, invocation = self._invocation(record, prepared)
        campaign = await self._campaigns.create(
            project_id=project.id,
            target_asset_id=target_asset_id,
            configuration_asset_id=configuration_asset_id,
            engine=engine,
            next_review_after=self._now() + _INITIAL_REVIEW_DELAY,
            next_review_reason="initial campaign supervision",
            configuration_purpose=record.proposal.configuration,
        )
        try:
            await self._invocations.publish(
                project.id, campaign.id, invocation, prepared.probe_invocations,
            )
            await self._containers.start_exact(project, campaign)
        except BaseException as error:
            if isinstance(error, asyncio.CancelledError):
                message = "campaign preparation was cancelled"
            else:
                message = str(error) or type(error).__name__
            try:
                await self._campaigns.record_error(campaign.id, message[:2_000])
                await self._invalidate(project.id)
            except BaseException as cleanup_error:
                error.add_note(f"campaign publication cleanup also failed: {cleanup_error}")
            raise
        await self._invalidate(project.id)
        return campaign

    @staticmethod
    def _identity(project, prepared) -> tuple[int, int | None, int]:
        if (
            getattr(prepared, "project_id", None) != project.id
            or getattr(prepared, "commit_sha", None) != project.commit_sha
        ):
            raise ValueError("prepared target does not match the exact project commit")
        image_id = getattr(prepared, "target_image_id", None)
        if (
            not isinstance(image_id, str)
            or len(image_id) != 71
            or not image_id.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in image_id[7:])
        ):
            raise ValueError("prepared target image is not immutable")
        target_labels = getattr(getattr(prepared, "target_manifest", None), "labels", None)
        coverage_labels = getattr(getattr(prepared, "coverage_manifest", None), "labels", None)
        if not isinstance(target_labels, dict) or not isinstance(coverage_labels, dict):
            raise ValueError("prepared target layer provenance is unavailable")
        try:
            target_id = int(target_labels["bigeye.target-asset"])
            configuration_id = int(coverage_labels["bigeye.configuration-asset-id"])
            coverage_id = int(coverage_labels["bigeye.coverage-asset-id"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("prepared target asset provenance is invalid") from error
        if min(target_id, configuration_id, coverage_id) <= 0:
            raise ValueError("prepared target asset provenance is invalid")
        return target_id, configuration_id, coverage_id

    @staticmethod
    def _invocation(record: TargetProposalRecord, prepared):
        proposal = record.proposal
        try:
            command = tuple(shlex.split(proposal.run_command, posix=True))
        except ValueError as error:
            raise ValueError("target run command is not valid shell-free argv") from error
        if not command:
            raise ValueError("target run command is empty")
        if command[0].startswith("/opt/bigeye/") is False:
            raise ValueError("target run command must use an /opt/bigeye executable")
        if any(item in _SHELL_OPERATOR_TOKENS for item in command):
            raise ValueError("target run command cannot contain shell operators")
        if proposal.instance_type == "system-level":
            file_mode = any(item in {"{input}", "@@"} for item in command)
            target_command = tuple("@@" if item == "{input}" else item for item in command)
            spec = EngineSpec(
                engine="afl", image_id=prepared.target_image_id,
                target_command=target_command, input_mode="file" if file_mode else "stdin",
                corpus_path="/campaign/corpus", output_path="/campaign/output",
                role="main", sanitizer_environment=_SANITIZER_ENVIRONMENT,
                timeout_ms=1_000, memory_limit_mb=1_024,
            )
            return "afl", AflCommand.build(spec)
        if proposal.instance_type == "component-level":
            target_command = tuple(item for item in command if item not in {"{input}", "@@"})
            spec = EngineSpec(
                engine="libfuzzer", image_id=prepared.target_image_id,
                target_command=target_command, input_mode="inprocess",
                corpus_path="/campaign/corpus", output_path="/campaign/output",
                role="main", sanitizer_environment=_SANITIZER_ENVIRONMENT,
                timeout_ms=1_000, memory_limit_mb=1_024,
            )
            return "libfuzzer", LibFuzzerCommand.build(spec)
        raise ValueError("target proposal has an unsupported instance type")

    async def _invalidate(self, project_id: int) -> None:
        if self._events is not None:
            await self._events.append(project_id, "events", {"name": "campaigns"})

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("campaign preparation clock must be timezone-aware")
        return value
