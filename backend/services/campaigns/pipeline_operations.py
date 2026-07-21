"""Execute immutable manager-selected pipeline actions through typed adapters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass, replace
from hashlib import sha256
import inspect
import json
from typing import Mapping

from backend.agents.outputs.campaign_review import PipelineOperationRecord
from backend.agents.tools.generated_assets import read_asset_file
from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation


@dataclass(frozen=True)
class PipelineOperationResult:
    action_id: str
    evidence_id: str
    operation: str
    summary: str
    asset_hashes: tuple[tuple[str, str], ...] = ()
    image_ids: tuple[str, ...] = ()


class TargetProposalPipelineAdapter:
    """Bind build/probe execution to the exact promoted proposal record."""

    def __init__(self, preparation, operation: str):
        if operation not in {"build", "probe"}:
            raise ValueError("target pipeline adapter operation is invalid")
        self._preparation = preparation
        self._operation = operation

    async def execute(self, project, record: PipelineOperationRecord):
        if record.operation != self._operation or record.target_proposal is None:
            raise ValueError("target pipeline action does not match its typed adapter")
        return await _await(self._preparation.prepare(project, record.target_proposal))


class CampaignArtifactPipelineAdapter:
    """Resolve exact persisted replay/coverage inputs and call production processing."""

    def __init__(self, *, operation, campaigns, assets, invocations, progress, processor):
        if operation not in {"replay", "coverage"}:
            raise ValueError("campaign artifact adapter operation is invalid")
        self._operation = operation
        self._campaigns = campaigns
        self._assets = assets
        self._invocations = invocations
        self._progress = progress
        self._processor = processor

    async def execute(self, project, record: PipelineOperationRecord):
        snapshot = record.campaign_snapshot
        if record.operation != self._operation or snapshot is None:
            raise ValueError("campaign pipeline action does not match its typed adapter")
        campaign = await _await(self._campaigns.get(snapshot.campaign_id))
        if (
            campaign is None
            or campaign.project_id != project.id
            or campaign.target_asset_id != snapshot.target_asset_id
            or campaign.configuration_asset_id != snapshot.configuration_asset_id
        ):
            raise ValueError("pipeline campaign identity changed before execution")
        progress = await _await(self._progress.pipeline_progress(project.id, campaign.id))
        expected = tuple(
            (item.kind, item.relative_path, item.content_sha256, item.size_bytes)
            for item in snapshot.artifacts
        )
        current = tuple(
            (item.kind, item.relative_path, item.content_sha256, item.size_bytes)
            for item in progress.artifacts
            if item.kind == ("crash" if self._operation == "replay" else "corpus")
        )
        if progress.evidence_id != snapshot.progress_evidence_id or current != expected:
            raise ValueError("pipeline campaign artifact snapshot changed before execution")
        selected = tuple(CampaignArtifactObservation(*value) for value in expected)
        bounded_progress = replace(progress, artifacts=selected, next_artifact_cursors=())
        assets = tuple(await _await(self._assets.list_for_project(project.id)))
        invocation = self._invocations.load(project.id, campaign.id)
        return await _await(self._processor.process(
            project=project,
            campaign=campaign,
            invocation=invocation,
            progress=bounded_progress,
            assets=assets,
        ))


class PipelineOperationService:
    """CAS-check and journal one selected action before invoking its typed adapter."""

    def __init__(
        self, *, build, probe, replay, coverage, discovery=None, events=None, journal=None,
    ):
        self._adapters = {
            "build": build,
            "probe": probe,
            "replay": replay,
            "coverage": coverage,
        }
        if any(getattr(type(value), "execute", None) is None for value in self._adapters.values()):
            raise TypeError("pipeline operations require four typed adapters")
        self._discovery = discovery
        self._events = events
        self._journal = journal

    async def execute(self, project, record: PipelineOperationRecord) -> PipelineOperationResult:
        self._validate(project, record)
        payload = record.model_dump(mode="json")
        journal_started = False
        try:
            if self._journal is not None:
                prior = self._journal.begin(project.id, record.action_id, payload)
                if prior is not None:
                    if prior.state == "completed" and prior.result is not None:
                        return self._result(prior.result)
                    raise RuntimeError("pipeline action has a durable failed result")
                journal_started = True
            asset_hashes = self._asset_hashes(project, record)
            output = await self._adapters[record.operation].execute(project, record)
            summary = self._summary(output)
            image_ids = self._image_ids(output)
            result = PipelineOperationResult(
                record.action_id,
                self._evidence_id(record, summary, asset_hashes, image_ids),
                record.operation,
                summary,
                asset_hashes,
                image_ids,
            )
            await self._record(project.id, record, result=result, error=None)
            if self._journal is not None:
                self._journal.complete(project.id, record.action_id, payload, asdict(result))
            return result
        except BaseException as error:
            await self._record(project.id, record, result=None, error=error)
            if self._journal is not None and journal_started:
                self._journal.fail(project.id, record.action_id, payload, {
                    "error_type": type(error).__name__,
                    "error": (str(error) or type(error).__name__)[:2_000],
                })
            raise

    def _asset_hashes(self, project, record) -> tuple[tuple[str, str], ...]:
        if tuple(path for path, _digest in record.draft_sha256s) != record.asset_paths:
            raise ValueError("pipeline draft snapshot does not match selected asset paths")
        if self._discovery is None:
            if record.asset_paths:
                raise ValueError("pipeline draft CAS requires project discovery")
            return ()
        context = self._discovery.context(project.id)
        values = tuple(
            (path, str(read_asset_file(context, path)["sha256"]))
            for path in record.asset_paths
        )
        if values != record.draft_sha256s:
            raise ValueError("pipeline draft changed after manager selection")
        return values

    async def _record(self, project_id, record, *, result, error) -> None:
        if self._events is None:
            return
        payload = {
            "event": "pipeline.operation",
            "action_id": record.action_id,
            "operation": record.operation,
            "worker_tool_call_id": record.worker_tool_call_id,
            "supporting_evidence_ids": list(record.evidence_ids),
            "status": "failed" if error is not None else "completed",
            "error_type": type(error).__name__ if error is not None else None,
            "error": (str(error) or type(error).__name__)[:2_000] if error is not None else None,
            "evidence_id": result.evidence_id if result is not None else None,
            "summary": result.summary if result is not None else None,
            "asset_hashes": dict(result.asset_hashes) if result is not None else {},
            "image_ids": list(result.image_ids) if result is not None else [],
            "trusted_instructions": False,
        }
        await _await(self._events.append(project_id, "debug", payload))
        await _await(self._events.append(project_id, "events", {"name": "campaigns"}))

    @staticmethod
    def _validate(project, record) -> None:
        if not isinstance(record, PipelineOperationRecord):
            raise TypeError("pipeline execution requires a validated operation record")
        if (
            type(getattr(project, "id", None)) is not int
            or record.project_id != project.id
            or getattr(project, "commit_sha", None) != record.project_commit_sha
        ):
            raise ValueError("pipeline operation project revision changed before execution")

    @staticmethod
    def _summary(output) -> str:
        if isinstance(output, Mapping):
            value = output.get("summary")
        else:
            value = getattr(output, "summary", None)
        if not isinstance(value, str) or not value.strip():
            value = type(output).__name__
        return value.strip()[:2_000]

    @classmethod
    def _image_ids(cls, output) -> tuple[str, ...]:
        values: set[str] = set()

        def add(value) -> None:
            if isinstance(value, str) and len(value) == 71 and value.startswith("sha256:"):
                if all(character in "0123456789abcdef" for character in value[7:]):
                    values.add(value)

        source = output if isinstance(output, Mapping) else (
            asdict(output) if is_dataclass(output) else getattr(output, "__dict__", {})
        )
        for key, value in source.items():
            if "image" in str(key).casefold():
                add(value)
        return tuple(sorted(values))

    @staticmethod
    def _evidence_id(record, summary, asset_hashes, image_ids) -> str:
        encoded = json.dumps({
            "action_id": record.action_id,
            "operation": record.operation,
            "summary": summary,
            "asset_hashes": asset_hashes,
            "image_ids": image_ids,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"pipeline-evidence:{record.project_id}:{sha256(encoded).hexdigest()}"

    @staticmethod
    def _result(value: dict) -> PipelineOperationResult:
        return PipelineOperationResult(
            action_id=value["action_id"],
            evidence_id=value["evidence_id"],
            operation=value["operation"],
            summary=value["summary"],
            asset_hashes=tuple(tuple(item) for item in value.get("asset_hashes", ())),
            image_ids=tuple(value.get("image_ids", ())),
        )


async def _await(value):
    return await value if inspect.isawaitable(value) else value
