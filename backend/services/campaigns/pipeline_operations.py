"""Execute manager-selected bounded operations through deterministic services."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import inspect
import json
from pathlib import PurePosixPath
from typing import Mapping

from backend.agents.outputs.campaign_review import PipelineOperationRecord
from backend.agents.tools.generated_assets import read_asset_file


_COMPILING_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".rs",
    ".sh", ".patch", ".diff", ".cmake", ".mk",
})


@dataclass(frozen=True)
class PipelineOperationResult:
    """Durable evidence identity and bounded deterministic result summary."""

    action_id: str
    evidence_id: str
    operation: str
    summary: str
    asset_hashes: tuple[tuple[str, str], ...] = ()
    image_ids: tuple[str, ...] = ()


class PipelineOperationService:
    """Keep requests inert until a selected action reaches deterministic dispatch."""

    def __init__(
        self,
        *,
        target_preparation,
        replay,
        coverage,
        execution_slots=None,
        discovery=None,
        events=None,
    ):
        self._target_preparation = target_preparation
        self._replay = replay
        self._coverage = coverage
        self._execution_slots = execution_slots
        self._discovery = discovery
        self._events = events

    async def execute(self, project, record: PipelineOperationRecord) -> PipelineOperationResult:
        """Execute exactly one application-owned action selected by the manager."""
        self._validate(project, record)
        asset_hashes = self._asset_hashes(project, record)
        try:
            if self._compiles(record) and self._execution_slots is not None:
                async with self._execution_slots.compilation(
                    project, f"pipeline:{record.action_id}",
                ):
                    output = await self._dispatch(project, record)
            else:
                output = await self._dispatch(project, record)
            summary = self._summary(output)
            image_ids = self._image_ids(output)
            evidence_id = self._evidence_id(record, summary, asset_hashes, image_ids)
            result = PipelineOperationResult(
                record.action_id,
                evidence_id,
                record.operation,
                summary,
                asset_hashes,
                image_ids,
            )
            await self._record(project.id, record, result=result, error=None)
            return result
        except BaseException as error:
            await self._record(project.id, record, result=None, error=error)
            raise

    async def _dispatch(self, project, record: PipelineOperationRecord):
        service = {
            "build": self._target_preparation,
            "probe": self._target_preparation,
            "replay": self._replay,
            "coverage": self._coverage,
        }[record.operation]
        instance_values = getattr(service, "__dict__", {})
        method = instance_values.get("execute") if isinstance(instance_values, dict) else None
        if method is None and getattr(type(service), "execute", None) is not None:
            method = service.execute
        if method is None:
            method = instance_values.get("prepare") if isinstance(instance_values, dict) else None
        if method is None and getattr(type(service), "prepare", None) is not None:
            method = service.prepare
        if method is None and callable(service):
            method = service
        if method is None:
            raise TypeError(f"deterministic {record.operation} service is unavailable")
        value = method(project, record)
        return await value if inspect.isawaitable(value) else value

    @staticmethod
    def _compiles(record: PipelineOperationRecord) -> bool:
        if record.operation == "build":
            return True
        if record.operation != "probe":
            return False
        return any(PurePosixPath(path).suffix.casefold() in _COMPILING_SUFFIXES for path in record.asset_paths)

    def _asset_hashes(
        self, project, record: PipelineOperationRecord,
    ) -> tuple[tuple[str, str], ...]:
        if self._discovery is None or not record.asset_paths:
            return ()
        context = self._discovery.context(project.id)
        values = []
        for path in record.asset_paths:
            item = read_asset_file(context, path)
            values.append((path, str(item["sha256"])))
        return tuple(values)

    async def _record(self, project_id: int, record, *, result, error) -> None:
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
        value = self._events.append(project_id, "debug", payload)
        if inspect.isawaitable(value):
            await value
        value = self._events.append(project_id, "events", {
            "name": "pipeline-operation",
            "action_id": record.action_id,
            "status": payload["status"],
            "evidence_id": payload["evidence_id"],
        })
        if inspect.isawaitable(value):
            await value

    @staticmethod
    def _validate(project, record) -> None:
        if not isinstance(record, PipelineOperationRecord):
            raise TypeError("pipeline execution requires a validated operation record")
        project_id = getattr(project, "id", None)
        if type(project_id) is not int or project_id <= 0 or record.project_id != project_id:
            raise ValueError("pipeline operation does not belong to the selected project")

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
            if (
                isinstance(value, str)
                and len(value) == 71
                and value.startswith("sha256:")
                and all(character in "0123456789abcdef" for character in value[7:])
            ):
                values.add(value)

        if isinstance(output, Mapping):
            for key, value in output.items():
                if "image" in str(key).casefold():
                    add(value)
        else:
            for name in ("image_id", "target_image_id", "coverage_image_id", "clean_image_id"):
                add(getattr(output, name, None))
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
