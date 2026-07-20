"""Authoritative local trace records for the Activity and Debug views."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import fields as dataclass_fields, is_dataclass
import json
from uuid import uuid4

from agents import RunConfig
from agents.items import RunItemBase

from backend.services.observability.redaction import REDACTED, redact


MAX_TRACE_COLLECTION_ITEMS = 100_000
MAX_TRACE_DEPTH = 64
MAX_TRACE_RECORD_CHARS = 400_000


class TraceSerializationError(ValueError):
    """Raised rather than silently dropping part of a known trace payload."""


def _agent_identity(agent) -> dict[str, object] | None:
    if agent is None:
        return None
    return {
        "name": getattr(agent, "name", None),
        "model": getattr(agent, "model", None),
    }


def _run_item_payload(item: RunItemBase) -> dict[str, object]:
    """Preserve SDK run-item data while replacing runtime agent graph references with identity."""
    payload: dict[str, object] = {
        "type": getattr(item, "type", type(item).__name__),
        "agent": _agent_identity(getattr(item, "agent", None)),
        "raw_item": getattr(item, "raw_item", None),
    }
    excluded = {"agent", "raw_item", "type", "_agent_ref", "_source_agent_ref", "_target_agent_ref"}
    for field in dataclass_fields(item):
        if field.name in excluded:
            continue
        value = getattr(item, field.name)
        if field.name in {"source_agent", "target_agent"}:
            payload[field.name] = _agent_identity(value)
        else:
            payload[field.name] = value
    return payload


def _json_value(value, depth: int = 0, ancestors: set[int] | None = None):
    if depth >= MAX_TRACE_DEPTH:
        raise TraceSerializationError("trace payload nesting exceeds its safety limit")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    ancestors = set() if ancestors is None else ancestors
    identity = id(value)
    if identity in ancestors:
        raise TraceSerializationError("trace payload contains a reference cycle")
    ancestors.add(identity)
    try:
        if isinstance(value, RunItemBase):
            return _json_value(_run_item_payload(value), depth + 1, ancestors)
        if hasattr(value, "model_dump"):
            try:
                dumped = value.model_dump(mode="json")
            except TypeError:
                dumped = value.model_dump()
            return _json_value(dumped, depth + 1, ancestors)
        if is_dataclass(value) and not isinstance(value, type):
            dumped = {field.name: getattr(value, field.name) for field in dataclass_fields(value)}
            return _json_value(dumped, depth + 1, ancestors)
        if isinstance(value, Mapping):
            if len(value) > MAX_TRACE_COLLECTION_ITEMS:
                raise TraceSerializationError("trace mapping exceeds its safety item limit")
            result = {}
            for key, item in value.items():
                name = str(key)
                if name in result:
                    raise TraceSerializationError("trace mapping keys collide after JSON conversion")
                result[name] = _json_value(item, depth + 1, ancestors)
            return result
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            if len(value) > MAX_TRACE_COLLECTION_ITEMS:
                raise TraceSerializationError("trace collection exceeds its safety item limit")
            return [_json_value(item, depth + 1, ancestors) for item in value]
        if hasattr(value, "__dict__"):
            return _json_value(vars(value), depth + 1, ancestors)
        return f"<{type(value).__name__}>"
    finally:
        ancestors.remove(identity)


def _replace_secrets(value, secrets: tuple[str, ...]):
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, REDACTED)
        return value
    if isinstance(value, list):
        return [_replace_secrets(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _replace_secrets(item, secrets) for key, item in value.items()}
    return value


def _usage(value) -> dict[str, int]:
    if value is None:
        return {
            "requests": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cached_tokens": 0, "reasoning_tokens": 0,
        }
    input_details = getattr(value, "input_tokens_details", None)
    output_details = getattr(value, "output_tokens_details", None)
    return {
        "requests": int(getattr(value, "requests", 0) or 0),
        "input_tokens": int(getattr(value, "input_tokens", 0) or 0),
        "output_tokens": int(getattr(value, "output_tokens", 0) or 0),
        "total_tokens": int(getattr(value, "total_tokens", 0) or 0),
        "cached_tokens": int(getattr(input_details, "cached_tokens", 0) or 0),
        "reasoning_tokens": int(getattr(output_details, "reasoning_tokens", 0) or 0),
    }


def _combined_usage(responses) -> dict[str, int]:
    total = _usage(None)
    for response in responses or ():
        current = _usage(getattr(response, "usage", None))
        for key in total:
            total[key] += current[key]
    return total


def _response_metadata(responses) -> tuple[str | None, dict[str, int]]:
    responses = list(responses or ())
    response_id = next(
        (getattr(response, "response_id", None) for response in reversed(responses) if getattr(response, "response_id", None)),
        None,
    )
    return response_id, _combined_usage(responses)


def reasoning_summaries(value) -> list[str]:
    data = _json_value(value)
    summaries: list[str] = []

    def visit(item):
        if isinstance(item, dict):
            item_type = str(item.get("type", "")).casefold()
            if "reasoning" in item_type and "summary" in item:
                collect_text(item["summary"])
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    def collect_text(item):
        if isinstance(item, str) and item.strip():
            summaries.append(item)
        elif isinstance(item, dict):
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                summaries.append(text)
        elif isinstance(item, list):
            for child in item:
                collect_text(child)

    visit(data)
    return list(dict.fromkeys(summaries))


def web_citations(value) -> list[str]:
    data = _json_value(value)
    citations: list[str] = []

    def visit(item):
        if isinstance(item, dict):
            item_type = str(item.get("type", "")).casefold()
            url = item.get("url")
            if "citation" in item_type and isinstance(url, str) and url.startswith(("https://", "http://")):
                citations.append(url[:2_000])
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(data)
    return list(dict.fromkeys(citations))


class LocalTrace:
    """Write sanitized records to BigEye's project-owned append-only event store."""

    def __init__(
        self, event_store, project_id: int, trace_id: str | None = None,
        secret_values: tuple[str, ...] = (),
    ):
        self._event_store = event_store
        self.project_id = project_id
        self.trace_id = trace_id or "trace_" + uuid4().hex
        self._secrets = tuple(value for value in secret_values if isinstance(value, str) and value)

    def run_config(self, workflow_name: str) -> RunConfig:
        """Keep SDK tracing enabled but prevent sensitive model/tool payload export."""
        return RunConfig(
            workflow_name=workflow_name, trace_id=self.trace_id, group_id=f"project-{self.project_id}",
            trace_metadata={"project_id": str(self.project_id)}, trace_include_sensitive_data=False,
        )

    def sanitize(self, value):
        return _replace_secrets(redact(_json_value(value)), self._secrets)

    def debug(self, event: str, **fields) -> None:
        payload = self.sanitize({"event": event, "trace_id": self.trace_id, **fields})
        if self._event_store is None:
            return
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        if len(encoded) <= MAX_TRACE_RECORD_CHARS:
            self._event_store.append_sync(self.project_id, "debug", payload)
            return
        chunks = [encoded[index:index + MAX_TRACE_RECORD_CHARS] for index in range(0, len(encoded), MAX_TRACE_RECORD_CHARS)]
        for index, chunk in enumerate(chunks):
            self._event_store.append_sync(self.project_id, "debug", {
                "event": event + ".chunk", "trace_id": self.trace_id, "chunk_index": index,
                "chunk_count": len(chunks), "encoding": "json", "data": chunk,
            })

    def activity(self, decision, motivation, evidence_ids, next_review_reason) -> None:
        if self._event_store is not None:
            self._event_store.append_sync(self.project_id, "activity", self.sanitize({
                "decision": decision, "motivation": motivation, "evidence_ids": evidence_ids,
                "next_review_reason": next_review_reason,
            }))

    @staticmethod
    def _invocation_fields(invocation) -> dict[str, object]:
        if invocation is None:
            return {}
        arguments = getattr(invocation, "tool_arguments", None)
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                pass
        return {
            "parent_tool": getattr(invocation, "tool_name", None),
            "parent_tool_call_id": getattr(invocation, "tool_call_id", None),
            "parent_tool_arguments": arguments,
        }

    def record_result(
        self, agent, workflow_input, result, retry_count: int = 0,
        invocation=None, parent_id: str | None = None,
    ) -> None:
        responses = getattr(result, "raw_responses", ()) or ()
        response_id, usage = _response_metadata(responses)
        invocation = invocation or getattr(result, "agent_tool_invocation", None)
        invocation_fields = self._invocation_fields(invocation)
        if parent_id is not None and "parent_tool_call_id" not in invocation_fields:
            invocation_fields["parent_tool_call_id"] = parent_id
        self.debug(
            "workflow.result", response_id=response_id, **invocation_fields,
            agent=getattr(agent, "name", None), model=getattr(agent, "model", None),
            input=workflow_input, output=getattr(result, "final_output", None), usage=usage,
            retry_count=retry_count, new_items=getattr(result, "new_items", ()) or (),
            raw_responses=responses, reasoning_summaries=reasoning_summaries(responses),
            web_citations=web_citations(responses),
        )

    def retry(self, agent, error: Exception, invocation=None) -> None:
        self.debug(
            "specialist.retry", agent=getattr(agent, "name", None), model=getattr(agent, "model", None),
            retry_count=1, error={"type": type(error).__name__, "message": str(error)},
            **self._invocation_fields(invocation),
        )

    def error(self, agent, error: Exception, invocation=None) -> None:
        self.debug(
            "workflow.error", agent=getattr(agent, "name", None), model=getattr(agent, "model", None),
            error={"type": type(error).__name__, "message": str(error)},
            **self._invocation_fields(invocation),
        )
