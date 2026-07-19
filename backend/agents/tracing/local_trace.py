"""Authoritative local trace records for the Activity and Debug views."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
import json
from uuid import uuid4

from agents import RunConfig

from backend.services.observability.redaction import REDACTED, redact


MAX_TRACE_STRING_CHARS = 32_000
MAX_TRACE_COLLECTION_ITEMS = 128
MAX_TRACE_DEPTH = 16
MAX_TRACE_RECORD_CHARS = 400_000


def _json_value(value, depth: int = 0):
    if depth >= MAX_TRACE_DEPTH:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_TRACE_STRING_CHARS]
    if isinstance(value, bytes):
        return value[:MAX_TRACE_STRING_CHARS].decode("utf-8", errors="replace")
    if hasattr(value, "model_dump"):
        try:
            return _json_value(value.model_dump(mode="json"), depth + 1)
        except TypeError:
            return _json_value(value.model_dump(), depth + 1)
    if is_dataclass(value) and not isinstance(value, type):
        return _json_value(asdict(value), depth + 1)
    if isinstance(value, Mapping):
        return {
            str(key)[:200]: _json_value(item, depth + 1)
            for key, item in list(value.items())[:MAX_TRACE_COLLECTION_ITEMS]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item, depth + 1) for item in list(value)[:MAX_TRACE_COLLECTION_ITEMS]]
    if hasattr(value, "__dict__"):
        return _json_value(vars(value), depth + 1)
    return f"<{type(value).__name__}>"


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
            summaries.append(item[:MAX_TRACE_STRING_CHARS])
        elif isinstance(item, dict):
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                summaries.append(text[:MAX_TRACE_STRING_CHARS])
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

    def activity(self, decision, motivation, evidence_ids, next_review_condition) -> None:
        if self._event_store is not None:
            self._event_store.append_sync(self.project_id, "activity", self.sanitize({
                "decision": decision, "motivation": motivation, "evidence_ids": evidence_ids,
                "next_review_condition": next_review_condition,
            }))

    def record_result(self, agent, workflow_input, result, retry_count: int = 0, parent_id: str | None = None) -> None:
        responses = getattr(result, "raw_responses", ()) or ()
        response_id, usage = _response_metadata(responses)
        self.debug(
            "workflow.result", response_id=response_id, parent_id=parent_id,
            agent=getattr(agent, "name", None), model=getattr(agent, "model", None),
            input=workflow_input, output=getattr(result, "final_output", None), usage=usage,
            retry_count=retry_count, new_items=getattr(result, "new_items", ()) or (),
            raw_responses=responses, reasoning_summaries=reasoning_summaries(responses),
            web_citations=web_citations(responses),
        )

    def retry(self, agent, error: Exception) -> None:
        self.debug(
            "specialist.retry", agent=getattr(agent, "name", None), model=getattr(agent, "model", None),
            retry_count=1, error={"type": type(error).__name__, "message": str(error)},
        )

    def error(self, agent, error: Exception) -> None:
        self.debug(
            "workflow.error", agent=getattr(agent, "name", None), model=getattr(agent, "model", None),
            error={"type": type(error).__name__, "message": str(error)},
        )
