"""Stable crash signatures and grouping fingerprints."""

from __future__ import annotations

import json
import re
from hashlib import sha256

from backend.fuzzing.crashes.replay import ReplayResult


_ADDRESS = re.compile(r"\b0x[0-9a-fA-F]+\b")
_FRAME_PREFIX = re.compile(r"^\s*#\d+\s+")
_WHITESPACE = re.compile(r"\s+")
_PROJECT_SOURCE = re.compile(
    r"(?<![/A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|rs|swift|m|mm):\d+(?::\d+)?"
)


def _text(value: str | None) -> str:
    return _WHITESPACE.sub(" ", (value or "").strip()).casefold()


def normalise_stack(stack: str) -> tuple[str, ...]:
    frames = []
    for raw in stack.splitlines()[:64]:
        source = _PROJECT_SOURCE.search(raw)
        if source is None:
            continue
        value = _FRAME_PREFIX.sub("", raw)
        value = _ADDRESS.sub("<address>", value)
        value = _text(value)
        if value and value not in frames:
            frames.append(value)
    return tuple(frames)


def _hash(payload: dict[str, object]) -> str:
    value = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(value).hexdigest()


def failure_signature(result: ReplayResult) -> str:
    """The failure identity minimisation must preserve (coverage is not required)."""
    return _hash({
        "signal": _text(result.signal),
        "sanitizer": _text(result.sanitizer),
        "source_location": _text(result.source_location),
        "stack": normalise_stack(result.stack),
    })


def crash_fingerprint(result: ReplayResult) -> str:
    """Group by stable failure identity; full coverage remains evidence, not identity."""
    return failure_signature(result)
