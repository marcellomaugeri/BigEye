"""Stable crash signatures and grouping fingerprints."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import PurePosixPath

from backend.fuzzing.crashes.replay import ReplayResult


_ADDRESS = re.compile(r"\b0x[0-9a-fA-F]+\b")
_WHITESPACE = re.compile(r"\s+")
_PROJECT_SOURCE = re.compile(
    r"(?<![/A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|rs|swift|m|mm):\d+(?::\d+)?"
)
_SYMBOL = re.compile(r"(?:\bin\s+|!)([^\s(]+)")
_MODULE = re.compile(r"\(([^()\s]+)\)")
_OFFSET = re.compile(r"\+0x[0-9a-fA-F]+\Z")
_RUNTIME_FUNCTION = re.compile(
    r"^(?:__libc_start_main|abort|raise|start_thread|pthread_[A-Za-z0-9_]+|"
    r"__asan_[A-Za-z0-9_]+|__ubsan_[A-Za-z0-9_]+|__msan_[A-Za-z0-9_]+|"
    r"__tsan_[A-Za-z0-9_]+)$",
    re.IGNORECASE,
)
_RUNTIME_MODULE = re.compile(
    r"^(?:libc(?:\.|-)|libpthread(?:\.|-)|libasan(?:\.|-)|libubsan(?:\.|-)|"
    r"libmsan(?:\.|-)|libtsan(?:\.|-)|ld-linux|libsystem)",
    re.IGNORECASE,
)


def _text(value: str | None) -> str:
    return _WHITESPACE.sub(" ", (value or "").strip()).casefold()


def normalise_stack(stack: str) -> tuple[str, ...]:
    frames = []
    for raw in stack.splitlines()[:64]:
        source = _PROJECT_SOURCE.search(raw)
        symbol_match = _SYMBOL.search(raw)
        if symbol_match is None:
            continue
        function = _OFFSET.sub("", symbol_match.group(1)).casefold()
        module_match = _MODULE.search(raw)
        module = ""
        if module_match is not None:
            module_value = _OFFSET.sub("", _ADDRESS.sub("", module_match.group(1)))
            module = PurePosixPath(module_value).name.casefold()
        if _RUNTIME_FUNCTION.fullmatch(function) or module and _RUNTIME_MODULE.match(module):
            continue
        location = source.group(0).casefold() if source is not None else module
        value = f"{function}@{location}" if location else function
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
