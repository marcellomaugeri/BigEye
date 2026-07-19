"""Data exchanged between engine command builders and container control."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class EngineSpec:
    """Validated-by-builder inputs for one engine process."""

    engine: str
    image_id: str
    target_command: tuple[str, ...]
    input_mode: str
    corpus_path: str
    output_path: str
    role: str
    sanitizer_environment: Mapping[str, str] = field(default_factory=dict)
    dictionary_path: str | None = None
    grammar_path: str | None = None
    timeout_ms: int = 1_000
    memory_limit_mb: int = 1_024
    campaign_labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ContainerInvocation:
    """A shell-free process invocation plus its required isolation policy."""

    engine: str
    image_id: str
    command: list[str]
    environment: Mapping[str, str]
    campaign_labels: Mapping[str, str]
    network_disabled: bool
    read_only_source: bool
    timeout_ms: int
    memory_limit_mb: int


@dataclass(frozen=True)
class EngineStatistics:
    """Observed engine counters; campaign decisions belong elsewhere."""

    execution_count: int
    execution_rate: float
    corpus_count: int
    corpus_size: int
    last_new_path: int | None
    crashes: int
    timeouts: int
    health: str
