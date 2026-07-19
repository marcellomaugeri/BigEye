"""Shared validation for shell-free engine process contracts."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Mapping

from backend.fuzzing.engines.contracts import EngineSpec


ROLE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
ENVIRONMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_common(spec: EngineSpec, engine: str, input_modes: frozenset[str]) -> None:
    if spec.engine != engine:
        raise ValueError(f"engine must be {engine}")
    validate_image_id(spec.image_id)
    if spec.input_mode not in input_modes:
        raise ValueError(f"input_mode must be one of {sorted(input_modes)}")
    if not spec.target_command or not _is_contained_path(spec.target_command[0], "/opt/bigeye"):
        raise ValueError("target command must begin with an absolute /opt/bigeye path")
    _validate_strings(spec.target_command, "target_command")
    validate_campaign_path(spec.corpus_path, "corpus_path", "/campaign/corpus")
    validate_campaign_path(spec.output_path, "output_path", "/campaign/output")
    if spec.corpus_path == spec.output_path:
        raise ValueError("corpus_path and output_path must be different")
    if not ROLE_PATTERN.fullmatch(spec.role):
        raise ValueError("role must contain only letters, digits, underscore, or hyphen")
    if isinstance(spec.timeout_ms, bool) or spec.timeout_ms <= 0:
        raise ValueError("timeout_ms must be positive")
    if isinstance(spec.memory_limit_mb, bool) or spec.memory_limit_mb <= 0:
        raise ValueError("memory_limit_mb must be positive")
    validate_environment(spec.sanitizer_environment)
    validate_labels(spec.campaign_labels)


def validate_campaign_path(path: str, name: str, root: str = "/campaign") -> None:
    if not isinstance(path, str) or "\x00" in path:
        raise ValueError(f"{name} must be a campaign path")
    parsed = PurePosixPath(path)
    root_parts = PurePosixPath(root).parts
    if not parsed.is_absolute() or parsed.parts[:len(root_parts)] != root_parts or ".." in parsed.parts:
        raise ValueError(f"{name} must be an absolute campaign path")


def validate_container_path(path: str, name: str) -> None:
    if not _is_absolute_container_path(path):
        raise ValueError(f"{name} must be an absolute container path")


def validate_environment(environment: Mapping[str, str]) -> None:
    for key, value in environment.items():
        if not isinstance(key, str) or not ENVIRONMENT_PATTERN.fullmatch(key):
            raise ValueError("environment variable names must be portable identifiers")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("environment variable values must be strings without NUL bytes")


def validate_labels(labels: Mapping[str, str]) -> None:
    for key, value in labels.items():
        if not isinstance(key, str) or not key or "\x00" in key or "\n" in key:
            raise ValueError("campaign label keys must be non-empty single-line strings")
        if not isinstance(value, str) or "\x00" in value or "\n" in value:
            raise ValueError("campaign label values must be single-line strings")


def validate_image_id(image_id: str) -> None:
    if not isinstance(image_id, str) or not IMAGE_ID_PATTERN.fullmatch(image_id):
        raise ValueError("image_id must be an immutable sha256 image ID")


def _is_absolute_container_path(value: str) -> bool:
    return isinstance(value, str) and value.startswith("/") and "\x00" not in value and ".." not in PurePosixPath(value).parts


def _is_contained_path(value: str, root: str) -> bool:
    if not _is_absolute_container_path(value):
        return False
    parts = PurePosixPath(value).parts
    root_parts = PurePosixPath(root).parts
    return parts[:len(root_parts)] == root_parts


def _validate_strings(values: tuple[str, ...], name: str) -> None:
    if any(not isinstance(value, str) or not value or "\x00" in value for value in values):
        raise ValueError(f"{name} entries must be non-empty strings without NUL bytes")
