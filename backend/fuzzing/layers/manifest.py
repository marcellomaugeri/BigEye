"""Immutable metadata for a generated BigEye image layer."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LayerManifest:
    kind: str
    tag: str
    content_hash: str
    parent_tag: str
    dockerfile: Path
    context_dir: Path
    labels: dict[str, str]
