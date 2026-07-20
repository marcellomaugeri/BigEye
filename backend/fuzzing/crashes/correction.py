"""One evidence-bound harness correction experiment with persisted lineage checks."""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Mapping

from backend.fuzzing.crashes.fingerprint import failure_signature
from backend.fuzzing.crashes.quarantine import CrashObservation
from backend.fuzzing.crashes.replay import ReplayResult


_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class CorrectionCandidate:
    asset_id: int
    image_id: str

    def __post_init__(self) -> None:
        if isinstance(self.asset_id, bool) or not isinstance(self.asset_id, int) or self.asset_id <= 0:
            raise ValueError("corrected asset ID must be positive")
        if not isinstance(self.image_id, str) or not _IMAGE.fullmatch(self.image_id):
            raise ValueError("corrected image ID must be exact")


@dataclass(frozen=True)
class CorrectionImage:
    image_id: str
    os: str
    architecture: str
    labels: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.image_id, str) or not _IMAGE.fullmatch(self.image_id):
            raise ValueError("correction image ID must be exact")
        if self.os != "linux" or self.architecture != "amd64":
            raise ValueError("correction images must be linux/amd64")
        if not isinstance(self.labels, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in self.labels.items()
        ):
            raise ValueError("correction image labels are invalid")
        object.__setattr__(self, "labels", tuple(sorted(self.labels.items())))

    def label_map(self) -> dict[str, str]:
        return dict(self.labels)


@dataclass(frozen=True)
class CorrectionEvidence:
    project_id: int
    target_asset_id: int
    corrected_asset_id: int
    base_image_id: str
    corrected_image_id: str
    target_asset_content_hash: str
    corrected_asset_content_hash: str
    base_manifest_hash: str
    corrected_manifest_hash: str
    commit_sha: str
    base_signature: str
    corrected_signature: str | None
    signature_disappeared: bool
    evidence_id: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.project_id, "project ID"),
            (self.target_asset_id, "target asset ID"),
            (self.corrected_asset_id, "corrected asset ID"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"correction {label} must be positive")
        for value, label in ((self.base_image_id, "base image"), (self.corrected_image_id, "corrected image")):
            if not isinstance(value, str) or not _IMAGE.fullmatch(value):
                raise ValueError(f"correction {label} must be exact")
        if self.base_image_id == self.corrected_image_id:
            raise ValueError("correction image must differ from the base image")
        for value, label in (
            (self.target_asset_content_hash, "target asset content hash"),
            (self.corrected_asset_content_hash, "corrected asset content hash"),
            (self.base_manifest_hash, "base manifest hash"),
            (self.corrected_manifest_hash, "corrected manifest hash"),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"correction {label} is invalid")
        if self.target_asset_content_hash == self.corrected_asset_content_hash:
            raise ValueError("correction child asset must have different content")
        if not isinstance(self.commit_sha, str) or not _COMMIT.fullmatch(self.commit_sha):
            raise ValueError("correction commit must be exact")
        if not isinstance(self.base_signature, str) or not _DIGEST.fullmatch(self.base_signature):
            raise ValueError("correction base signature is invalid")
        if self.corrected_signature is not None and not _DIGEST.fullmatch(self.corrected_signature):
            raise ValueError("correction result signature is invalid")
        if not isinstance(self.signature_disappeared, bool):
            raise ValueError("correction disappearance flag must be boolean")
        if self.signature_disappeared != (self.corrected_signature is None):
            raise ValueError("correction disappearance claim contradicts the replay signature")
        if not isinstance(self.evidence_id, str) or not re.fullmatch(r"correction:[0-9a-f]{64}", self.evidence_id):
            raise ValueError("correction evidence ID is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "project_id": self.project_id,
            "target_asset_id": self.target_asset_id,
            "corrected_asset_id": self.corrected_asset_id,
            "base_image_id": self.base_image_id,
            "corrected_image_id": self.corrected_image_id,
            "target_asset_content_hash": self.target_asset_content_hash,
            "corrected_asset_content_hash": self.corrected_asset_content_hash,
            "base_manifest_hash": self.base_manifest_hash,
            "corrected_manifest_hash": self.corrected_manifest_hash,
            "commit_sha": self.commit_sha,
            "base_signature": self.base_signature,
            "corrected_signature": self.corrected_signature,
            "signature_disappeared": self.signature_disappeared,
            "evidence_id": self.evidence_id,
        }

    @classmethod
    def from_dict(cls, value: object) -> CorrectionEvidence:
        if not isinstance(value, dict) or set(value) != {
            "project_id", "target_asset_id", "corrected_asset_id", "base_image_id",
            "corrected_image_id", "target_asset_content_hash", "corrected_asset_content_hash",
            "base_manifest_hash", "corrected_manifest_hash", "commit_sha", "base_signature", "corrected_signature",
            "signature_disappeared", "evidence_id",
        }:
            raise ValueError("stored correction evidence is invalid")
        return cls(**value)


class HarnessCorrectionExperiment:
    """Create one child target, then compare the same input in exact inspected images."""

    def __init__(self, assets, images, builder, replayer):
        self._assets = assets
        self._images = images
        self._builder = builder
        self._replayer = replayer

    async def run(
        self, crash: CrashObservation, input_bytes: bytes, expected_signature: str,
    ) -> CorrectionEvidence:
        original = await self._assets.get(crash.target_asset_id)
        self._validate_original_asset(original, crash)
        base_image = await self._await(self._images.inspect_exact(crash.image_id))
        base_manifest_hash = self._validate_image(base_image, crash, crash.image_id, original, None)

        candidate = await self._await(self._builder.create_child(crash, input_bytes, original))
        if not isinstance(candidate, CorrectionCandidate):
            raise ValueError("correction builder did not return a persisted candidate reference")
        if candidate.image_id == crash.image_id:
            raise ValueError("correction builder reused the base image")
        corrected = await self._assets.get(candidate.asset_id)
        self._validate_child_asset(corrected, original, crash)
        corrected_image = await self._await(self._images.inspect_exact(candidate.image_id))
        corrected_manifest_hash = self._validate_image(
            corrected_image, crash, candidate.image_id, corrected, original.id,
        )

        base_replay = await self._replayer.replay(crash, input_bytes, "original")
        self._validate_replay(base_replay, crash.image_id)
        if not base_replay.crashed or failure_signature(base_replay) != expected_signature:
            raise ValueError("correction base replay did not preserve the processed crash signature")
        corrected_crash = replace(crash, target_asset_id=corrected.id, image_id=candidate.image_id)
        corrected_replay = await self._replayer.replay(corrected_crash, input_bytes, "original")
        self._validate_replay(corrected_replay, candidate.image_id)
        corrected_signature = failure_signature(corrected_replay) if corrected_replay.crashed else None
        disappeared = not corrected_replay.crashed and corrected_signature is None
        identity = sha256(
            f"{crash.project_id}:{original.id}:{corrected.id}:{crash.image_id}:{candidate.image_id}:"
            f"{original.content_hash}:{corrected.content_hash}:{base_manifest_hash}:{corrected_manifest_hash}:"
            f"{crash.commit_sha}:{expected_signature}:{corrected_signature}".encode("ascii")
        ).hexdigest()
        return CorrectionEvidence(
            project_id=crash.project_id,
            target_asset_id=original.id,
            corrected_asset_id=corrected.id,
            base_image_id=crash.image_id,
            corrected_image_id=candidate.image_id,
            target_asset_content_hash=original.content_hash,
            corrected_asset_content_hash=corrected.content_hash,
            base_manifest_hash=base_manifest_hash,
            corrected_manifest_hash=corrected_manifest_hash,
            commit_sha=crash.commit_sha,
            base_signature=expected_signature,
            corrected_signature=corrected_signature,
            signature_disappeared=disappeared,
            evidence_id=f"correction:{identity}",
        )

    @staticmethod
    async def _await(value):
        return await value if inspect.isawaitable(value) else value

    @staticmethod
    def _validate_original_asset(asset, crash: CrashObservation) -> None:
        if (
            asset is None or asset.id != crash.target_asset_id or asset.project_id != crash.project_id
            or asset.validated_at is None or asset.error is not None
            or not isinstance(asset.content_hash, str) or not _DIGEST.fullmatch(asset.content_hash)
        ):
            raise ValueError("original target asset is not a persisted validated project asset")

    @staticmethod
    def _validate_child_asset(asset, original, crash: CrashObservation) -> None:
        if (
            asset is None or asset.id == original.id or asset.project_id != crash.project_id
            or asset.parent_id != original.id or asset.kind != original.kind
            or asset.validated_at is None or asset.error is not None
            or not isinstance(asset.content_hash, str) or not _DIGEST.fullmatch(asset.content_hash)
            or asset.content_hash == original.content_hash
        ):
            raise ValueError("corrected target is not a validated child asset")

    @staticmethod
    def _validate_image(image, crash: CrashObservation, expected_id: str, asset, parent_id: int | None) -> str:
        if not isinstance(image, CorrectionImage) or image.image_id != expected_id:
            raise ValueError("correction image inspection did not return the exact image")
        labels = image.label_map()
        expected = {
            "bigeye.project": str(crash.project_id),
            "bigeye.commit": crash.commit_sha,
            "bigeye.layer": "target",
            "bigeye.target-asset": str(asset.id),
            "bigeye.target-content-hash": asset.content_hash,
        }
        if parent_id is not None:
            expected["bigeye.parent-target-asset"] = str(parent_id)
        if any(labels.get(key) != value for key, value in expected.items()):
            raise ValueError("correction image labels do not match project, commit, manifest, and asset lineage")
        manifest_hash = labels.get("bigeye.content-hash")
        if not isinstance(manifest_hash, str) or not _DIGEST.fullmatch(manifest_hash):
            raise ValueError("correction image does not contain an exact manifest content hash")
        return manifest_hash

    @staticmethod
    def _validate_replay(result, expected_image: str) -> None:
        if (
            not isinstance(result, ReplayResult) or result.variant != "original"
            or result.image_id != expected_image or result.error is not None
        ):
            raise ValueError("correction replay did not use the exact inspected image")
