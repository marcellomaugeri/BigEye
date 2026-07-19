"""Engine-native crash minimisation guarded by exact failure replay."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from backend.fuzzing.crashes.fingerprint import failure_signature
from backend.fuzzing.crashes.quarantine import CrashObservation, DEFAULT_MAX_INPUT_BYTES
from backend.fuzzing.crashes.replay import ReplayExecutor, ReplayResult


class NativeCrashMinimiser(Protocol):
    async def minimise(self, crash: CrashObservation, input_bytes: bytes, expected_signature: str) -> bytes: ...


@dataclass(frozen=True)
class MinimisationResult:
    input_bytes: bytes
    accepted: bool
    original_size: int
    minimal_size: int
    evidence_id: str


class CrashMinimiser:
    """Accept an engine minimum only when original-image replay preserves the failure."""

    def __init__(self, native: NativeCrashMinimiser, max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES):
        self._native = native
        self._max_input_bytes = max_input_bytes

    async def minimise(
        self,
        crash: CrashObservation,
        input_bytes: bytes,
        expected_signature: str | None,
        replayer: ReplayExecutor,
    ) -> MinimisationResult:
        if expected_signature is None:
            return self._rejected(input_bytes)
        try:
            candidate = await self._native.minimise(crash, input_bytes, expected_signature)
        except Exception:
            return self._rejected(input_bytes)
        if (
            not isinstance(candidate, bytes) or len(candidate) > len(input_bytes)
            or len(candidate) > self._max_input_bytes
        ):
            return self._rejected(input_bytes)
        try:
            replay = await replayer.replay(crash, candidate, "original")
        except Exception:
            return self._rejected(input_bytes)
        if (
            not isinstance(replay, ReplayResult) or replay.variant != "original" or not replay.crashed
            or failure_signature(replay) != expected_signature
        ):
            return self._rejected(input_bytes)
        return MinimisationResult(candidate, True, len(input_bytes), len(candidate), "minimisation:accepted")

    @staticmethod
    def _rejected(input_bytes: bytes) -> MinimisationResult:
        return MinimisationResult(input_bytes, False, len(input_bytes), len(input_bytes), "minimisation:original-retained")
