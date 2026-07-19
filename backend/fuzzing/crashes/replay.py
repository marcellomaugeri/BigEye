"""Repeated exact-environment replay and compatible verification variants."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from backend.fuzzing.crashes.quarantine import CrashObservation, _source_reference


_SIGNAL_PATTERN = re.compile(r"SIG[A-Z0-9]+\Z")
_SANITIZERS = frozenset({"address", "undefined", "memory", "thread", "cfi", "leak", "none"})


@dataclass(frozen=True)
class ReplayResult:
    variant: str
    crashed: bool
    signal: str | None
    stack: str
    sanitizer: str | None
    source_location: str | None
    coverage: tuple[str, ...]
    exit_code: int | None
    image_id: str
    output: str = ""
    error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.variant, str) or not self.variant or len(self.variant) > 200:
            raise ValueError("replay variant is invalid")
        if not isinstance(self.crashed, bool):
            raise ValueError("replay crashed flag must be boolean")
        for value, label, maximum in (
            (self.signal, "signal", 100),
            (self.stack, "stack", 128 * 1024),
            (self.sanitizer, "sanitizer", 100),
            (self.source_location, "source location", 2_000),
            (self.output, "replay output", 256 * 1024),
            (self.error, "replay error", 2_000),
        ):
            if value is not None and (not isinstance(value, str) or len(value) > maximum or "\x00" in value):
                raise ValueError(f"replay {label} is invalid or exceeds its bound")
        if not isinstance(self.coverage, tuple) or len(self.coverage) > 65_536 or any(
            not isinstance(value, str) or not value or len(value) > 2_000 for value in self.coverage
        ):
            raise ValueError("replay coverage is invalid or exceeds its bound")
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise ValueError("replay exit code is invalid")
        if not isinstance(self.image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
            raise ValueError("replay image ID must be exact")
        if self.signal is not None and not _SIGNAL_PATTERN.fullmatch(self.signal):
            raise ValueError("replay signal is not a validated signal name")
        if self.sanitizer is not None and (
            not self.sanitizer or any(part not in _SANITIZERS for part in self.sanitizer.split("+"))
        ):
            raise ValueError("replay sanitizer is not a validated sanitizer name")
        _source_reference(self.source_location, "replay source location")
        for value in self.coverage:
            _source_reference(value, "replay coverage location")


@dataclass(frozen=True)
class ReplayEvidence:
    original: tuple[ReplayResult, ...]
    compatible_sanitizers: tuple[ReplayResult, ...]
    clean: ReplayResult | None
    reproducible: bool
    matching_original_runs: int
    expected_signature: str | None

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        identifiers = [f"replay:original:{index}" for index in range(1, len(self.original) + 1)]
        identifiers.extend(f"replay:{value.variant}" for value in self.compatible_sanitizers)
        if self.clean is not None:
            identifiers.append("replay:clean")
        return tuple(identifiers)


class ReplayExecutor(Protocol):
    async def replay(self, crash: CrashObservation, input_bytes: bytes, variant: str) -> ReplayResult: ...


class CrashReplay:
    """Collect replay evidence; exceptions become bounded unresolved evidence."""

    def __init__(self, executor: ReplayExecutor, attempts: int = 3):
        if isinstance(attempts, bool) or not isinstance(attempts, int) or not 2 <= attempts <= 10:
            raise ValueError("replay attempts must be between two and ten")
        self._executor = executor
        self._attempts = attempts

    async def collect(self, crash: CrashObservation, input_bytes: bytes) -> ReplayEvidence:
        original = await self.collect_original(crash, input_bytes)
        return await self.collect_variants(crash, input_bytes, original)

    async def collect_original(self, crash: CrashObservation, input_bytes: bytes) -> ReplayEvidence:
        from backend.fuzzing.crashes.fingerprint import failure_signature

        original = tuple([
            await self._run(crash, input_bytes, "original") for _ in range(self._attempts)
        ])
        signatures = [failure_signature(result) if result.crashed else None for result in original]
        expected = next((value for value in signatures if value is not None), None)
        matching = sum(value == expected for value in signatures) if expected is not None else 0
        reproducible = expected is not None and matching == len(original)
        return ReplayEvidence(original, (), None, reproducible, matching, expected)

    async def collect_variants(
        self, crash: CrashObservation, input_bytes: bytes, original: ReplayEvidence,
    ) -> ReplayEvidence:
        compatible = tuple([
            await self._run(crash, input_bytes, f"sanitizer:{variant}")
            for variant, _image_id in crash.compatible_sanitizer_variants
        ])
        clean = await self._run(crash, input_bytes, "clean") if crash.clean_image_id is not None else None
        return ReplayEvidence(
            original.original, compatible, clean, original.reproducible,
            original.matching_original_runs, original.expected_signature,
        )

    async def _run(self, crash: CrashObservation, input_bytes: bytes, variant: str) -> ReplayResult:
        try:
            result = await self._executor.replay(crash, input_bytes, variant)
            if not isinstance(result, ReplayResult) or result.variant != variant:
                raise ValueError("replay executor returned a mismatched variant")
            if variant == "original":
                expected_image = crash.image_id
            elif variant == "clean":
                expected_image = crash.clean_image_id
            else:
                expected_image = dict(crash.compatible_sanitizer_variants).get(variant.removeprefix("sanitizer:"))
            if result.image_id != expected_image:
                raise ValueError("replay executor returned evidence from a different image")
            return result
        except Exception as error:
            return ReplayResult(
                variant=variant, crashed=False, signal=None, stack="", sanitizer=None,
                source_location=None, coverage=(), exit_code=None,
                image_id=(
                    crash.image_id if variant == "original"
                    else crash.clean_image_id if variant == "clean" and crash.clean_image_id is not None
                    else dict(crash.compatible_sanitizer_variants).get(
                        variant.removeprefix("sanitizer:"), crash.image_id,
                    )
                ),
                error=f"replay failed ({type(error).__name__})",
            )
