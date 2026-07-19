"""Plan baseline and evidence-gated sanitizer variants."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SanitizerTarget:
    concurrent: bool
    fully_instrumentable_dependency_closure: bool = False
    language: str = "c"
    lto_compatible: bool = False


@dataclass(frozen=True)
class SanitizerPlan:
    primary: tuple[str, ...]
    replay_variants: tuple[str, ...]
    concurrent_replay_variants: tuple[str, ...]
    quality_signals: tuple[str, ...]
    leak_classification: str


class SanitizerPlanner:
    @staticmethod
    def plan(target: SanitizerTarget, worker_count: int) -> SanitizerPlan:
        if worker_count < 1:
            raise ValueError("worker count must be positive")
        candidates: list[str] = []
        if target.fully_instrumentable_dependency_closure:
            candidates.append("memory")
        if target.concurrent:
            candidates.append("thread")
        if target.language.strip().lower() in {"c++", "cpp", "cxx"} and target.lto_compatible:
            candidates.append("cfi")
        return SanitizerPlan(
            primary=("address", "undefined"),
            replay_variants=tuple(candidates),
            concurrent_replay_variants=tuple(candidates[: max(0, worker_count - 1)]),
            quality_signals=("leak",),
            leak_classification="quality evidence",
        )
