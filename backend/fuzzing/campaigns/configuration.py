"""Choose and evaluate one documented configuration hypothesis at a time."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigurationHypothesis:
    name: str
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    evidence_ids: tuple[str, ...]
    documented: bool


@dataclass(frozen=True)
class ConfigurationEvidence:
    hypotheses: tuple[ConfigurationHypothesis, ...]


@dataclass(frozen=True)
class ConfigurationCandidate:
    name: str
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ConfigurationOutcome:
    unique_clean_lines: frozenset[str] = frozenset()
    unique_behaviours: frozenset[str] = frozenset()
    distinct_crash: bool = False


@dataclass(frozen=True)
class ConfigurationDecision:
    retained: bool
    reason: str


class ConfigurationPlanner:
    @staticmethod
    def next_candidate(
        evidence: ConfigurationEvidence,
        tried: tuple[str | ConfigurationCandidate, ...],
    ) -> ConfigurationCandidate | None:
        tried_names = {item.name if isinstance(item, ConfigurationCandidate) else item for item in tried}
        for hypothesis in evidence.hypotheses:
            if (
                hypothesis.name not in tried_names
                and hypothesis.documented
                and hypothesis.evidence_ids
                and all(identifier.strip() for identifier in hypothesis.evidence_ids)
                and hypothesis.name.strip()
            ):
                return ConfigurationCandidate(
                    hypothesis.name,
                    hypothesis.arguments,
                    hypothesis.environment,
                    hypothesis.evidence_ids,
                )
        return None

    @staticmethod
    def evaluate(outcome: ConfigurationOutcome) -> ConfigurationDecision:
        if outcome.unique_clean_lines:
            return ConfigurationDecision(True, "configuration adds unique clean coverage")
        if outcome.unique_behaviours:
            return ConfigurationDecision(True, "configuration adds unique behaviour")
        if outcome.distinct_crash:
            return ConfigurationDecision(True, "configuration exposes a distinct replayable crash")
        return ConfigurationDecision(False, "configuration adds no unique evidence")
