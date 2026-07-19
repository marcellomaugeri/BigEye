"""Select the next smallest justified campaign improvement."""

from __future__ import annotations

from dataclasses import dataclass

from backend.fuzzing.campaigns.configuration import ConfigurationCandidate


@dataclass(frozen=True)
class ProgressionEvidence:
    engine: str = "afl++"
    normal_build_ready: bool = False
    baseline_sanitizers_validated: bool = False
    seed_coverage_healthy: bool = False
    basic_fuzzer_running: bool = False
    basic_campaign_healthy: bool = False
    dictionary_evidence_ids: tuple[str, ...] = ()
    cmplog_evidence_ids: tuple[str, ...] = ()
    configuration: ConfigurationCandidate | None = None
    component_gap_evidence_ids: tuple[str, ...] = ()
    special_sanitizer: str | None = None
    special_sanitizer_evidence_ids: tuple[str, ...] = ()
    grammar_library: str | None = None
    grammar_evidence_ids: tuple[str, ...] = ()
    completed_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProgressionAction:
    name: str
    evidence_ids: tuple[str, ...] = ()
    arguments: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    detail: str | None = None

    @property
    def key(self) -> str:
        return f"{self.name}:{self.detail}" if self.detail else self.name


class CampaignProgression:
    @staticmethod
    def next_step(evidence: ProgressionEvidence) -> ProgressionAction | None:
        if not evidence.normal_build_ready:
            return ProgressionAction("prepare normal build")
        if not evidence.baseline_sanitizers_validated:
            return ProgressionAction("validate address and undefined")
        if not evidence.seed_coverage_healthy:
            return ProgressionAction("validate seed and coverage health")
        if not evidence.basic_fuzzer_running:
            return ProgressionAction("start basic fuzzer")
        if not evidence.basic_campaign_healthy:
            return None

        completed = set(evidence.completed_actions)
        candidates: list[ProgressionAction] = []
        if evidence.dictionary_evidence_ids:
            candidates.append(ProgressionAction("enable dictionary", evidence.dictionary_evidence_ids))
        if evidence.engine == "afl++" and evidence.cmplog_evidence_ids:
            candidates.append(ProgressionAction("enable CmpLog", evidence.cmplog_evidence_ids))
        if evidence.configuration is not None and evidence.configuration.evidence_ids:
            candidates.append(ProgressionAction(
                "try configuration",
                evidence.configuration.evidence_ids,
                evidence.configuration.arguments,
                evidence.configuration.environment,
                evidence.configuration.name,
            ))
        if evidence.component_gap_evidence_ids:
            candidates.append(ProgressionAction("prepare component gap target", evidence.component_gap_evidence_ids))
        if evidence.special_sanitizer and evidence.special_sanitizer_evidence_ids:
            candidates.append(ProgressionAction(
                "run specialised sanitizer replay",
                evidence.special_sanitizer_evidence_ids,
                detail=evidence.special_sanitizer,
            ))
        if evidence.engine == "afl++" and evidence.grammar_library and evidence.grammar_evidence_ids:
            candidates.append(ProgressionAction(
                "enable grammar mutator",
                evidence.grammar_evidence_ids,
                environment=(("AFL_CUSTOM_MUTATOR_LIBRARY", evidence.grammar_library),),
            ))
        return next((candidate for candidate in candidates if candidate.key not in completed), None)
