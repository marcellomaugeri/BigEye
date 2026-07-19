"""Evidence-first crash grouping and classification of user-facing findings."""

from __future__ import annotations

import re
from dataclasses import dataclass

from backend.agents.outputs.triage_result import TriageResult
from backend.fuzzing.crashes.artifacts import FindingArtifactStore
from backend.fuzzing.crashes.fingerprint import crash_fingerprint
from backend.fuzzing.crashes.minimisation import CrashMinimiser, MinimisationResult
from backend.fuzzing.crashes.quarantine import (
    CrashObservation,
    CrashQuarantine,
    QuarantinedCrash,
)
from backend.fuzzing.crashes.replay import CrashReplay, ReplayEvidence, ReplayResult
from backend.models.finding import Finding


APPROVED_CLASSIFICATIONS = frozenset({
    "harness-induced false positive",
    "improper contract usage",
    "true vulnerability",
    "flaky or environmental",
    "unresolved",
})
_UNPROVEN_EXPLOITABILITY = re.compile(
    r"\b(?:exploitable|exploitability|remote code execution|arbitrary code execution|rce)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CrashTriageEvidence:
    project_id: int
    campaign_id: int
    fingerprint: str
    reproducible: bool
    original_attempts: int
    matching_original_runs: int
    signal: str | None
    sanitizer: str | None
    source_location: str | None
    stack: tuple[str, ...]
    coverage: tuple[str, ...]
    compatible_variants: tuple[dict[str, object], ...]
    clean_variant: dict[str, object] | None
    minimisation: dict[str, object]
    correction: dict[str, object] | None
    harness_misuse_evidence: tuple[str, ...]
    evidence_ids: tuple[str, ...]




class CrashPipeline:
    """Run deterministic evidence collection before the only finding database write."""

    def __init__(self, *, quarantine: CrashQuarantine, replayer, minimiser: CrashMinimiser,
                 findings, specialist, correction=None, replay_attempts: int = 3):
        self.quarantine = quarantine
        self.artifacts = FindingArtifactStore(quarantine)
        self._replayer = replayer
        self._replay = CrashReplay(replayer, replay_attempts)
        self._minimiser = minimiser
        self._findings = findings
        self._specialist = specialist
        self._correction = correction

    async def process(self, observation: CrashObservation) -> Finding | None:
        quarantined = self.quarantine.persist(observation)
        original = await self._replay.collect_original(observation, observation.input_bytes)
        minimum = await self._minimiser.minimise(
            observation, observation.input_bytes, original.expected_signature, self._replayer,
        )
        replay = await self._replay.collect_variants(observation, minimum.input_bytes, original)
        representative = next((result for result in replay.original if result.crashed), None)
        if representative is None:
            representative = self._observation_result(observation)
        fingerprint = crash_fingerprint(representative)
        correction = await self._correction_experiment(observation, minimum, replay)
        evidence = self._evidence(observation, fingerprint, replay, minimum, correction, representative, quarantined)
        forced = self._deterministic_classification(observation, replay, correction)
        triage = await self._triage(evidence)
        classification = forced or triage.classification
        if classification not in APPROVED_CLASSIFICATIONS:
            classification = "unresolved"
        if observation.harness_misuse_evidence and correction is None:
            classification = "unresolved"
        description = self._description(observation, classification, triage.description, representative)
        priority_rank = 1 if classification == "true vulnerability" and replay.reproducible else None
        priority_reason = self._priority_reason(
            observation, triage.priority_rationale,
        ) if priority_rank is not None else None
        published_triage = triage.model_copy(update={"classification": classification, "description": description})
        self.artifacts.publish(fingerprint, quarantined, minimum.input_bytes, evidence, published_triage)
        return await self._findings.create_or_increment(
            project_id=observation.project_id,
            fingerprint=fingerprint,
            classification=classification,
            priority_rank=priority_rank,
            priority_reason=priority_reason,
            description=description,
            reproducible=replay.reproducible,
        )

    async def _correction_experiment(
        self, observation: CrashObservation, minimum: MinimisationResult, replay: ReplayEvidence,
    ) -> dict[str, object] | None:
        if not observation.harness_misuse_evidence or self._correction is None:
            return None
        try:
            value = await self._correction.create_and_replay(observation, minimum.input_bytes, replay)
        except Exception:
            return {"error": "bounded correction experiment failed"}
        if not isinstance(value, dict):
            return {"error": "bounded correction experiment returned invalid evidence"}
        asset_id, parent_id = value.get("asset_id"), value.get("parent_asset_id")
        image_id, commit_sha = value.get("image_id"), value.get("commit_sha")
        crashed, evidence_id = value.get("crashed"), value.get("evidence_id")
        if (
            isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id <= 0
            or asset_id == observation.target_asset_id
            or parent_id != observation.target_asset_id
            or not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or commit_sha != observation.commit_sha
            or not isinstance(crashed, bool)
            or not isinstance(evidence_id, str) or not evidence_id or len(evidence_id) > 2_000
            or evidence_id.startswith("/") or ".." in evidence_id
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", evidence_id)
        ):
            return {"error": "bounded correction experiment did not create a valid child asset"}
        return {
            "asset_id": asset_id, "parent_asset_id": parent_id, "image_id": image_id,
            "commit_sha": commit_sha, "crashed": crashed, "evidence_id": evidence_id,
        }

    async def _triage(self, evidence: CrashTriageEvidence) -> TriageResult:
        try:
            raw = await self._specialist.triage(evidence)
            result = raw if isinstance(raw, TriageResult) else TriageResult.model_validate(raw)
            if result.classification not in APPROVED_CLASSIFICATIONS:
                raise ValueError("unsupported classification")
            if len(result.evidence_ids) != len(set(result.evidence_ids)) or not set(result.evidence_ids) <= set(evidence.evidence_ids):
                raise ValueError("specialist cited evidence outside the processed crash group")
            return result
        except Exception:
            return TriageResult(
                classification="unresolved",
                description="Crash evidence was preserved for investigation.",
                evidence_ids=list(evidence.evidence_ids),
                uncertainty="The crash specialist did not return a valid evidence-bounded classification.",
                priority_rationale="No project-relative priority can be assigned until classification succeeds.",
                repair_intent="Review the retained replay and source evidence, then retry classification.",
            )

    @staticmethod
    def _deterministic_classification(
        observation: CrashObservation, replay: ReplayEvidence, correction: dict[str, object] | None,
    ) -> str | None:
        if not replay.reproducible:
            if any(result.crashed for result in replay.original):
                return "flaky or environmental"
            return "unresolved"
        if observation.harness_misuse_evidence and correction is not None and correction.get("crashed") is False:
            return "harness-induced false positive"
        if observation.harness_misuse_evidence and correction is not None and "error" in correction:
            return "unresolved"
        return None

    @staticmethod
    def _description(
        observation: CrashObservation, classification: str, value: str, representative: ReplayResult,
    ) -> str:
        description = " ".join(value.split())[:1_000] if isinstance(value, str) else ""
        if not description:
            description = "Crash evidence was preserved for investigation."
        if classification == "true vulnerability" and not observation.exploitability_proven and _UNPROVEN_EXPLOITABILITY.search(description):
            location = representative.source_location or "project source"
            description = f"Reproduced sanitizer failure near {location}; investigate the affected input path."
        return description

    @staticmethod
    def _priority_reason(observation: CrashObservation, value: str) -> str:
        reason = " ".join(value.split())[:2_000] if isinstance(value, str) else ""
        if not reason:
            return "Reproducible sanitizer evidence requires project-source investigation."
        if not observation.exploitability_proven and _UNPROVEN_EXPLOITABILITY.search(reason):
            return "Reproducible sanitizer evidence and project-source reach place this group first for investigation."
        return reason

    @staticmethod
    def _observation_result(observation: CrashObservation) -> ReplayResult:
        return ReplayResult(
            variant="observation", crashed=True, signal=observation.signal or None,
            stack=observation.stack, sanitizer=observation.sanitizer,
            source_location=observation.source_location, coverage=observation.coverage,
            exit_code=None, image_id=observation.image_id,
        )

    @staticmethod
    def _result_summary(result: ReplayResult) -> dict[str, object]:
        return {
            "variant": result.variant,
            "crashed": result.crashed,
            "signal": result.signal,
            "sanitizer": result.sanitizer,
            "source_location": result.source_location,
            "image_id": result.image_id,
            "error": result.error,
        }

    @classmethod
    def _evidence(
        cls, observation: CrashObservation, fingerprint: str, replay: ReplayEvidence,
        minimum: MinimisationResult, correction: dict[str, object] | None,
        representative: ReplayResult, quarantined: QuarantinedCrash,
    ) -> CrashTriageEvidence:
        evidence_ids = [f"quarantine:{quarantined.group_key}:{quarantined.occurrence}"]
        evidence_ids.extend(replay.evidence_ids)
        evidence_ids.append(minimum.evidence_id)
        evidence_ids.extend(observation.harness_misuse_evidence)
        if correction is not None and isinstance(correction.get("evidence_id"), str):
            evidence_ids.append(correction["evidence_id"])
        return CrashTriageEvidence(
            project_id=observation.project_id,
            campaign_id=observation.campaign_id,
            fingerprint=fingerprint,
            reproducible=replay.reproducible,
            original_attempts=len(replay.original),
            matching_original_runs=replay.matching_original_runs,
            signal=representative.signal,
            sanitizer=representative.sanitizer,
            source_location=representative.source_location,
            stack=tuple(representative.stack.splitlines()[:64]),
            coverage=representative.coverage,
            compatible_variants=tuple(cls._result_summary(value) for value in replay.compatible_sanitizers),
            clean_variant=cls._result_summary(replay.clean) if replay.clean is not None else None,
            minimisation={
                "accepted": minimum.accepted,
                "original_size": minimum.original_size,
                "minimal_size": minimum.minimal_size,
            },
            correction=correction,
            harness_misuse_evidence=observation.harness_misuse_evidence,
            evidence_ids=tuple(dict.fromkeys(evidence_ids)),
        )
