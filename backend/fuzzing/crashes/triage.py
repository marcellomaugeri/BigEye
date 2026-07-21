"""Evidence-first crash grouping and classification of user-facing findings."""

from __future__ import annotations

from dataclasses import dataclass
import re

from backend.agents.outputs.triage_result import TriageResult
from backend.fuzzing.crashes.artifacts import FindingArtifactStore
from backend.fuzzing.crashes.correction import CorrectionEvidence
from backend.fuzzing.crashes.fingerprint import (
    CrashGroupIdentity,
    compatible_crash_groups,
    crash_fingerprint,
    crash_group_identity,
)
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
    grouping: dict[str, object] | None = None
    engine: str | None = None
    input_mode: str | None = None
    target_boundary: str | None = None
    component_contract_valid: bool | None = None
    contract_evidence_ids: tuple[str, ...] = ()
    original_image_id: str | None = None
    clean_image_id: str | None = None


_MEMORY_SAFETY_SANITIZERS = frozenset({"address", "memory", "cfi"})
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


def confirmed_project_memory_safety(evidence: CrashTriageEvidence) -> bool:
    """Recognise a confirmed project fault without making an exploitability claim."""
    clean = evidence.clean_variant
    grouping = evidence.grouping
    if (
        evidence.reproducible is not True
        or evidence.original_attempts != 3
        or evidence.matching_original_runs != 3
        or not _memory_safety_sanitizer(evidence.sanitizer)
        or not isinstance(clean, dict)
        or clean.get("crashed") is not True
        or clean.get("error") is not None
        or not _memory_safety_sanitizer(clean.get("sanitizer"))
        or not isinstance(evidence.original_image_id, str)
        or _IMAGE_ID.fullmatch(evidence.original_image_id) is None
        or not isinstance(evidence.clean_image_id, str)
        or _IMAGE_ID.fullmatch(evidence.clean_image_id) is None
        or clean.get("image_id") != evidence.clean_image_id
        or evidence.original_image_id == evidence.clean_image_id
        or not isinstance(grouping, dict)
        or grouping.get("reproducible") is not True
        or not _memory_safety_sanitizer(grouping.get("failure_class"))
        or grouping.get("harness_misuse") is not False
        or evidence.harness_misuse_evidence
    ):
        return False
    frames = grouping.get("frames")
    if not isinstance(frames, list) or not frames or not isinstance(frames[0], dict):
        return False
    primary_source = frames[0].get("source_location")
    primary_function = frames[0].get("function")
    clean_source = clean.get("source_location")
    if not all(
        isinstance(value, str) and value
        for value in (primary_source, primary_function, clean_source)
    ) or _source_identity(primary_source) != _source_identity(clean_source):
        return False
    if evidence.target_boundary == "system" and evidence.engine == "afl":
        return evidence.input_mode in {"file", "stdin"}
    return bool(
        evidence.target_boundary == "component"
        and evidence.engine == "libfuzzer"
        and evidence.input_mode == "inprocess"
        and evidence.component_contract_valid is True
        and evidence.contract_evidence_ids
        and set(evidence.contract_evidence_ids) <= set(evidence.evidence_ids)
    )


def _memory_safety_sanitizer(value: object) -> bool:
    return isinstance(value, str) and bool(
        set(value.split("+")) & _MEMORY_SAFETY_SANITIZERS
    )


def _source_identity(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


class CrashPipeline:
    """Run deterministic evidence collection before the only finding database write."""

    def __init__(self, *, quarantine: CrashQuarantine, replayer, minimiser: CrashMinimiser,
                 findings, specialist, correction=None, replay_attempts: int = 3, events=None):
        self.quarantine = quarantine
        self.artifacts = FindingArtifactStore(quarantine)
        self._replayer = replayer
        self._replay = CrashReplay(replayer, replay_attempts)
        self._minimiser = minimiser
        self._findings = findings
        self._specialist = specialist
        self._correction = correction
        self._events = events

    async def process(self, observation: CrashObservation) -> Finding | None:
        original = await self._replay.collect_original(observation, observation.input_bytes)
        minimum = await self._minimiser.minimise(
            observation, observation.input_bytes, original.expected_signature, self._replayer,
        )
        replay = await self._replay.collect_variants(observation, minimum.input_bytes, original)
        representative = next((result for result in replay.original if result.crashed), None)
        if representative is None:
            representative = self._observation_result(observation)
        raw_fingerprint = crash_fingerprint(representative)
        grouping = crash_group_identity(
            representative,
            commit_sha=observation.commit_sha,
            reproducible=replay.reproducible,
            minimised_testcase=minimum.input_bytes,
            minimisation_accepted=minimum.accepted,
            harness_misuse=bool(observation.harness_misuse_evidence),
        )
        fingerprint = await self._compatible_fingerprint(
            observation.project_id, raw_fingerprint, grouping,
        )
        correction = await self._correction_experiment(observation, fingerprint, minimum, replay)
        quarantined = self.quarantine.persist(observation)
        evidence = self._evidence(
            observation, fingerprint, replay, minimum, correction, representative,
            quarantined, grouping,
        )
        forced = self._deterministic_classification(observation, replay, correction)
        triage = await self._triage(evidence)
        classification = forced or triage.classification
        if classification not in APPROVED_CLASSIFICATIONS:
            classification = "unresolved"
        if observation.harness_misuse_evidence and correction is None:
            classification = "unresolved"
        published_triage = self._publication_triage(classification, evidence, representative)
        async with self.artifacts.coordinate(
            fingerprint, quarantined, minimum.input_bytes, evidence, published_triage,
        ) as selected:
            finding = await self._findings.create_or_increment(
                project_id=observation.project_id,
                fingerprint=fingerprint,
                classification=selected.classification,
                description=selected.description,
                reproducible=selected.reproducible,
                candidate_selected=selected.candidate_selected,
            )
            linker = getattr(self._findings, "link_campaign", None)
            if linker is not None:
                await linker(observation.campaign_id, observation.project_id, fingerprint)
        if self._events is not None:
            await self._events.append(observation.project_id, "events", {"name": "findings"})
        return finding

    async def _compatible_fingerprint(
        self, project_id: int, raw_fingerprint: str, grouping: CrashGroupIdentity,
    ) -> str:
        list_findings = getattr(self._findings, "list_for_project", None)
        if list_findings is None:
            return raw_fingerprint
        findings = await list_findings(project_id)
        if any(finding.fingerprint == raw_fingerprint for finding in findings):
            return raw_fingerprint
        compatible = []
        for finding in findings:
            detail = self.artifacts.detail(finding)
            stored = detail.get("grouping")
            if stored is None:
                continue
            try:
                identity = CrashGroupIdentity.from_mapping(stored)
            except ValueError:
                continue
            if compatible_crash_groups(grouping, identity):
                compatible.append(finding.fingerprint)
        # Ambiguous compatibility is retained as a separate exact group.
        return compatible[0] if len(compatible) == 1 else raw_fingerprint

    async def _correction_experiment(
        self, observation: CrashObservation, fingerprint: str,
        minimum: MinimisationResult, replay: ReplayEvidence,
    ) -> dict[str, object] | None:
        if not observation.harness_misuse_evidence or self._correction is None:
            return None
        expected = replay.expected_signature
        if expected is None:
            return {"error": "correction requires a reproduced base signature"}
        if self.artifacts.claim_correction(observation.project_id, fingerprint):
            try:
                value = await self._correction.run(observation, minimum.input_bytes, expected)
                if not isinstance(value, CorrectionEvidence):
                    raise ValueError("correction did not return validated evidence")
                self._validate_correction(value, observation, expected)
                self.artifacts.store_correction_result(observation.project_id, fingerprint, value)
            except Exception:
                return {"error": "bounded correction experiment failed validation"}
        else:
            try:
                value = self.artifacts.read_correction_result(observation.project_id, fingerprint)
            except (OSError, ValueError):
                value = None
            if value is None:
                return {"error": "bounded correction experiment has no validated result"}
            try:
                self._validate_correction(value, observation, expected)
            except ValueError:
                return {"error": "stored correction evidence does not match this crash group"}
        return value.as_dict()

    @staticmethod
    def _validate_correction(
        value: CorrectionEvidence, observation: CrashObservation, expected_signature: str,
    ) -> None:
        if (
            value.project_id != observation.project_id
            or value.target_asset_id != observation.target_asset_id
            or value.base_image_id != observation.image_id
            or value.commit_sha != observation.commit_sha
            or value.base_signature != expected_signature
        ):
            raise ValueError("correction evidence lineage does not match the processed crash")

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
        if (
            observation.harness_misuse_evidence and correction is not None
            and correction.get("signature_disappeared") is True
        ):
            return "harness-induced false positive"
        if observation.harness_misuse_evidence and correction is not None and "error" in correction:
            return "unresolved"
        return None

    @staticmethod
    def _publication_triage(
        classification: str, evidence: CrashTriageEvidence, representative: ReplayResult,
    ) -> TriageResult:
        """Build user-visible text only from validated deterministic evidence."""
        location = representative.source_location or "project source"
        failure = f"{representative.sanitizer} sanitizer" if representative.sanitizer else "crash"
        if classification == "true vulnerability":
            description = f"Reproduced {failure} failure near {location}; investigate the affected operation."
            uncertainty = "Replay establishes a stable failure; source review is required to determine impact."
            repair = f"Review the operation and its input checks near {location}."
        elif classification == "harness-induced false positive":
            description = "A validated child target correction removed the reproduced failure."
            uncertainty = "The original target contract remains retained for comparison with the corrected child."
            repair = "Review the original harness setup and preserve the validated child target lineage."
        elif classification == "improper contract usage":
            description = "Replay evidence indicates that the target contract may be used incorrectly."
            uncertainty = "Source review is required to confirm the expected setup and call order."
            repair = f"Review target setup and call order near {location}."
        elif classification == "flaky or environmental":
            description = "The failure did not reproduce consistently and remains retained for investigation."
            uncertainty = "Available replays do not distinguish an intermittent defect from an environmental effect."
            repair = "Repeat the retained input in the same immutable image and inspect environmental differences."
        else:
            description = "The retained crash evidence does not support a definitive classification."
            uncertainty = "Replay or correction evidence is incomplete or inconclusive."
            repair = f"Review retained replay evidence and the affected operation near {location}."
        return TriageResult(
            classification=classification,
            description=description,
            evidence_ids=list(evidence.evidence_ids),
            uncertainty=uncertainty,
            priority_rationale="Project-relative priority is computed from persisted classification and replay evidence.",
            repair_intent=repair,
        )

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
        grouping: CrashGroupIdentity,
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
            grouping=grouping.as_dict(),
            engine=observation.engine,
            input_mode=observation.input_mode,
            target_boundary=("system" if observation.engine == "afl" else "component"),
            component_contract_valid=None,
            contract_evidence_ids=(),
            original_image_id=observation.image_id,
            clean_image_id=observation.clean_image_id,
        )
