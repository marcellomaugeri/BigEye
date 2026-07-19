"""Deterministic crash evidence must exist before a finding is published."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.agents.outputs.triage_result import TriageResult
from backend.fuzzing.crashes.fingerprint import crash_fingerprint
from backend.fuzzing.crashes.minimisation import CrashMinimiser
from backend.fuzzing.crashes.quarantine import CrashObservation, CrashQuarantine
from backend.fuzzing.crashes.replay import ReplayResult
from backend.fuzzing.crashes.artifacts import FindingArtifactStore
from backend.fuzzing.crashes.triage import CrashPipeline, CrashTriageEvidence
from backend.models.finding import Finding


def run(coroutine):
    return asyncio.run(coroutine)


def observation(**changes) -> CrashObservation:
    values = {
        "project_id": 7,
        "campaign_id": 11,
        "commit_sha": "a" * 40,
        "engine": "libfuzzer",
        "image_id": "sha256:" + "b" * 64,
        "target_asset_id": 31,
        "configuration_asset_id": 32,
        "sanitizer": "address",
        "command": ("/opt/bigeye/target", "/campaign/input"),
        "input_bytes": b"PREFIX-crash-SUFFIX",
        "engine_output": "AddressSanitizer: heap-buffer-overflow",
        "stack": "#0 0x123 in parse src/parser.c:42\n#1 0x456 in entry harness.cc:8",
        "signal": "SIGABRT",
        "source_location": "src/parser.c:42",
        "coverage": ("src/parser.c:40", "src/parser.c:42"),
        "compatible_sanitizer_variants": (("undefined", "sha256:" + "d" * 64),),
        "clean_image_id": "sha256:" + "c" * 64,
    }
    values.update(changes)
    return CrashObservation(**values)


class Replay:
    def __init__(self, *, stable: bool = True):
        self.stable = stable
        self.calls = []

    async def replay(self, crash, input_bytes: bytes, variant: str) -> ReplayResult:
        self.calls.append((variant, input_bytes))
        attempt = sum(call[0] == variant for call in self.calls)
        crashed = self.stable or attempt % 2 == 1
        return ReplayResult(
            variant=variant,
            crashed=crashed,
            signal="SIGABRT" if crashed else None,
            stack=crash.stack if crashed else "",
            sanitizer=crash.sanitizer if crashed else None,
            source_location=crash.source_location if crashed else None,
            coverage=crash.coverage,
            exit_code=-6 if crashed else 0,
            output="bounded replay output",
            image_id=(
                crash.image_id if variant == "original"
                else crash.clean_image_id if variant == "clean"
                else dict(crash.compatible_sanitizer_variants)[variant.removeprefix("sanitizer:")]
            ),
        )


class NativeMinimiser:
    def __init__(self):
        self.calls = []

    async def minimise(self, crash, input_bytes: bytes, expected_signature: str) -> bytes:
        self.calls.append((crash.engine, input_bytes, expected_signature))
        return b"crash"


class Findings:
    def __init__(self):
        self.rows = {}
        self.calls = []

    async def create_or_increment(self, **values):
        self.calls.append(values)
        key = (values["project_id"], values["fingerprint"])
        existing = self.rows.get(key)
        count = 1 if existing is None else existing.occurrence_count + 1
        finding = Finding(
            id=len(self.rows) + 1 if existing is None else existing.id,
            project_id=values["project_id"],
            fingerprint=values["fingerprint"],
            classification=values["classification"],
            priority_rank=values["priority_rank"],
            priority_reason=values["priority_reason"],
            description=values["description"],
            reproducible=values["reproducible"],
            occurrence_count=count,
            created_at=datetime(2026, 7, 20, tzinfo=UTC),
            triaged_at=datetime(2026, 7, 20, tzinfo=UTC),
            error=None,
        )
        self.rows[key] = finding
        return finding


class Specialist:
    def __init__(self, classification="true vulnerability", description="Reproduced parser memory failure.", priority=None):
        self.classification = classification
        self.description = description
        self.priority = priority or "Reproducible sanitizer failure in a project parser."
        self.calls = []

    async def triage(self, evidence):
        self.calls.append(evidence)
        return TriageResult(
            classification=self.classification,
            description=self.description,
            evidence_ids=list(evidence.evidence_ids),
            uncertainty="The affected input path still needs source review.",
            priority_rationale=self.priority,
            repair_intent="Inspect the bounds contract at src/parser.c:42.",
        )


def pipeline(tmp_path: Path, *, replay=None, specialist=None, corrector=None):
    repository = Findings()
    native = NativeMinimiser()
    service = CrashPipeline(
        quarantine=CrashQuarantine(tmp_path),
        replayer=replay or Replay(),
        minimiser=CrashMinimiser(native),
        findings=repository,
        specialist=specialist or Specialist(),
        correction=corrector,
    )
    return service, repository, native


def artifact_evidence(fingerprint: str) -> CrashTriageEvidence:
    return CrashTriageEvidence(
        project_id=7, campaign_id=11, fingerprint=fingerprint, reproducible=True,
        original_attempts=3, matching_original_runs=3, signal="SIGABRT",
        sanitizer="address", source_location="src/parser.c:42", stack=("#0 parse",),
        coverage=("src/parser.c:42",), compatible_variants=(), clean_variant=None,
        minimisation={"accepted": True, "original_size": 5, "minimal_size": 5},
        correction=None, harness_misuse_evidence=(), evidence_ids=("replay:original:1",),
    )


def artifact_triage() -> TriageResult:
    return TriageResult(
        classification="true vulnerability", description="Reproduced parser memory failure.",
        evidence_ids=["replay:original:1"], uncertainty="Source reach needs review.",
        priority_rationale="Reproducible parser failure.", repair_intent="Review parser bounds.",
    )


def test_duplicate_crashes_become_one_group_with_occurrence_count(tmp_path: Path):
    service, repository, _ = pipeline(tmp_path)

    first = run(service.process(observation(input_bytes=b"one")))
    second = run(service.process(observation(input_bytes=b"two")))

    assert first.id == second.id
    assert second.occurrence_count == 2
    assert len(repository.calls) == 2
    retained = service.artifacts.read_reproducer(second)
    metadata = service.artifacts.detail(second)["reproducer"]
    assert retained == b"one"
    assert metadata == {"sha256": __import__("hashlib").sha256(retained).hexdigest(), "size": len(retained)}


def test_raw_crash_is_quarantined_and_not_published_until_replay_completes(tmp_path: Path):
    service, repository, _ = pipeline(tmp_path)
    pending = observation()

    quarantined = service.quarantine.persist(pending)

    assert repository.calls == []
    metadata = json.loads(service.quarantine.read_metadata(quarantined).decode())
    assert metadata["commit_sha"] == pending.commit_sha
    assert metadata["image_id"] == pending.image_id
    assert metadata["target_asset_id"] == 31
    assert service.quarantine.read_original(quarantined) == pending.input_bytes


def test_minimisation_must_preserve_the_original_failure_signature(tmp_path: Path):
    class ChangedSignatureReplay(Replay):
        async def replay(self, crash, input_bytes, variant):
            result = await super().replay(crash, input_bytes, variant)
            if input_bytes == b"crash":
                return replace(result, signal="SIGSEGV", stack="#0 other src/other.c:9")
            return result

    service, _, native = pipeline(tmp_path, replay=ChangedSignatureReplay())

    finding = run(service.process(observation()))
    detail = service.artifacts.detail(finding)

    assert native.calls
    assert service.artifacts.read_reproducer(finding) == b"PREFIX-crash-SUFFIX"
    assert detail["minimisation"]["accepted"] is False


def test_flaky_crash_is_retained_and_cannot_be_promoted_to_vulnerability(tmp_path: Path):
    service, _, _ = pipeline(tmp_path, replay=Replay(stable=False))

    finding = run(service.process(observation()))

    assert finding.classification == "flaky or environmental"
    assert finding.reproducible is False
    assert service.artifacts.read_reproducer(finding)


def test_harness_failure_is_not_promoted_as_target_vulnerability(tmp_path: Path):
    class Correction:
        def __init__(self):
            self.calls = []

        async def create_and_replay(self, crash, input_bytes, evidence):
            self.calls.append((crash.target_asset_id, input_bytes))
            return {
                "asset_id": 99,
                "parent_asset_id": crash.target_asset_id,
                "image_id": "sha256:" + "e" * 64,
                "commit_sha": crash.commit_sha,
                "crashed": False,
                "evidence_id": "correction:99",
            }

    correction = Correction()
    service, _, _ = pipeline(tmp_path, specialist=Specialist("true vulnerability"), corrector=correction)

    finding = run(service.process(observation(harness_misuse_evidence=("probe:invalid-call-order",))))

    assert finding.classification == "harness-induced false positive"
    assert finding.classification != "true vulnerability"
    assert correction.calls == [(31, b"crash")]
    assert service.artifacts.detail(finding)["correction"]["asset_id"] == 99


def test_replay_rejects_a_result_from_a_different_image(tmp_path: Path):
    class WrongImage(Replay):
        async def replay(self, crash, input_bytes, variant):
            result = await super().replay(crash, input_bytes, variant)
            if variant.startswith("sanitizer:"):
                return replace(result, image_id="sha256:" + "f" * 64)
            return result

    service, _, _ = pipeline(tmp_path, replay=WrongImage())

    finding = run(service.process(observation()))
    compatible = service.artifacts.detail(finding)["replay"]["compatible_variants"]

    assert compatible[0]["crashed"] is False
    assert compatible[0]["error"] == "replay failed (ValueError)"


def test_invalid_specialist_classification_is_preserved_as_unresolved(tmp_path: Path):
    service, _, _ = pipeline(tmp_path, specialist=Specialist("critical RCE"))

    finding = run(service.process(observation()))

    assert finding.classification == "unresolved"
    assert finding.error is None


def test_unproven_exploitability_claim_is_not_published(tmp_path: Path):
    service, _, _ = pipeline(
        tmp_path,
        specialist=Specialist("true vulnerability", "Exploitable remote code execution in parser."),
    )

    finding = run(service.process(observation(exploitability_proven=False)))

    assert "exploit" not in finding.description.casefold()
    assert "code execution" not in finding.description.casefold()


def test_unproven_exploitability_claim_is_removed_from_priority_rationale(tmp_path: Path):
    service, _, _ = pipeline(
        tmp_path,
        specialist=Specialist(priority="Priority one because remote code execution is exploitable."),
    )

    finding = run(service.process(observation(exploitability_proven=False)))

    assert "exploit" not in finding.priority_reason.casefold()
    assert "code execution" not in finding.priority_reason.casefold()


def test_empty_crashing_input_is_retained_as_a_valid_reproducer(tmp_path: Path):
    service, _, _ = pipeline(tmp_path)

    finding = run(service.process(observation(input_bytes=b"")))

    assert service.artifacts.read_reproducer(finding) == b""
    assert service.artifacts.detail(finding)["reproducer"]["size"] == 0


def test_fingerprint_normalises_addresses_but_keeps_source_signal_and_coverage():
    left = ReplayResult(
        variant="original", crashed=True, signal="SIGSEGV",
        stack="#0 0x1234 in parse src/a.c:42", sanitizer="address",
        source_location="src/a.c:42", coverage=("src/a.c:41", "src/a.c:42"), exit_code=-11,
        image_id="sha256:" + "b" * 64,
    )
    right = replace(left, stack="#0 0xabcdef in parse src/a.c:42")
    changed = replace(left, coverage=("src/a.c:41", "src/a.c:99"))

    assert crash_fingerprint(left) == crash_fingerprint(right)
    assert crash_fingerprint(left) != crash_fingerprint(changed)


def test_quarantine_rejects_oversized_inputs_and_symlinked_project_paths(tmp_path: Path):
    quarantine = CrashQuarantine(tmp_path, max_input_bytes=8)
    with pytest.raises(ValueError, match="input exceeds"):
        quarantine.persist(observation(input_bytes=b"123456789"))

    (tmp_path / "projects").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "projects" / "7").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        CrashQuarantine(tmp_path).persist(observation())


def test_quarantine_rejects_a_project_path_swap_before_publication(tmp_path: Path):
    class SwappingQuarantine(CrashQuarantine):
        def _after_group_opened(self, project_id, group_key, _descriptor):
            parent = tmp_path / "projects" / str(project_id) / "crashes" / "quarantine"
            (parent / group_key).rename(parent / f"{group_key}.moved")
            (parent / group_key).mkdir()

    with pytest.raises(ValueError, match="canonical quarantine"):
        SwappingQuarantine(tmp_path).persist(observation())


def test_finding_publication_rejects_a_symlinked_lock_file(tmp_path: Path):
    quarantine = CrashQuarantine(tmp_path)
    crash = quarantine.persist(observation())
    fingerprint = "f" * 64
    destination = tmp_path / "projects" / "7" / "findings" / fingerprint
    destination.mkdir(parents=True)
    outside = tmp_path / "outside-lock"
    outside.write_bytes(b"outside")
    (destination / ".lock").symlink_to(outside)

    with pytest.raises(ValueError, match="lock"):
        FindingArtifactStore(quarantine).publish(
            fingerprint, crash, b"crash", artifact_evidence(fingerprint), artifact_triage(),
        )


def test_finding_publication_rejects_a_tampered_occurrence_record(tmp_path: Path):
    quarantine = CrashQuarantine(tmp_path)
    crash = quarantine.persist(observation())
    fingerprint = "e" * 64
    destination = tmp_path / "projects" / "7" / "findings" / fingerprint / "occurrences"
    destination.mkdir(parents=True)
    outside = tmp_path / "outside-occurrence"
    outside.write_bytes(b"outside")
    name = f"{crash.group_key}-{crash.occurrence}.json"
    (destination / name).symlink_to(outside)

    with pytest.raises(ValueError, match="occurrence"):
        FindingArtifactStore(quarantine).publish(
            fingerprint, crash, b"crash", artifact_evidence(fingerprint), artifact_triage(),
        )
