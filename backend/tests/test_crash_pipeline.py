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
from backend.fuzzing.crashes.artifacts import FindingArtifactStore, FindingRecoveryRequired
from backend.fuzzing.crashes.correction import (
    CorrectionCandidate,
    CorrectionImage,
    HarnessCorrectionExperiment,
)
from backend.fuzzing.crashes.triage import CrashPipeline, CrashTriageEvidence
from backend.models.finding import Finding


NOW = datetime(2026, 7, 20, tzinfo=UTC)


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
        await asyncio.sleep(0)
        key = (values["project_id"], values["fingerprint"])
        existing = self.rows.get(key)
        count = 1 if existing is None else existing.occurrence_count + 1
        selected_values = values if existing is None or values["candidate_selected"] else {
            **values,
            "classification": existing.classification,
            "description": existing.description,
            "reproducible": existing.reproducible,
        }
        priority_reason = (
            f"{selected_values['classification']}; "
            f"{'reproducible' if selected_values['reproducible'] else 'not reproducible'}; "
            f"observed {count} {'time' if count == 1 else 'times'}"
        )
        finding = Finding(
            id=len(self.rows) + 1 if existing is None else existing.id,
            project_id=values["project_id"],
            fingerprint=values["fingerprint"],
            classification=selected_values["classification"],
            priority_rank=1,
            priority_reason=priority_reason,
            description=selected_values["description"],
            reproducible=selected_values["reproducible"],
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
    expected = min((b"one", b"two"), key=lambda value: __import__("hashlib").sha256(value).hexdigest())
    assert retained == expected
    assert metadata == {"sha256": __import__("hashlib").sha256(retained).hexdigest(), "size": len(retained)}


def test_parallel_duplicates_keep_database_fields_and_selected_artifact_consistent(tmp_path: Path):
    service, repository, _ = pipeline(tmp_path)

    async def exercise():
        return await asyncio.gather(
            service.process(observation(input_bytes=b"one")),
            service.process(observation(input_bytes=b"two")),
        )

    first, second = run(exercise())
    finding = repository.rows[(7, first.fingerprint)]

    assert first.id == second.id == finding.id
    assert finding.occurrence_count == 2
    assert service.artifacts.detail(finding)["reproducer"]["size"] == len(
        service.artifacts.read_reproducer(finding)
    )
    assert all(call["classification"] == finding.classification for call in repository.calls)


def test_representative_policy_updates_database_only_when_candidate_becomes_selected(tmp_path: Path):
    class SequenceSpecialist(Specialist):
        def __init__(self):
            super().__init__()
            self.classifications = iter(("unresolved", "true vulnerability", "unresolved"))

        async def triage(self, evidence):
            self.classification = next(self.classifications)
            return await super().triage(evidence)

    service, repository, _ = pipeline(tmp_path, specialist=SequenceSpecialist())

    run(service.process(observation(input_bytes=b"first-long-input")))
    run(service.process(observation(input_bytes=b"second-long-input")))
    finding = run(service.process(observation(input_bytes=b"x")))

    assert [call["candidate_selected"] for call in repository.calls] == [True, True, False]
    assert finding.classification == "true vulnerability"
    assert finding.occurrence_count == 3
    assert service.artifacts.detail(finding)["reproducer"]["size"] == len(
        service.artifacts.read_reproducer(finding)
    )


def test_database_failure_durably_rolls_back_a_new_selected_pointer(tmp_path: Path):
    class FailingFindings:
        async def create_or_increment(self, **_values):
            raise RuntimeError("injected database failure")

    service, _, _ = pipeline(tmp_path)
    service._findings = FailingFindings()
    with pytest.raises(RuntimeError, match="database failure"):
        run(service.process(observation()))

    roots = [path for path in (tmp_path / "projects/7/findings").iterdir() if path.is_dir()]
    assert len(roots) == 1
    root = roots[0]
    assert not (root / "current.json").exists()
    assert list((root / "generations").iterdir()) == []


def test_database_failure_with_uncertain_pointer_rollback_requires_recovery(tmp_path: Path):
    class RollbackFailingStore(FindingArtifactStore):
        armed = False

        def _sync_pointer_directory(self, directory, phase):
            if self.armed and phase == "rollback":
                raise OSError("injected database rollback fsync failure")
            return super()._sync_pointer_directory(directory, phase)

    class FailingFindings:
        async def create_or_increment(self, **_values):
            raise RuntimeError("injected database failure")

    service, _, _ = pipeline(tmp_path)
    store = RollbackFailingStore(service.quarantine)
    service.artifacts = store
    run(service.process(observation(input_bytes=b"first-long-input")))
    service._findings = FailingFindings()
    store.armed = True

    with pytest.raises(FindingRecoveryRequired, match="requires reconciliation"):
        run(service.process(observation(input_bytes=b"x")))

    root = next((tmp_path / "projects/7/findings").iterdir())
    assert len(list((root / "generations").iterdir())) == 2


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


def test_fabricated_correction_dictionary_cannot_classify_a_false_positive(tmp_path: Path):
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

    assert finding.classification == "unresolved"
    assert correction.calls == []


def test_validated_correction_uses_persisted_lineage_exact_images_and_runs_once_per_group(tmp_path: Path):
    from backend.models.asset import CampaignAsset

    original_asset = CampaignAsset(
        31, 7, "target", "parser", "1" * 64, None, NOW, NOW, None,
    )
    corrected_asset = CampaignAsset(
        99, 7, "target", "parser correction", "2" * 64, 31, NOW, NOW, None,
    )

    class Assets:
        async def get(self, asset_id):
            return {31: original_asset, 99: corrected_asset}.get(asset_id)

    class Images:
        def inspect_exact(self, image_id):
            corrected = image_id == "sha256:" + "e" * 64
            labels = {
                "bigeye.project": "7", "bigeye.commit": "a" * 40, "bigeye.layer": "target",
                "bigeye.content-hash": ("5" if corrected else "4") * 64,
                "bigeye.target-asset": "99" if corrected else "31",
                "bigeye.target-content-hash": ("2" if corrected else "1") * 64,
            }
            if corrected:
                labels["bigeye.parent-target-asset"] = "31"
            return CorrectionImage(image_id, "linux", "amd64", labels)

    class Builder:
        def __init__(self):
            self.calls = 0

        async def create_child(self, crash, input_bytes, original):
            self.calls += 1
            return CorrectionCandidate(99, "sha256:" + "e" * 64)

    class CorrectionReplay(Replay):
        async def replay(self, crash, input_bytes, variant):
            if crash.target_asset_id == 99:
                self.calls.append((variant, input_bytes))
                return ReplayResult(
                    variant="original", crashed=False, signal=None, stack="", sanitizer="address",
                    source_location=None, coverage=(), exit_code=0, image_id=crash.image_id,
                )
            return await super().replay(crash, input_bytes, variant)

    replayer = CorrectionReplay()
    builder = Builder()
    correction = HarnessCorrectionExperiment(Assets(), Images(), builder, replayer)
    service, _, _ = pipeline(tmp_path, replay=replayer, specialist=Specialist("true vulnerability"), corrector=correction)
    crash = observation(harness_misuse_evidence=("probe:invalid-call-order",))

    first = run(service.process(crash))
    second = run(service.process(replace(crash, input_bytes=b"other")))

    assert first.classification == "harness-induced false positive"
    assert second.classification == "harness-induced false positive"
    assert builder.calls == 1
    correction_detail = service.artifacts.detail(second)["correction"]
    assert correction_detail["corrected_asset_id"] == 99
    assert correction_detail["signature_disappeared"] is True


def test_correction_evidence_rejects_a_contradictory_disappearance_claim():
    from backend.fuzzing.crashes.correction import CorrectionEvidence

    with pytest.raises(ValueError, match="disappearance"):
        CorrectionEvidence(
            project_id=7, target_asset_id=31, corrected_asset_id=99,
            base_image_id="sha256:" + "b" * 64,
            corrected_image_id="sha256:" + "e" * 64,
            target_asset_content_hash="1" * 64,
            corrected_asset_content_hash="2" * 64,
            base_manifest_hash="4" * 64,
            corrected_manifest_hash="5" * 64,
            commit_sha="a" * 40, base_signature="1" * 64,
            corrected_signature="2" * 64, signature_disappeared=True,
            evidence_id="correction:" + "3" * 64,
        )


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

    finding = run(service.process(observation()))

    assert "exploit" not in finding.description.casefold()
    assert "code execution" not in finding.description.casefold()
    assert finding.description == (
        "Reproduced address sanitizer failure near src/parser.c:42; "
        "investigate the affected operation."
    )


def test_unproven_exploitability_claim_is_removed_from_priority_rationale(tmp_path: Path):
    service, _, _ = pipeline(
        tmp_path,
        specialist=Specialist(priority="Priority one because remote code execution is exploitable."),
    )

    finding = run(service.process(observation()))

    assert "exploit" not in finding.priority_reason.casefold()
    assert "code execution" not in finding.priority_reason.casefold()


def test_model_authored_claims_never_reach_finding_detail_fields(tmp_path: Path):
    class HostileSpecialist:
        async def triage(self, evidence):
            claim = "Proven exploitable RCE with attacker-controlled code execution."
            return TriageResult(
                classification="true vulnerability",
                description=claim,
                evidence_ids=list(evidence.evidence_ids),
                uncertainty=claim,
                priority_rationale=claim,
                repair_intent=claim,
            )

    service, _, _ = pipeline(tmp_path, specialist=HostileSpecialist())

    finding = run(service.process(observation()))
    published = service.artifacts.detail(finding)
    text = json.dumps({"description": finding.description, **published}).casefold()

    assert "exploit" not in text
    assert "code execution" not in text
    assert "attacker-controlled" not in text


def test_empty_crashing_input_is_retained_as_a_valid_reproducer(tmp_path: Path):
    service, _, _ = pipeline(tmp_path)

    finding = run(service.process(observation(input_bytes=b"")))

    assert service.artifacts.read_reproducer(finding) == b""
    assert service.artifacts.detail(finding)["reproducer"]["size"] == 0


def test_fingerprint_normalises_addresses_and_ignores_incidental_coverage():
    left = ReplayResult(
        variant="original", crashed=True, signal="SIGSEGV",
        stack="#0 0x1234 in parse src/a.c:42", sanitizer="address",
        source_location="src/a.c:42", coverage=("src/a.c:41", "src/a.c:42"), exit_code=-11,
        image_id="sha256:" + "b" * 64,
    )
    right = replace(left, stack="#0 0xabcdef in parse src/a.c:42")
    changed = replace(left, coverage=("src/a.c:41", "src/a.c:99"))

    assert crash_fingerprint(left) == crash_fingerprint(right)
    assert crash_fingerprint(left) == crash_fingerprint(changed)


def test_fingerprint_keeps_distinct_project_crash_sites_separate():
    first = ReplayResult(
        variant="original", crashed=True, signal="SIGSEGV",
        stack="#0 0x1234 in parse src/a.c:42\n#1 libc.so", sanitizer="address",
        source_location="src/a.c:42", coverage=("src/a.c:42",), exit_code=-11,
        image_id="sha256:" + "b" * 64,
    )
    second = replace(first, stack="#0 0x999 in parse src/b.c:9\n#1 libc.so", source_location="src/b.c:9")
    incidental = replace(first, stack="#0 0x9999 in parse src/a.c:42\n#1 changed-libc.so")

    assert crash_fingerprint(first) != crash_fingerprint(second)
    assert crash_fingerprint(first) == crash_fingerprint(incidental)


def test_fingerprint_keeps_symbolized_no_extension_functions_and_removes_runtime_aslr_noise():
    base = ReplayResult(
        variant="original", crashed=True, signal="SIGSEGV",
        stack="#0 0x1234 in parse_one (/opt/project/parser+0xab)\n#1 0x456 in __libc_start_main libc.so.6+0x99",
        sanitizer="address", source_location=None, coverage=(), exit_code=-11,
        image_id="sha256:" + "b" * 64,
    )
    same = replace(
        base,
        stack="#0 0xdeadbeef in parse_one (/different/root/parser+0xff)\n#1 0x999 in abort libc.so.6+0x12",
    )
    distinct = replace(base, stack="#0 0x777 in parse_two (/opt/project/parser+0x01)")

    assert crash_fingerprint(base) == crash_fingerprint(same)
    assert crash_fingerprint(base) != crash_fingerprint(distinct)


def test_replay_result_rejects_unvalidated_signal_and_sanitizer_names():
    with pytest.raises(ValueError, match="signal"):
        ReplayResult(
            variant="original", crashed=True, signal="not-a-signal", stack="#0 parse src/a.c:42",
            sanitizer="address", source_location="src/a.c:42", coverage=(), exit_code=-1,
            image_id="sha256:" + "b" * 64,
        )
    with pytest.raises(ValueError, match="sanitizer"):
        ReplayResult(
            variant="original", crashed=True, signal="SIGSEGV", stack="#0 parse src/a.c:42",
            sanitizer="<script>", source_location="src/a.c:42", coverage=(), exit_code=-1,
            image_id="sha256:" + "b" * 64,
        )


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


def test_observation_rejects_aggregate_metadata_before_json_serialisation_or_publication(tmp_path: Path, monkeypatch):
    import backend.fuzzing.crashes.quarantine as quarantine_module

    large_coverage = tuple(f"src/{'a' * 1000}{index}.c:1" for index in range(3_000))
    monkeypatch.setattr(
        quarantine_module.json, "dumps",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("json.dumps must not run")),
    )

    with pytest.raises(ValueError, match="metadata exceeds"):
        observation(coverage=large_coverage)

    assert not (tmp_path / "projects").exists()


def test_observation_caps_evidence_sources_to_the_specialist_output_bound():
    images = tuple((f"sanitizer-{index}", "sha256:" + f"{index:064x}") for index in range(17))
    with pytest.raises(ValueError, match="sanitizer variants"):
        observation(compatible_sanitizer_variants=images)
    with pytest.raises(ValueError, match="harness evidence"):
        observation(harness_misuse_evidence=tuple(f"probe:{index}" for index in range(17)))


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


def test_finding_artefacts_publish_one_immutable_generation_and_pointer(tmp_path: Path):
    quarantine = CrashQuarantine(tmp_path)
    crash = quarantine.persist(observation())
    fingerprint = "d" * 64
    store = FindingArtifactStore(quarantine)

    store.publish(fingerprint, crash, b"crash", artifact_evidence(fingerprint), artifact_triage())

    root = tmp_path / "projects" / "7" / "findings" / fingerprint
    pointer = json.loads((root / "current.json").read_text())
    generation = root / "generations" / pointer["generation"]
    assert set(path.name for path in generation.iterdir()) == {"minimal.bin", "evidence.json"}
    assert (generation / "minimal.bin").read_bytes() == b"crash"
    assert not (root / "minimal.bin").exists()
    assert not (root / "evidence.json").exists()
    assert generation.stat().st_mode & 0o222 == 0
    assert all(path.stat().st_mode & 0o222 == 0 for path in generation.iterdir())


def test_failed_generation_update_keeps_the_previous_complete_generation(tmp_path: Path):
    quarantine = CrashQuarantine(tmp_path)
    first = quarantine.persist(observation(input_bytes=b"first"))
    second = quarantine.persist(observation(input_bytes=b"second"))
    fingerprint = "c" * 64
    store = FindingArtifactStore(quarantine)
    store.publish(fingerprint, first, b"larger", artifact_evidence(fingerprint), artifact_triage())
    root = tmp_path / "projects" / "7" / "findings" / fingerprint
    previous_pointer = (root / "current.json").read_bytes()

    class FailingPointerStore(FindingArtifactStore):
        def _before_pointer_switch(self, _directory, _generation):
            raise RuntimeError("forced pointer failure")

    with pytest.raises(RuntimeError, match="forced pointer failure"):
        FailingPointerStore(quarantine).publish(
            fingerprint, second, b"x", artifact_evidence(fingerprint), artifact_triage(),
        )

    assert (root / "current.json").read_bytes() == previous_pointer
    assert [path.name for path in (root / "generations").iterdir()] == [
        json.loads(previous_pointer)["generation"]
    ]
    finding = replace(
        Findings().rows.get((7, fingerprint), None) or Finding(
            5, 7, fingerprint, "unresolved", 1, "reason", "description", True, 1,
            datetime(2026, 7, 20, tzinfo=UTC), datetime(2026, 7, 20, tzinfo=UTC), None,
        )
    )
    assert store.read_reproducer(finding) == b"larger"


@pytest.mark.parametrize("failure", ["replace", "fsync"])
def test_pointer_publication_failure_durably_restores_the_previous_generation(tmp_path: Path, failure: str):
    quarantine = CrashQuarantine(tmp_path)
    first = quarantine.persist(observation(input_bytes=b"first"))
    second = quarantine.persist(observation(input_bytes=b"second"))
    fingerprint = "b" * 64

    class FailingStore(FindingArtifactStore):
        armed = False

        def _replace_pointer(self, directory, temporary, phase):
            if self.armed and phase == "publication" and failure == "replace":
                raise OSError("injected replace failure")
            return super()._replace_pointer(directory, temporary, phase)

        def _sync_pointer_directory(self, directory, phase):
            if self.armed and phase == "publication" and failure == "fsync":
                raise OSError("injected fsync failure")
            return super()._sync_pointer_directory(directory, phase)

    store = FailingStore(quarantine)
    store.publish(fingerprint, first, b"larger", artifact_evidence(fingerprint), artifact_triage())
    root = tmp_path / "projects/7/findings" / fingerprint
    previous = (root / "current.json").read_bytes()
    store.armed = True

    with pytest.raises(OSError, match=failure):
        store.publish(fingerprint, second, b"x", artifact_evidence(fingerprint), artifact_triage())

    assert (root / "current.json").read_bytes() == previous
    assert [path.name for path in (root / "generations").iterdir()] == [
        json.loads(previous)["generation"]
    ]


def test_uncertain_pointer_rollback_retains_both_complete_generations_for_recovery(tmp_path: Path):
    quarantine = CrashQuarantine(tmp_path)
    first = quarantine.persist(observation(input_bytes=b"first"))
    second = quarantine.persist(observation(input_bytes=b"second"))
    fingerprint = "9" * 64

    class UncertainStore(FindingArtifactStore):
        armed = False

        def _sync_pointer_directory(self, directory, phase):
            if self.armed and phase in {"publication", "rollback"}:
                raise OSError(f"injected {phase} fsync failure")
            return super()._sync_pointer_directory(directory, phase)

    store = UncertainStore(quarantine)
    store.publish(fingerprint, first, b"larger", artifact_evidence(fingerprint), artifact_triage())
    root = tmp_path / "projects/7/findings" / fingerprint
    store.armed = True

    with pytest.raises(FindingRecoveryRequired, match="reconciliation"):
        store.publish(fingerprint, second, b"x", artifact_evidence(fingerprint), artifact_triage())

    generations = list((root / "generations").iterdir())
    assert len(generations) == 2
    assert all({path.name for path in generation.iterdir()} == {"minimal.bin", "evidence.json"} for generation in generations)
    assert all(generation.stat().st_mode & 0o222 == 0 for generation in generations)
