from __future__ import annotations

import hashlib
import os
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


def _clean_execution(prepared, target, *, lines=frozenset({"parser.c:12"})):
    from backend.fuzzing.corpus.admission import ExecutionEvidence

    return ExecutionEvidence(
        executed=True,
        ok=True,
        clean=True,
        clean_line_delta=lines,
        content_sha256=prepared.content_sha256,
        target_contract=target,
    )


def _durable_admission(path, contract, *, useful=True):
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate

    lines = frozenset({"parser.c:12"}) if useful else frozenset()
    return CorpusAdmission(
        lambda prepared, target: _clean_execution(prepared, target, lines=lines),
    ).validate(CorpusCandidate(path, path.name), contract.identifier)

def test_seed_is_admitted_only_after_execution_and_useful_clean_evidence(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "tests" / "sample.bin"
    seed.parent.mkdir()
    seed.write_bytes(b"sample")
    candidate = CorpusCandidate(seed, "tests/sample.bin")
    admitted = CorpusAdmission(_clean_execution).validate(candidate, "target-contract")
    redundant = CorpusAdmission(
        lambda prepared, target: _clean_execution(prepared, target, lines=frozenset()),
    ).validate(candidate, "target-contract")

    assert admitted.admitted is True
    assert admitted.provenance == "tests/sample.bin"
    assert admitted.first_clean_delta == ("line:parser.c:12",)
    assert redundant.admitted is False
    assert redundant.reason == "candidate adds no clean coverage or behaviour"


def test_public_admit_never_claims_durable_admission_from_caller_evidence(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "seed"
    seed.write_bytes(b"seed")
    result = CorpusAdmission().admit(
        CorpusCandidate(seed, "seed"),
        ExecutionEvidence(True, True, True, frozenset({"target.c:1"}), content_sha256="claimed", target_contract="claimed"),
    )

    assert result.admitted is False
    assert result.reason == "caller-supplied evidence is not durable; use validate"

    secret = tmp_path / "secret"
    secret.write_bytes(b"do-not-read")
    linked = tmp_path / "linked"
    linked.symlink_to(secret)
    linked_result = CorpusAdmission().admit(
        CorpusCandidate(linked, "linked"),
        ExecutionEvidence(True, True, True),
    )
    assert linked_result.content_sha256 == ""


def test_validate_executes_candidate_and_rejects_a_known_content_hash(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "sample"
    seed.write_bytes(b"same")
    calls = []

    def execute(prepared, target):
        calls.append((prepared, target))
        return _clean_execution(prepared, target, lines=frozenset({"target.c:2"}))

    policy = CorpusAdmission(execute)
    candidate = CorpusCandidate(seed, "examples/sample")
    first = policy.validate(candidate, "target")
    duplicate = policy.validate(candidate, "target", known_hashes={first.content_sha256})

    assert len(calls) == 1
    assert first.admitted is True
    assert duplicate.admitted is False
    assert duplicate.reason == "candidate content is already present"
    assert calls[0][0].content == b"same"


def test_admission_binds_execution_to_candidate_digest_identity_and_target_contract(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "seed"
    seed.write_bytes(b"original")

    def wrong_digest(prepared, target):
        return ExecutionEvidence(True, True, True, frozenset({"a.c:1"}), content_sha256="0" * 64, target_contract=target)

    def wrong_target(prepared, _target):
        return ExecutionEvidence(True, True, True, frozenset({"a.c:1"}), content_sha256=prepared.content_sha256, target_contract="other")

    assert CorpusAdmission(wrong_digest).validate(CorpusCandidate(seed, "seed"), "target").admitted is False
    assert CorpusAdmission(wrong_target).validate(CorpusCandidate(seed, "seed"), "target").admitted is False


@pytest.mark.parametrize(
    ("executed", "ok", "clean", "lines", "reason"),
    [
        (False, True, True, frozenset({"a.c:1"}), "candidate was not executed"),
        (True, False, True, frozenset({"a.c:1"}), "candidate is invalid for the target"),
        (True, True, False, frozenset({"a.c:1"}), "candidate has no clean execution evidence"),
        (True, True, True, frozenset({" "}), "execution evidence contains blank identifiers"),
    ],
)
def test_validate_rejects_non_durable_or_blank_execution_evidence(
    tmp_path: Path,
    executed: bool,
    ok: bool,
    clean: bool,
    lines,
    reason: str,
) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "seed"
    seed.write_bytes(b"seed")

    def execute(prepared, target):
        return ExecutionEvidence(executed, ok, clean, lines, content_sha256=prepared.content_sha256, target_contract=target)

    result = CorpusAdmission(execute).validate(CorpusCandidate(seed, "seed"), "target")

    assert result.admitted is False
    assert result.reason == reason


def test_admission_rejects_candidate_path_swap_during_execution(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate

    seed = tmp_path / "seed"
    seed.write_bytes(b"original")

    def swap(prepared, target):
        seed.rename(tmp_path / "held-original")
        seed.write_bytes(b"replacement")
        return _clean_execution(prepared, target)

    with pytest.raises(ValueError, match="changed during execution"):
        CorpusAdmission(swap).validate(CorpusCandidate(seed, "seed"), "target")


def test_admission_rejects_candidate_replaced_after_discovery_even_with_same_bytes(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, SeedCollector

    repository = tmp_path / "repository"
    seed = repository / "tests" / "seed"
    seed.parent.mkdir(parents=True)
    seed.write_bytes(b"same")
    candidate = SeedCollector().collect(repository)[0]
    seed.unlink()
    seed.write_bytes(b"same")

    with pytest.raises(ValueError, match="changed since discovery"):
        CorpusAdmission(_clean_execution).validate(candidate, "target")


def test_seed_collection_is_bounded_contained_and_requires_citations_for_agent_proposals(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusCandidate, SeedCollector

    repository = tmp_path / "repository"
    for relative in ("tests/one.bin", "examples/two.bin", "src/not-a-seed.c"):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode())
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    (repository / "samples").mkdir()
    (repository / "samples/link.bin").symlink_to(outside)

    cited = CorpusCandidate(repository / "src/not-a-seed.c", "src/not-a-seed.c", ("source:src/not-a-seed.c:1",))
    uncited = CorpusCandidate(repository / "src/not-a-seed.c", "src/not-a-seed.c")
    collected = SeedCollector(max_candidates=2).collect(repository, (cited, uncited))

    assert len(collected) == 2
    assert all(candidate.path.is_relative_to(repository) for candidate in collected)
    assert all(not candidate.path.is_symlink() for candidate in collected)
    assert any(candidate.evidence_ids for candidate in collected)


def test_seed_collection_stops_early_without_following_git_symlinks_or_deep_trees(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusCandidate, SeedCollector

    repository = tmp_path / "repository"
    (repository / ".git/tests").mkdir(parents=True)
    (repository / ".git/tests/secret").write_bytes(b"secret")
    (repository / "tests").mkdir()
    for index in range(12):
        (repository / "tests" / f"{index:02}.bin").write_bytes(b"1234")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "host").write_bytes(b"host")
    (repository / "tests/linked").symlink_to(outside, target_is_directory=True)
    blank = CorpusCandidate(repository / "tests/00.bin", "tests/00.bin", (" ",))

    collected = SeedCollector(
        max_candidates=10,
        max_entries=5,
        max_directories=4,
        max_depth=2,
        max_total_bytes=8,
    ).collect(repository, (blank,))

    assert len(collected) <= 2
    assert all(".git" not in candidate.path.parts for candidate in collected)
    assert all("linked" not in candidate.path.parts for candidate in collected)
    assert all(candidate.evidence_ids != (" ",) for candidate in collected)


class _NativeRunner:
    def __init__(self):
        self.commands: list[tuple[str, ...]] = []

    def run(
        self, campaign, command: tuple[str, ...], output: Path, source: Path | None = None,
    ) -> None:
        self.commands.append(command)
        if command[0] in {"afl-cmin", campaign.target_command[0]}:
            output.mkdir(parents=True, exist_ok=True)
            selected = campaign.corpus_dir / "keep"
            (output / "keep").write_bytes(selected.read_bytes())
        elif command[0] == "afl-tmin":
            assert source is not None and source.is_file()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"k")


class _FakeContainerController:
    def __init__(
        self,
        corpus,
        *,
        active=True,
        stop_verified=True,
        campaign_id=7,
        project_id=3,
        identity_path=None,
        quiesce_error=None,
        inspect_after_quiesce_error=None,
        resume_error=None,
        replacement_error=None,
    ):
        from backend.fuzzing.corpus.quiescence import CampaignWriterIdentity

        self._identity_type = CampaignWriterIdentity
        self._campaign_id = campaign_id
        self._project_id = project_id
        self._identity_path = Path(os.path.abspath(identity_path or corpus))
        self._follow_canonical_path = identity_path is None
        self._refresh_identity()
        self.active = active
        self.stop_verified = stop_verified
        self.state = "running" if active else "stopped"
        self.quiesce_error = quiesce_error
        self.inspect_after_quiesce_error = inspect_after_quiesce_error
        self.resume_error = resume_error
        self.replacement_error = replacement_error
        self.calls = []
        self.writer_gate = threading.Lock()
        self._gate_held = False
        self._quiesce_failed = False

    def resolve(self, project_id, campaign_id):
        self.calls.append(("resolve", project_id, campaign_id))
        if self._follow_canonical_path:
            self._refresh_identity()
        return self.identity

    def inspect(self, identity):
        from backend.fuzzing.corpus.quiescence import CampaignWriterState

        self.calls.append(("inspect", identity))
        if self._quiesce_failed and self.inspect_after_quiesce_error is not None:
            raise self.inspect_after_quiesce_error
        return CampaignWriterState(self.identity, self.state, self.active)

    def quiesce(self, identity):
        self.calls.append(("quiesce", identity))
        if self.stop_verified:
            self.writer_gate.acquire()
            self._gate_held = True
            self.active = False
            self.state = "stopped"
        if self.quiesce_error is not None:
            self._quiesce_failed = True
            raise self.quiesce_error

    def resume(self, identity, prior_state):
        self.calls.append(("resume", identity, prior_state))
        if self.resume_error is not None:
            raise self.resume_error
        self.active = prior_state.active
        self.state = prior_state.state
        if self._gate_held:
            self._gate_held = False
            self.writer_gate.release()

    def replace(self, identity, prior_state):
        self.calls.append(("replace", identity, prior_state))
        if self.replacement_error is not None:
            raise self.replacement_error
        self._refresh_identity(container_id="container-7-replacement")
        self.active = prior_state.active
        self.state = prior_state.state
        if self._gate_held:
            self._gate_held = False
            self.writer_gate.release()
        return self.identity

    def _refresh_identity(self, container_id="container-7"):
        identity_stat = os.stat(self._identity_path, follow_symlinks=False)
        self.identity = self._identity_type(
            self._campaign_id,
            self._project_id,
            container_id,
            self._identity_path,
            identity_stat.st_dev,
            identity_stat.st_ino,
        )


def _quiesced_minimiser(runner, coverage, corpus, controller=None):
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceService

    controller = controller or _FakeContainerController(corpus)
    return CorpusMinimiser(
        runner,
        coverage,
        quiescence_service=CampaignQuiescenceService(controller),
    )


def _owned_campaign(engine, corpus, target_command):
    from backend.fuzzing.corpus.minimisation import CorpusCampaign

    return CorpusCampaign(engine, corpus, target_command, id=7, project_id=3)


def test_afl_minimisation_uses_native_tools_and_replaces_only_after_coverage_preservation(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign" / "corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"keep")
    (corpus / "drop").write_bytes(b"drop")
    campaign = _owned_campaign("afl++", corpus, ("/opt/bigeye/target", "@@"))
    runner = _NativeRunner()
    controller = _FakeContainerController(corpus)
    original_identity = controller.identity
    minimiser = _quiesced_minimiser(
        runner, lambda _campaign, _corpus: frozenset({"parser.c:12"}), corpus, controller,
    )

    result = minimiser.minimise(campaign)

    assert result.replaced is True
    assert result.before_count == 2
    assert result.after_count == 1
    assert [command[0] for command in runner.commands] == ["afl-cmin", "afl-tmin"]
    assert (corpus / "keep").read_bytes() == b"k"
    assert not (corpus / "drop").exists()
    assert controller.identity.container_id != original_identity.container_id
    assert controller.identity.corpus_inode == corpus.stat().st_ino
    assert controller.identity.corpus_inode != original_identity.corpus_inode
    assert [call[0] for call in controller.calls].count("replace") == 1
    assert [call[0] for call in controller.calls].count("resume") == 0
    assert not tuple(corpus.parent.glob(".corpus.retired-*"))


def test_minimisation_keeps_original_corpus_when_clean_coverage_is_lost(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign" / "corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"keep")
    campaign = CorpusCampaign("libfuzzer", corpus, ("/opt/bigeye/target",))
    runner = _NativeRunner()

    def coverage(_campaign, path):
        return frozenset({"parser.c:12"}) if path == corpus else frozenset()

    result = CorpusMinimiser(runner, coverage).minimise(campaign)

    assert result.replaced is False
    assert result.reason == "minimised corpus did not preserve clean coverage"
    assert (corpus / "keep").read_bytes() == b"keep"
    assert runner.commands[0][:2] == ("/opt/bigeye/target", "-merge=1")
    assert list(corpus.parent.glob("corpus.minimising-*")) == []


def test_libfuzzer_minimisation_preserves_target_arguments_before_merge_flags(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign" / "corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"keep")
    campaign = CorpusCampaign("libfuzzer", corpus, ("/opt/bigeye/target", "--target-mode"))
    runner = _NativeRunner()

    CorpusMinimiser(runner, lambda _campaign, _path: frozenset({"a.c:1"})).minimise(campaign)

    assert runner.commands[0] == (
        "/opt/bigeye/target", "--target-mode", "-merge=1", "/campaign/minimised", "/campaign/corpus",
    )


def test_minimisation_rejects_symlinked_native_output_without_touching_its_target(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"keep")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel").write_bytes(b"safe")

    class SymlinkRunner:
        def run(self, _campaign, _command, output):
            output.rmdir()
            output.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="native output directory changed"):
        CorpusMinimiser(SymlinkRunner(), lambda _campaign, _path: frozenset({"a.c:1"})).minimise(
            CorpusCampaign("libfuzzer", corpus, ("/target",)),
        )

    assert (corpus / "keep").read_bytes() == b"keep"
    assert (outside / "sentinel").read_bytes() == b"safe"
    assert not any(path.is_symlink() for path in corpus.parent.iterdir())


def test_minimisation_rejects_corpus_directory_swap_across_clean_probe(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"keep")
    moved = corpus.with_name("held-original")
    calls = 0

    def coverage(_campaign, path):
        nonlocal calls
        calls += 1
        if calls == 1:
            path.rename(moved)
            path.mkdir()
            (path / "attacker").write_bytes(b"attacker")
        return frozenset({"a.c:1"})

    with pytest.raises(ValueError, match="corpus directory changed"):
        CorpusMinimiser(_NativeRunner(), coverage).minimise(CorpusCampaign("libfuzzer", corpus, ("/target",)))

    assert (moved / "keep").read_bytes() == b"keep"
    assert (corpus / "attacker").read_bytes() == b"attacker"


def test_minimisation_restores_original_when_candidate_publication_fails(tmp_path: Path, monkeypatch) -> None:
    import backend.fuzzing.corpus.minimisation as module

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    campaign = _owned_campaign("libfuzzer", corpus, ("/target",))
    controller = _FakeContainerController(corpus)
    original_identity = controller.identity
    real_replace = module.os.replace
    failed = False

    def fail_candidate(source, destination, *args, **kwargs):
        nonlocal failed
        if not failed and str(source).startswith(".corpus.minimising-") and destination == "corpus":
            failed = True
            raise OSError("forced publication failure")
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fail_candidate)
    with pytest.raises(OSError, match="forced publication failure"):
        module.CorpusMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=module.CampaignQuiescenceService(controller),
        ).minimise(campaign)

    assert (corpus / "keep").read_bytes() == b"original"
    assert controller.identity == original_identity
    assert [call[0] for call in controller.calls].count("resume") == 1
    assert [call[0] for call in controller.calls].count("replace") == 0


def test_minimisation_recovers_original_after_interrupted_post_publish_cleanup(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    campaign_root = tmp_path / "campaign"
    corpus = campaign_root / "corpus"
    backup = campaign_root / ".corpus.before-minimisation"
    corpus.mkdir(parents=True)
    backup.mkdir()
    (corpus / "keep").write_bytes(b"unverified-candidate")
    (backup / "keep").write_bytes(b"original")

    result = _quiesced_minimiser(
        _NativeRunner(),
        lambda _campaign, _path: frozenset({"a.c:1"}),
        corpus,
    ).minimise(
        _owned_campaign("libfuzzer", corpus, ("/target",)),
    )

    assert result.replaced is True
    assert (corpus / "keep").read_bytes() == b"original"
    assert not backup.exists()


def test_minimisation_serialises_operations_for_one_corpus(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"keep")
    campaign = _owned_campaign("libfuzzer", corpus, ("/target",))

    class ConcurrentRunner(_NativeRunner):
        def __init__(self):
            super().__init__()
            self.active = 0
            self.maximum = 0
            self.guard = threading.Lock()

        def run(self, campaign, command, output):
            with self.guard:
                self.active += 1
                self.maximum = max(self.maximum, self.active)
            time.sleep(0.03)
            try:
                super().run(campaign, command, output)
            finally:
                with self.guard:
                    self.active -= 1

    runner = ConcurrentRunner()
    minimiser = _quiesced_minimiser(runner, lambda _campaign, _path: frozenset({"a.c:1"}), corpus)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: minimiser.minimise(campaign), range(2)))

    assert all(result.replaced for result in results)
    assert runner.maximum == 1


@pytest.mark.parametrize("change", ["added", "changed", "removed"])
def test_minimisation_preserves_live_corpus_changes_made_during_native_runner(tmp_path: Path, change: str) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    keep = corpus / "keep"
    keep.write_bytes(b"original")
    campaign = CorpusCampaign("libfuzzer", corpus, ("/target",))

    class ChangingRunner(_NativeRunner):
        def run(self, campaign, command, output):
            super().run(campaign, command, output)
            if change == "added":
                (corpus / "late").write_bytes(b"late")
            elif change == "changed":
                keep.write_bytes(b"changed")
            else:
                keep.unlink()

    with pytest.raises(ValueError, match="live corpus changed during minimisation"):
        CorpusMinimiser(ChangingRunner(), lambda _campaign, _path: frozenset({"a.c:1"})).minimise(campaign)

    if change == "added":
        assert keep.read_bytes() == b"original"
        assert (corpus / "late").read_bytes() == b"late"
    elif change == "changed":
        assert keep.read_bytes() == b"changed"
    else:
        assert not keep.exists()


def test_minimisation_preserves_live_input_added_during_candidate_coverage_probe(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    calls = 0

    def coverage(_campaign, _path):
        nonlocal calls
        calls += 1
        if calls == 2:
            (corpus / "late-during-probe").write_bytes(b"late")
        return frozenset({"a.c:1"})

    with pytest.raises(ValueError, match="live corpus changed during minimisation"):
        CorpusMinimiser(_NativeRunner(), coverage).minimise(CorpusCampaign("libfuzzer", corpus, ("/target",)))

    assert (corpus / "keep").read_bytes() == b"original"
    assert (corpus / "late-during-probe").read_bytes() == b"late"


def test_minimisation_rejects_candidate_content_swap_after_coverage_probe(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    calls = 0

    def coverage(_campaign, path):
        nonlocal calls
        calls += 1
        if calls == 2:
            candidate = path / "keep"
            candidate.rename(path / "held-candidate")
            candidate.write_bytes(b"original")
        return frozenset({"a.c:1"})

    with pytest.raises(ValueError, match="candidate corpus changed during minimisation"):
        CorpusMinimiser(_NativeRunner(), coverage).minimise(CorpusCampaign("libfuzzer", corpus, ("/target",)))

    assert (corpus / "keep").read_bytes() == b"original"


def test_minimisation_without_quiescence_service_evaluates_but_never_replaces(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")

    result = CorpusMinimiser(_NativeRunner(), lambda _campaign, _path: frozenset({"a.c:1"})).minimise(
        CorpusCampaign("libfuzzer", corpus, ("/target",)),
    )

    assert result.replaced is False
    assert result.reason == "corpus publication requires external-writer quiescence"
    assert (corpus / "keep").read_bytes() == b"original"


def test_quiescence_does_not_run_publication_when_container_stop_is_not_verified(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import (
        CampaignQuiescenceService,
        CampaignWriterStillActive,
    )

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    controller = _FakeContainerController(corpus, stop_verified=False)

    class ObservedMinimiser(CorpusMinimiser):
        publication_started = False

        def _before_quiesced_validation(self, _corpus):
            self.publication_started = True

    minimiser = ObservedMinimiser(
        _NativeRunner(),
        lambda _campaign, _path: frozenset({"a.c:1"}),
        quiescence_service=CampaignQuiescenceService(controller),
    )

    with pytest.raises(CampaignWriterStillActive, match="campaign writer is still active"):
        minimiser.minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert minimiser.publication_started is False
    assert (corpus / "keep").read_bytes() == b"original"
    assert [call[0] for call in controller.calls].count("resume") == 0


@pytest.mark.parametrize("injection", ["during_manifest", "before_replace"])
def test_minimisation_detects_writer_when_provider_does_not_actually_quiesce(tmp_path: Path, injection: str) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    keep = corpus / "keep"
    keep.write_bytes(b"original")
    controller = _FakeContainerController(corpus)

    class InjectingMinimiser(CorpusMinimiser):
        armed = False

        def _before_quiesced_validation(self, _corpus):
            self.armed = True

        def _after_manifest_file(self, _descriptor, _relative_path):
            if self.armed and injection == "during_manifest":
                self.armed = False
                (corpus / "late-during-manifest").write_bytes(b"late")

        def _before_atomic_replace(self, _corpus):
            if injection == "before_replace":
                keep.write_bytes(b"changed-before-replace")

    with pytest.raises(ValueError, match="live corpus changed during minimisation"):
        InjectingMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=CampaignQuiescenceService(controller),
        ).minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    if injection == "during_manifest":
        assert (corpus / "late-during-manifest").read_bytes() == b"late"
    else:
        assert keep.read_bytes() == b"changed-before-replace"


def test_inactive_writer_lost_after_publication_rolls_back_original_before_resume(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import (
        CampaignQuiescenceService,
        CampaignWriterStillActive,
    )

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    keep = corpus / "keep"
    keep.write_bytes(b"original")
    controller = _FakeContainerController(corpus)

    class RestartingWriterMinimiser(CorpusMinimiser):
        def _after_candidate_publication(self, _corpus):
            controller.active = True
            controller.state = "restarting"

    minimiser = RestartingWriterMinimiser(
        _NativeRunner(),
        lambda _campaign, _path: frozenset({"a.c:1"}),
        quiescence_service=CampaignQuiescenceService(controller),
    )
    with pytest.raises(CampaignWriterStillActive, match="campaign writer is still active"):
        minimiser.minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert keep.read_bytes() == b"original"
    assert [call[0] for call in controller.calls].count("resume") == 1
    assert not (corpus.parent / ".corpus.before-minimisation").exists()


def test_commit_fsync_failure_restores_original_before_writer_resumes(tmp_path: Path, monkeypatch) -> None:
    import backend.fuzzing.corpus.minimisation as module

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    keep = corpus / "keep"
    keep.write_bytes(b"original")
    controller = _FakeContainerController(corpus)
    real_fsync = module.os.fsync
    failed = False

    def fail_after_backup_retirement(descriptor):
        nonlocal failed
        retired = tuple(corpus.parent.glob(".corpus.retired-*"))
        if not failed and retired and not (corpus.parent / ".corpus.before-minimisation").exists():
            failed = True
            raise OSError("forced commit fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", fail_after_backup_retirement)
    minimiser = module.CorpusMinimiser(
        _NativeRunner(),
        lambda _campaign, _path: frozenset({"a.c:1"}),
        quiescence_service=module.CampaignQuiescenceService(controller),
    )

    with pytest.raises(OSError, match="forced commit fsync failure"):
        minimiser.minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert keep.read_bytes() == b"original"
    assert [call[0] for call in controller.calls].count("resume") == 1
    assert not tuple(corpus.parent.glob(".corpus.retired-*"))


@pytest.mark.parametrize("mismatch", ["campaign", "project", "corpus"])
def test_quiescence_rejects_foreign_writer_identity_and_corpus_before_transition(
    tmp_path: Path,
    mismatch: str,
) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignOwnershipMismatch, CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    foreign = tmp_path / "foreign-corpus"
    foreign.mkdir()
    controller = _FakeContainerController(
        corpus,
        campaign_id=8 if mismatch == "campaign" else 7,
        project_id=4 if mismatch == "project" else 3,
        identity_path=foreign if mismatch == "corpus" else corpus,
    )

    with pytest.raises(CampaignOwnershipMismatch, match="does not own the requested campaign corpus"):
        CorpusMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=CampaignQuiescenceService(controller),
        ).minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert (corpus / "keep").read_bytes() == b"original"
    assert not any(call[0] in {"quiesce", "resume"} for call in controller.calls)


def test_partial_quiesce_failure_resumes_only_after_safe_stopped_state_is_verified(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    primary = RuntimeError("stop failed after stopping")
    controller = _FakeContainerController(corpus, quiesce_error=primary)

    with pytest.raises(RuntimeError, match="stop failed after stopping") as caught:
        CorpusMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=CampaignQuiescenceService(controller),
        ).minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert caught.value is primary
    assert (corpus / "keep").read_bytes() == b"original"
    assert [call[0] for call in controller.calls].count("resume") == 1


def test_partial_quiesce_with_unknown_state_never_resumes_writer(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceRecoveryError, CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    primary = RuntimeError("partial stop")
    inspection = RuntimeError("state unavailable")
    controller = _FakeContainerController(
        corpus,
        quiesce_error=primary,
        inspect_after_quiesce_error=inspection,
    )

    with pytest.raises(CampaignQuiescenceRecoveryError) as caught:
        CorpusMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=CampaignQuiescenceService(controller),
        ).minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert caught.value.primary_error is primary
    assert caught.value.recovery_error is inspection
    assert caught.value.recovery_required is True
    assert [call[0] for call in controller.calls].count("resume") == 0


def test_partial_quiesce_preserves_both_stop_and_resume_failures(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceRecoveryError, CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    primary = RuntimeError("partial stop")
    resume = RuntimeError("resume failed")
    controller = _FakeContainerController(
        corpus,
        quiesce_error=primary,
        resume_error=resume,
    )

    with pytest.raises(CampaignQuiescenceRecoveryError) as caught:
        CorpusMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=CampaignQuiescenceService(controller),
        ).minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert caught.value.primary_error is primary
    assert caught.value.resume_error is resume
    assert [call[0] for call in controller.calls].count("resume") == 1


@pytest.mark.parametrize("failure_at", ["rollback", "verification"])
def test_rollback_failure_marks_recovery_required_and_leaves_writer_stopped(
    tmp_path: Path,
    failure_at: str,
) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceRecoveryError, CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    controller = _FakeContainerController(corpus)
    primary = RuntimeError("post-publication verification failed")
    rollback = OSError("rollback failed")

    class BrokenRollbackMinimiser(CorpusMinimiser):
        def _after_candidate_publication(self, _corpus):
            raise primary

        def _rollback_candidate(self, *args):
            if failure_at == "rollback":
                raise rollback
            return super()._rollback_candidate(*args)

        def _verify_rolled_back_candidate(self, *args):
            if failure_at == "verification":
                raise rollback
            return super()._verify_rolled_back_candidate(*args)

    with pytest.raises(CampaignQuiescenceRecoveryError) as caught:
        BrokenRollbackMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=CampaignQuiescenceService(controller),
        ).minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert caught.value.primary_error is primary
    assert caught.value.recovery_error is rollback
    assert caught.value.recovery_required is True
    assert controller.active is False
    assert [call[0] for call in controller.calls].count("resume") == 0


def test_replacement_failure_after_commit_requires_recovery_without_rolling_back(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceRecoveryError, CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    original_identity = (corpus.stat().st_dev, corpus.stat().st_ino)
    replacement = RuntimeError("replacement failed")
    controller = _FakeContainerController(corpus, replacement_error=replacement)

    with pytest.raises(CampaignQuiescenceRecoveryError) as caught:
        CorpusMinimiser(
            _NativeRunner(),
            lambda _campaign, _path: frozenset({"a.c:1"}),
            quiescence_service=CampaignQuiescenceService(controller),
        ).minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))

    assert caught.value.primary_error is None
    assert caught.value.resume_error is replacement
    assert caught.value.recovery_required is True
    assert controller.active is False
    assert (corpus / "keep").read_bytes() == b"original"
    assert (corpus.stat().st_dev, corpus.stat().st_ino) != original_identity
    assert tuple(corpus.parent.glob(".corpus.retired-*"))
    assert [call[0] for call in controller.calls].count("replace") == 1
    assert [call[0] for call in controller.calls].count("resume") == 0


def test_quiescence_service_serialises_publication_transitions_per_campaign(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.quiescence import (
        CampaignCorpusOwnership,
        CampaignOwnershipMismatch,
        CampaignQuiescenceService,
    )

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    corpus_stat = corpus.stat()
    ownership = CampaignCorpusOwnership(7, 3, corpus, corpus_stat.st_dev, corpus_stat.st_ino)
    controller = _FakeContainerController(corpus)
    service = CampaignQuiescenceService(controller)
    active_operations = 0
    maximum_active = 0
    entered = threading.Event()
    release = threading.Event()
    state_lock = threading.Lock()

    class Operation:
        def run(self):
            nonlocal active_operations, maximum_active
            with state_lock:
                active_operations += 1
                maximum_active = max(maximum_active, active_operations)
            entered.set()
            assert release.wait(1)
            return "published"

        def commit(self):
            nonlocal active_operations
            with state_lock:
                active_operations -= 1
            replacement = corpus.with_name(f"corpus-new-{id(self)}")
            retired = corpus.with_name(f"corpus-retired-{id(self)}")
            replacement.mkdir()
            corpus.rename(retired)
            replacement.rename(corpus)

        def rollback(self):
            nonlocal active_operations
            with state_lock:
                active_operations -= 1

        def verify_commit(self):
            pass

        def verify_rollback(self):
            pass

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(service.execute, ownership, Operation())
        assert entered.wait(1)
        second = executor.submit(service.execute, ownership, Operation())
        time.sleep(0.02)
        assert maximum_active == 1
        release.set()
        assert first.result() == "published"
        with pytest.raises(CampaignOwnershipMismatch, match="no longer canonical"):
            second.result()

    assert maximum_active == 1
    assert [call[0] for call in controller.calls].count("quiesce") == 1
    assert [call[0] for call in controller.calls].count("replace") == 1
    assert [call[0] for call in controller.calls].count("resume") == 0


def test_quiescence_blocks_late_writer_until_publication_is_committed(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusMinimiser
    from backend.fuzzing.corpus.quiescence import CampaignQuiescenceService

    corpus = tmp_path / "campaign/corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"original")
    controller = _FakeContainerController(corpus)

    class BlockingWriterMinimiser(CorpusMinimiser):
        writer = None

        def _before_atomic_replace(self, _corpus):
            attempted = threading.Event()

            def write():
                attempted.set()
                with controller.writer_gate:
                    (corpus / "late-after-release").write_bytes(b"late")

            self.writer = threading.Thread(target=write)
            self.writer.start()
            assert attempted.wait(1)
            assert self.writer.is_alive()

    minimiser = BlockingWriterMinimiser(
        _NativeRunner(),
        lambda _campaign, _path: frozenset({"a.c:1"}),
        quiescence_service=CampaignQuiescenceService(controller),
    )
    result = minimiser.minimise(_owned_campaign("libfuzzer", corpus, ("/target",)))
    minimiser.writer.join(1)

    assert result.replaced is True
    assert not minimiser.writer.is_alive()
    assert (corpus / "late-after-release").read_bytes() == b"late"
    assert [call[0] for call in controller.calls].count("replace") == 1
    assert [call[0] for call in controller.calls].count("resume") == 0


def test_corpus_sync_requires_exact_contract_and_revalidates_each_input(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.synchronisation import CorpusContract, CorpusSynchroniser

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / "accepted").write_bytes(b"accepted")
    (source / "rejected").write_bytes(b"rejected")
    contract = CorpusContract("target-hash", "stdin", "default")
    calls = []

    def validate(path):
        calls.append(path.name)
        return _durable_admission(path, contract, useful=path.name == "accepted")

    result = CorpusSynchroniser().synchronise(source, destination, contract, contract, validate)

    assert calls == ["accepted", "rejected"]
    assert len(result.transferred_hashes) == 1
    assert len(list(destination.iterdir())) == 1

    incompatible = CorpusContract("other-target", "stdin", "default")
    no_sync = CorpusSynchroniser().synchronise(source, destination, contract, incompatible, validate)
    assert no_sync.transferred_hashes == ()
    assert no_sync.reason == "campaign contracts are incompatible"
    assert calls == ["accepted", "rejected"]


def test_sync_rejects_forged_admission_result_even_when_digest_and_identity_match(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import AdmissionResult
    from backend.fuzzing.corpus.synchronisation import CorpusContract, CorpusSynchroniser

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    seed = source / "seed"
    seed.write_bytes(b"seed")
    contract = CorpusContract("target", "stdin", "default")

    def forge(path):
        source_stat = path.stat(follow_symlinks=False)
        return AdmissionResult(
            True,
            "claimed",
            "seed",
            hashlib.sha256(path.read_bytes()).hexdigest(),
            ("line:a.c:1",),
            source_identity=(source_stat.st_dev, source_stat.st_ino, source_stat.st_size, source_stat.st_mtime_ns),
            target_contract=contract.identifier,
        )

    result = CorpusSynchroniser().synchronise(source, destination, contract, contract, forge)

    assert result.transferred_hashes == ()
    assert len(result.rejected_hashes) == 1
    assert not any(destination.iterdir())


def test_sync_rejects_unsafe_existing_hash_entry_and_staging_symlink(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.synchronisation import CorpusContract, CorpusSynchroniser

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    candidate = source / "seed"
    candidate.write_bytes(b"seed")
    digest = hashlib.sha256(b"seed").hexdigest()
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (destination / digest).symlink_to(outside)
    contract = CorpusContract("target", "stdin", "default")

    def validate(path):
        return _durable_admission(path, contract)

    with pytest.raises(ValueError, match="unsafe existing corpus entry"):
        CorpusSynchroniser().synchronise(source, destination, contract, contract, validate)
    assert outside.read_bytes() == b"outside"

    (destination / digest).unlink()

    class SwapStaging(CorpusSynchroniser):
        def _after_staging_written(self, descriptor, staging_name):
            os.unlink(staging_name, dir_fd=descriptor)
            os.symlink(outside, staging_name, dir_fd=descriptor)

    with pytest.raises(ValueError, match="staging entry changed"):
        SwapStaging().synchronise(source, destination, contract, contract, validate)
    assert outside.read_bytes() == b"outside"
    assert not (destination / digest).exists()


@pytest.mark.parametrize("swap", ["source", "destination"])
def test_sync_rejects_source_or_destination_directory_swap(tmp_path: Path, swap: str) -> None:
    from backend.fuzzing.corpus.synchronisation import CorpusContract, CorpusSynchroniser

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    (source / "seed").write_bytes(b"seed")
    contract = CorpusContract("target", "stdin", "default")

    def validate(path):
        return _durable_admission(path, contract)

    class SwapDirectory(CorpusSynchroniser):
        def _after_directories_opened(self, _source_descriptor, _destination_descriptor):
            selected = source if swap == "source" else destination
            selected.rename(selected.with_name(f"held-{selected.name}"))
            selected.mkdir()

    with pytest.raises(ValueError, match=f"{swap} corpus directory changed"):
        SwapDirectory().synchronise(source, destination, contract, contract, validate)

    assert not any(destination.iterdir())


def test_sync_rejects_source_entry_swap_after_bounded_traversal(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.synchronisation import CorpusContract, CorpusSynchroniser

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    seed = source / "seed"
    seed.write_bytes(b"same")
    contract = CorpusContract("target", "stdin", "default")

    def validate(path):
        return _durable_admission(path, contract)

    class SwapEntry(CorpusSynchroniser):
        def _after_traversal(self, _source_descriptor):
            seed.rename(source / "original")
            seed.write_bytes(b"same")

    with pytest.raises(ValueError, match="source corpus entry changed"):
        SwapEntry().synchronise(source, destination, contract, contract, validate)

    assert not any(destination.iterdir())


def test_sync_stops_before_publication_when_traversal_budget_is_exceeded(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.synchronisation import CorpusContract, CorpusSynchroniser

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    for index in range(4):
        (source / str(index)).write_bytes(b"seed")
    contract = CorpusContract("target", "stdin", "default")

    with pytest.raises(ValueError, match="entry limit"):
        CorpusSynchroniser(max_entries=2).synchronise(source, destination, contract, contract, lambda _path: None)

    assert not destination.exists() or not any(destination.iterdir())
