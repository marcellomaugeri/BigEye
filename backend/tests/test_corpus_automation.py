from __future__ import annotations

import shutil
from pathlib import Path


def test_seed_is_admitted_only_after_execution_and_useful_clean_evidence(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "tests" / "sample.bin"
    seed.parent.mkdir()
    seed.write_bytes(b"sample")
    candidate = CorpusCandidate(seed, "tests/sample.bin")

    admitted = CorpusAdmission().admit(
        candidate,
        ExecutionEvidence(executed=True, ok=True, clean=True, clean_line_delta=frozenset({"parser.c:12"})),
    )
    redundant = CorpusAdmission().admit(
        candidate,
        ExecutionEvidence(executed=True, ok=True, clean=True),
    )

    assert admitted.admitted is True
    assert admitted.provenance == "tests/sample.bin"
    assert admitted.first_clean_delta == ("line:parser.c:12",)
    assert redundant.admitted is False
    assert redundant.reason == "candidate adds no clean coverage or behaviour"


def test_admission_rejects_unexecuted_invalid_unclean_and_unprovenanced_candidates(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "seed"
    seed.write_bytes(b"seed")
    policy = CorpusAdmission()
    useful = {"clean_line_delta": frozenset({"target.c:1"})}

    assert not policy.admit(CorpusCandidate(seed, ""), ExecutionEvidence(True, True, True, **useful)).admitted
    assert not policy.admit(CorpusCandidate(seed, "seed"), ExecutionEvidence(False, True, True, **useful)).admitted
    assert not policy.admit(CorpusCandidate(seed, "seed"), ExecutionEvidence(True, False, True, **useful)).admitted
    assert not policy.admit(CorpusCandidate(seed, "seed"), ExecutionEvidence(True, True, False, **useful)).admitted


def test_validate_executes_candidate_and_rejects_a_known_content_hash(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence

    seed = tmp_path / "sample"
    seed.write_bytes(b"same")
    calls = []

    def execute(candidate, target):
        calls.append((candidate, target))
        return ExecutionEvidence(True, True, True, frozenset({"target.c:2"}))

    policy = CorpusAdmission(execute)
    candidate = CorpusCandidate(seed, "examples/sample")
    first = policy.validate(candidate, "target")
    duplicate = policy.validate(candidate, "target", known_hashes={first.content_sha256})

    assert len(calls) == 2
    assert first.admitted is True
    assert duplicate.admitted is False
    assert duplicate.reason == "candidate content is already present"


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


class _NativeRunner:
    def __init__(self):
        self.commands: list[tuple[str, ...]] = []

    def run(self, campaign, command: tuple[str, ...], output: Path) -> None:
        self.commands.append(command)
        if command[0] in {"afl-cmin", campaign.target_command[0]}:
            output.mkdir(parents=True, exist_ok=True)
            source = campaign.corpus_dir / "keep"
            (output / "keep").write_bytes(source.read_bytes())
        elif command[0] == "afl-tmin":
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"k")


def test_afl_minimisation_uses_native_tools_and_replaces_only_after_coverage_preservation(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusMinimiser

    corpus = tmp_path / "campaign" / "corpus"
    corpus.mkdir(parents=True)
    (corpus / "keep").write_bytes(b"keep")
    (corpus / "drop").write_bytes(b"drop")
    campaign = CorpusCampaign("afl++", corpus, ("/opt/bigeye/target", "@@"))
    runner = _NativeRunner()
    minimiser = CorpusMinimiser(runner, lambda _campaign, _corpus: frozenset({"parser.c:12"}))

    result = minimiser.minimise(campaign)

    assert result.replaced is True
    assert result.before_count == 2
    assert result.after_count == 1
    assert [command[0] for command in runner.commands] == ["afl-cmin", "afl-tmin"]
    assert (corpus / "keep").read_bytes() == b"k"
    assert not (corpus / "drop").exists()


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


def test_corpus_sync_requires_exact_contract_and_revalidates_each_input(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.admission import AdmissionResult
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
        digest = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
        return AdmissionResult(path.name == "accepted", "useful" if path.name == "accepted" else "redundant", path.name, digest, ())

    result = CorpusSynchroniser().synchronise(source, destination, contract, contract, validate)

    assert calls == ["accepted", "rejected"]
    assert len(result.transferred_hashes) == 1
    assert len(list(destination.iterdir())) == 1

    incompatible = CorpusContract("other-target", "stdin", "default")
    no_sync = CorpusSynchroniser().synchronise(source, destination, contract, incompatible, validate)
    assert no_sync.transferred_hashes == ()
    assert no_sync.reason == "campaign contracts are incompatible"
    assert calls == ["accepted", "rejected"]
