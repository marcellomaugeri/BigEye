from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
import socket
from types import SimpleNamespace

import pytest

NOW = datetime(2026, 7, 20, tzinfo=UTC)
COMMIT = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64


class Journal:
    def __init__(self):
        self.records = {}

    async def get(self, project_id, campaign_id, kind, content_sha256):
        return self.records.get((project_id, campaign_id, kind, content_sha256))

    async def record(self, record):
        self.records[(
            record.project_id, record.campaign_id, record.kind, record.content_sha256,
        )] = record
        return record

    async def accepted_count(self, project_id, campaign_id, kind):
        return sum(
            value.accepted
            for key, value in self.records.items()
            if key[0] == project_id and key[1] == campaign_id and key[2] == kind
        )


def _workspace(root: Path) -> Path:
    campaign = root / "projects/7/campaigns/9"
    for name in ("corpus", "output", "config", "logs"):
        (campaign / name).mkdir(parents=True, exist_ok=True)
    return campaign


def _progress(artifact):
    from backend.services.campaigns.production_runtime import CampaignProgressObservation

    return CampaignProgressObservation(
        9, 2.0, NOW, 1, int(artifact.kind == "crash"), "progress:9", "container-9",
        executions=100, executions_per_second=10.0, artifacts=(artifact,),
    )


def test_corpus_adapter_uses_real_admission_clean_replay_and_traceability_before_publication(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageLine
    from backend.services.campaigns.production_artifacts import ProductionCorpusArtifactHandler

    campaign_root = _workspace(tmp_path)
    raw = campaign_root / "output" / "queue-a"
    raw.write_bytes(b"useful")
    digest = sha256(b"useful").hexdigest()
    artifact = CampaignArtifactObservation("corpus", "output/queue-a", digest, 6)
    snapshot = SimpleNamespace(
        build_kind="clean",
        lines=(CoverageLine("src/parser.c", 4, "parse", "c" * 64),),
        hits=(CoverageHit("src/parser.c", 4, b"useful", digest),),
    )

    class Coverage:
        def __init__(self):
            self.calls = 0

        def replay(self, target, inputs):
            self.calls += 1
            assert target.contract_hash == "coverage-contract"
            assert Path(tuple(inputs)[0]).read_bytes() == b"useful"
            return snapshot

    class Traceability:
        def __init__(self):
            self.calls = []

        async def record(self, value):
            self.calls.append(value)
            return [SimpleNamespace(id=1)]

    coverage, traceability, journal = Coverage(), Traceability(), Journal()
    handler = ProductionCorpusArtifactHandler(
        workspace=tmp_path,
        journal=journal,
        target_resolver=SimpleNamespace(resolve=lambda **_values: SimpleNamespace(
            contract_hash="coverage-contract",
        )),
        clean_coverage=coverage,
        traceability=traceability,
    )
    values = dict(
        project=SimpleNamespace(id=7), campaign=SimpleNamespace(id=9),
        invocation=SimpleNamespace(engine="afl"), progress=_progress(artifact), artifact=artifact,
    )

    first = asyncio.run(handler.process(**values))
    second = asyncio.run(handler.process(**values))

    assert first.accepted is True
    assert second.accepted is False
    assert second.reason == "artifact already processed"
    assert coverage.calls == 1
    assert traceability.calls == [snapshot]
    assert (campaign_root / "corpus" / digest).read_bytes() == b"useful"


def test_crash_adapter_builds_exact_observation_and_never_reprocesses_the_same_raw_hash(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.models.finding import Finding
    from backend.services.campaigns.production_artifacts import ProductionCrashArtifactHandler

    campaign_root = _workspace(tmp_path)
    raw = campaign_root / "output" / "crash-deadbeef"
    raw.write_bytes(b"crash")
    digest = sha256(b"crash").hexdigest()
    artifact = CampaignArtifactObservation("crash", "output/crash-deadbeef", digest, 5)
    finding = Finding(
        id=4, project_id=7, fingerprint="f" * 64,
        classification="unresolved", priority_rank=1, priority_reason="retained",
        description="retained", reproducible=True, occurrence_count=1,
        created_at=NOW, triaged_at=NOW, error=None,
    )

    class Pipeline:
        def __init__(self):
            self.observations = []

        async def process(self, observation):
            self.observations.append(observation)
            return finding

    pipeline, journal = Pipeline(), Journal()
    handler = ProductionCrashArtifactHandler(tmp_path, journal, pipeline)
    invocation = SimpleNamespace(
        engine="afl", image_id=IMAGE_ID,
        command=["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output", "--",
                 "/opt/bigeye/parser", "@@"],
        environment={"ASAN_OPTIONS": "abort_on_error=1", "UBSAN_OPTIONS": "halt_on_error=1"},
    )
    values = dict(
        project=SimpleNamespace(id=7, commit_sha=COMMIT),
        campaign=SimpleNamespace(
            id=9, target_asset_id=31, configuration_asset_id=32,
        ),
        invocation=invocation, progress=_progress(artifact), artifact=artifact,
    )

    first = asyncio.run(handler.process(**values))
    second = asyncio.run(handler.process(**values))

    assert first.accepted is True
    assert second.accepted is False
    assert len(pipeline.observations) == 1
    observation = pipeline.observations[0]
    assert observation.input_bytes == b"crash"
    assert observation.command == ("/opt/bigeye/parser", "/bigeye/input/crash")
    assert observation.sanitizer == "address+undefined"
    assert first.evidence_id == "finding:" + "f" * 64


def test_crash_adapter_persists_the_clean_replay_argv_from_the_coverage_contract(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.models.finding import Finding
    from backend.services.campaigns.production_artifacts import ProductionCrashArtifactHandler

    campaign_root = _workspace(tmp_path)
    raw = campaign_root / "output" / "crash-clean"
    raw.write_bytes(b"crash")
    artifact = CampaignArtifactObservation(
        "crash", "output/crash-clean", sha256(b"crash").hexdigest(), 5,
    )
    finding = Finding(
        id=4, project_id=7, fingerprint="f" * 64,
        classification="unresolved", priority_rank=1, priority_reason="retained",
        description="retained", reproducible=True, occurrence_count=1,
        created_at=NOW, triaged_at=NOW, error=None,
    )

    class Pipeline:
        async def process(self, observation): self.observation = observation; return finding

    pipeline = Pipeline()
    handler = ProductionCrashArtifactHandler(
        tmp_path, Journal(), pipeline,
        SimpleNamespace(resolve=lambda **_values: SimpleNamespace(
            clean_image_id="sha256:" + "c" * 64,
            replay_command=("/opt/bigeye/parser-clean", "--mode", "plain", "{input}"),
        )),
    )
    asyncio.run(handler.process(
        project=SimpleNamespace(id=7, commit_sha=COMMIT),
        campaign=SimpleNamespace(id=9, target_asset_id=31, configuration_asset_id=32),
        invocation=SimpleNamespace(
            engine="afl", image_id=IMAGE_ID,
            command=["afl-fuzz", "--", "/opt/bigeye/parser-fuzz", "@@"],
            environment={"ASAN_OPTIONS": "abort_on_error=1"},
        ),
        progress=_progress(artifact), artifact=artifact,
    ))

    assert pipeline.observation.command == ("/opt/bigeye/parser-fuzz", "/bigeye/input/crash")
    assert pipeline.observation.clean_command == (
        "/opt/bigeye/parser-clean", "--mode", "plain", "/bigeye/input/crash",
    )


def test_afl_stdin_crash_adapter_preserves_the_validated_stdin_contract(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.models.finding import Finding
    from backend.services.campaigns.production_artifacts import ProductionCrashArtifactHandler

    campaign_root = _workspace(tmp_path)
    raw = campaign_root / "output" / "id:000001,sig:11"
    raw.write_bytes(b"stdin-crash")
    artifact = CampaignArtifactObservation(
        "crash", "output/id:000001,sig:11",
        sha256(b"stdin-crash").hexdigest(), len(b"stdin-crash"),
    )
    finding = Finding(
        id=4, project_id=7, fingerprint="f" * 64,
        classification="unresolved", priority_rank=1, priority_reason="retained",
        description="retained", reproducible=True, occurrence_count=1,
        created_at=NOW, triaged_at=NOW, error=None,
    )

    class Pipeline:
        async def process(self, observation):
            self.observation = observation
            return finding

    pipeline = Pipeline()
    handler = ProductionCrashArtifactHandler(
        tmp_path, Journal(), pipeline,
        SimpleNamespace(resolve=lambda **_values: SimpleNamespace(
            clean_image_id="sha256:" + "c" * 64,
            replay_command=(
                "/opt/bigeye/stdin-parser-clean", "--encrypted", "{stdin}",
            ),
        )),
    )
    asyncio.run(handler.process(
        project=SimpleNamespace(id=7, commit_sha=COMMIT),
        campaign=SimpleNamespace(id=9, target_asset_id=31, configuration_asset_id=32),
        invocation=SimpleNamespace(
            engine="afl", image_id=IMAGE_ID,
            command=["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
                     "--", "/opt/bigeye/stdin-parser", "--encrypted"],
            environment={"ASAN_OPTIONS": "abort_on_error=1"},
        ),
        progress=_progress(artifact), artifact=artifact,
    ))

    assert pipeline.observation.command == ("/opt/bigeye/stdin-parser", "--encrypted")
    assert pipeline.observation.input_mode == "stdin"
    assert pipeline.observation.clean_command == (
        "/opt/bigeye/stdin-parser-clean", "--encrypted",
    )


def test_minimisation_adapter_invokes_existing_corpus_minimiser_only_at_threshold(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusResult
    from backend.services.campaigns.production_artifacts import ProductionCorpusMinimisation

    campaign_root = _workspace(tmp_path)
    journal = Journal()

    @dataclass(frozen=True)
    class Record:
        project_id: int
        campaign_id: int
        kind: str
        content_sha256: str
        accepted: bool

    for index in range(2):
        record = Record(7, 9, "corpus", f"{index:064x}", True)
        journal.records[(7, 9, "corpus", record.content_sha256)] = record

    class Minimiser:
        def __init__(self):
            self.calls = []

        def minimise(self, campaign):
            self.calls.append(campaign)
            return CorpusResult(True, "clean coverage preserved", 2, 1, (("afl-cmin",),))

    minimiser = Minimiser()
    service = ProductionCorpusMinimisation(
        workspace=tmp_path, journal=journal, minimiser=minimiser, threshold=2,
    )
    invocation = SimpleNamespace(
        engine="afl", command=["afl-fuzz", "--", "/opt/bigeye/parser", "@@"],
    )

    evidence_id = asyncio.run(service.minimise_if_needed(
        project=SimpleNamespace(id=7), campaign=SimpleNamespace(id=9), invocation=invocation,
    ))

    assert evidence_id == "corpus-minimisation:7:9:2:1"
    assert minimiser.calls[0].engine == "afl++"
    assert minimiser.calls[0].corpus_dir == campaign_root / "corpus"


def test_clean_coverage_contract_survives_restart_and_resolves_exact_validated_assets(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.probe import ProbeInvocation
    from backend.services.campaigns.production_artifacts import CampaignCoverageTargetResolver
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    campaign_root = _workspace(tmp_path)
    repository = tmp_path / "projects/7/repository"
    repository.mkdir(parents=True)
    prepared = SimpleNamespace(
        project_id=7,
        commit_sha=COMMIT,
        replay_environment=(
            ("ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0"),
            ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
        ),
        coverage_image_id="sha256:" + "c" * 64,
        coverage_manifest=SimpleNamespace(
            content_hash="d" * 64,
            labels={
                "bigeye.parent-image": IMAGE_ID,
                "bigeye.configuration-asset-id": "32",
                "bigeye.coverage-asset-id": "34",
            },
        ),
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        probe_invocations=(
            ProbeInvocation(
                "seed:test.seed", "seed",
                ("/opt/bigeye/parser", "--file", "/src/test.seed", "--mode", "plain"),
                b"seed",
            ),
        ),
    )
    store = CampaignInvocationStore(tmp_path)
    asyncio.run(store.publish_coverage(7, 9, COMMIT, prepared))

    @dataclass(frozen=True)
    class Asset:
        id: int
        project_id: int = 7
        validated_at: datetime = NOW
        error: str | None = None

    class Assets:
        async def get(self, asset_id):
            return Asset(asset_id)

    target = asyncio.run(CampaignCoverageTargetResolver(
        tmp_path, CampaignInvocationStore(tmp_path), Assets(),
    ).resolve(
        project=SimpleNamespace(id=7, commit_sha=COMMIT),
        campaign=SimpleNamespace(
            id=9, project_id=7, target_asset_id=31, configuration_asset_id=32,
        ),
    ))

    assert target.clean_image_id == "sha256:" + "c" * 64
    assert target.clean_parent_image_id == IMAGE_ID
    assert target.replay_command == (
        "/opt/bigeye/parser", "--file", "{input}", "--mode", "plain",
    )
    assert target.replay_environment == (
        ("ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0"),
        ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
    )
    assert target.coverage_asset_id == 34
    assert target.repository_root == repository
    assert campaign_root.joinpath("config/coverage.json").is_file()


@pytest.mark.parametrize(
    "command",
    [
        ("/opt/bigeye/parser", "--mode", "plain"),
        ("/opt/bigeye/parser", "/src/test.seed", "--file", "/src/test.seed"),
        ("/opt/bigeye/parser", "--file", "{input}", "--also", "/src/test.seed"),
        ("/opt/bigeye/parser", "--file", "/src/other.seed"),
    ],
)
def test_clean_coverage_publication_rejects_missing_duplicate_or_mismatched_file_paths(
    tmp_path: Path, command,
) -> None:
    from backend.fuzzing.campaigns.probe import ProbeInvocation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    _workspace(tmp_path)
    prepared = SimpleNamespace(
        project_id=7,
        commit_sha=COMMIT,
        replay_environment=(),
        coverage_image_id="sha256:" + "c" * 64,
        coverage_manifest=SimpleNamespace(
            content_hash="d" * 64,
            labels={
                "bigeye.parent-image": IMAGE_ID,
                "bigeye.configuration-asset-id": "32",
                "bigeye.coverage-asset-id": "34",
            },
        ),
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        probe_invocations=(
            ProbeInvocation("seed:test.seed", "seed", command, b"seed"),
        ),
    )

    with pytest.raises(ValueError, match="explicit input|replay contract"):
        asyncio.run(CampaignInvocationStore(tmp_path).publish_coverage(
            7, 9, COMMIT, prepared,
        ))

    assert not tmp_path.joinpath("projects/7/campaigns/9/config/coverage.json").exists()


def test_clean_coverage_publication_rejects_an_invalid_prepared_environment(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.probe import ProbeInvocation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    _workspace(tmp_path)
    prepared = SimpleNamespace(
        project_id=7,
        commit_sha=COMMIT,
        replay_environment=(("OPENAI_API_KEY", "must-not-be-published"),),
        coverage_image_id="sha256:" + "c" * 64,
        coverage_manifest=SimpleNamespace(
            content_hash="d" * 64,
            labels={
                "bigeye.parent-image": IMAGE_ID,
                "bigeye.configuration-asset-id": "32",
                "bigeye.coverage-asset-id": "34",
            },
        ),
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        probe_invocations=(
            ProbeInvocation(
                "seed", "seed", ("/opt/bigeye/parser", "/src/test.seed"), b"seed",
            ),
        ),
    )

    with pytest.raises(ValueError, match="contract"):
        asyncio.run(CampaignInvocationStore(tmp_path).publish_coverage(
            7, 9, COMMIT, prepared,
        ))

    assert not tmp_path.joinpath("projects/7/campaigns/9/config/coverage.json").exists()


def test_clean_coverage_publication_requires_the_prepared_environment(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.probe import ProbeInvocation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    _workspace(tmp_path)
    prepared = SimpleNamespace(
        project_id=7,
        commit_sha=COMMIT,
        coverage_image_id="sha256:" + "c" * 64,
        coverage_manifest=SimpleNamespace(
            content_hash="d" * 64,
            labels={
                "bigeye.parent-image": IMAGE_ID,
                "bigeye.configuration-asset-id": "32",
                "bigeye.coverage-asset-id": "34",
            },
        ),
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        probe_invocations=(
            ProbeInvocation(
                "seed", "seed", ("/opt/bigeye/parser", "/src/test.seed"), b"seed",
            ),
        ),
    )

    with pytest.raises(ValueError, match="environment"):
        asyncio.run(CampaignInvocationStore(tmp_path).publish_coverage(
            7, 9, COMMIT, prepared,
        ))

    assert not tmp_path.joinpath("projects/7/campaigns/9/config/coverage.json").exists()


def test_stdin_clean_coverage_contract_survives_restart_without_argv_input_path(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.probe import ProbeInvocation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    _workspace(tmp_path)
    prepared = SimpleNamespace(
        project_id=7,
        commit_sha=COMMIT,
        replay_environment=(
            ("ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0"),
            ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
        ),
        coverage_image_id="sha256:" + "c" * 64,
        coverage_manifest=SimpleNamespace(
            content_hash="d" * 64,
            labels={
                "bigeye.parent-image": IMAGE_ID,
                "bigeye.configuration-asset-id": "32",
                "bigeye.coverage-asset-id": "34",
            },
        ),
        target_manifest=SimpleNamespace(labels={"bigeye.target-asset": "31"}),
        probe_invocations=(
            ProbeInvocation(
                "seed", "seed",
                ("/opt/bigeye/stdin-parser", "--mode", "plain", "{stdin}"),
                b"seed",
            ),
        ),
    )
    store = CampaignInvocationStore(tmp_path)

    asyncio.run(store.publish_coverage(7, 9, COMMIT, prepared))

    contract = store.load_coverage(7, 9)
    assert contract.binary_path == "/opt/bigeye/stdin-parser"
    assert contract.replay_command == (
        "/opt/bigeye/stdin-parser", "--mode", "plain", "{stdin}",
    )


@pytest.mark.parametrize(
    "replay_command",
    [
        ("/opt/bigeye/parser", "{stdin}", "{stdin}"),
        ("/opt/bigeye/parser", "{input}", "{stdin}"),
        ("/opt/bigeye/parser", "{input}", "--mode={stdin}"),
        ("/opt/bigeye/parser", "--file={input}", "{stdin}"),
        ("/opt/bigeye/parser", "plain"),
    ],
)
def test_campaign_coverage_contract_requires_one_application_input_marker(replay_command) -> None:
    from backend.fuzzing.campaigns.coverage_contract import CampaignCoverageContract

    with pytest.raises(ValueError, match="contract"):
        CampaignCoverageContract(
            project_id=7, commit_sha=COMMIT,
            clean_image_id="sha256:" + "c" * 64,
            clean_content_hash="d" * 64, clean_parent_image_id=IMAGE_ID,
            target_asset_id=31, configuration_asset_id=32,
            clean_build_configuration_asset_id=32, coverage_asset_id=34,
            binary_path="/opt/bigeye/parser", replay_command=replay_command,
            replay_environment=(),
        )


def test_campaign_coverage_contract_requires_an_explicit_replay_environment() -> None:
    from backend.fuzzing.campaigns.coverage_contract import CampaignCoverageContract

    with pytest.raises(TypeError, match="replay_environment"):
        CampaignCoverageContract(
            project_id=7, commit_sha=COMMIT,
            clean_image_id="sha256:" + "c" * 64,
            clean_content_hash="d" * 64, clean_parent_image_id=IMAGE_ID,
            target_asset_id=31, configuration_asset_id=32,
            clean_build_configuration_asset_id=32, coverage_asset_id=34,
            binary_path="/opt/bigeye/parser",
            replay_command=("/opt/bigeye/parser", "{input}"),
        )


def test_campaign_configuration_files_are_descriptor_published_with_the_invocation(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    campaign_root = _workspace(tmp_path)
    invocation = ContainerInvocation(
        engine="afl", image_id=IMAGE_ID,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "-x",
            "/campaign/config/tokens.dict", "--", "/opt/bigeye/parser", "@@",
        ],
        environment={"AFL_NO_UI": "1"}, campaign_labels={},
        network_disabled=True, read_only_source=True,
        timeout_ms=1_000, memory_limit_mb=1_024,
    )
    seed = SimpleNamespace(role="seed", testcase_bytes=b"seed")
    intent = b'{"applied_primary":["address","undefined"]}'

    asyncio.run(CampaignInvocationStore(tmp_path).publish(
        7, 9, invocation, (seed,), configuration_files={
            "tokens.dict": b'keyword="MAGIC"\n',
            "sanitizer-intent.json": intent,
        },
    ))

    assert campaign_root.joinpath("config/tokens.dict").read_bytes() == b'keyword="MAGIC"\n'
    assert campaign_root.joinpath("config/sanitizer-intent.json").read_bytes() == intent


def test_configuration_variant_updates_fuzzer_and_clean_replay_without_rebuilding(
    tmp_path: Path,
) -> None:
    import json
    from dataclasses import asdict

    from backend.fuzzing.campaigns.coverage_contract import CampaignCoverageContract
    from backend.fuzzing.engines.contracts import ContainerInvocation
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    campaign_root = _workspace(tmp_path)
    (campaign_root / "corpus/seed").write_bytes(b"seed")
    contract = CampaignCoverageContract(
        project_id=7, commit_sha=COMMIT,
        clean_image_id="sha256:" + "c" * 64,
        clean_content_hash="d" * 64, clean_parent_image_id=IMAGE_ID,
        target_asset_id=31, configuration_asset_id=32,
        clean_build_configuration_asset_id=32, coverage_asset_id=34,
        binary_path="/opt/bigeye/parser",
        replay_command=("/opt/bigeye/parser", "--file", "{input}"),
        replay_environment=(),
    )
    (campaign_root / "config/coverage.json").write_text(json.dumps(asdict(contract)))
    invocation = ContainerInvocation(
        engine="afl", image_id=IMAGE_ID,
        command=[
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--",
            "/opt/bigeye/parser", "--file", "@@", "--encrypt",
        ],
        environment={"AFL_NO_UI": "1", "BIGEYE_MODE": "encrypted"},
        campaign_labels={}, network_disabled=True, read_only_source=True,
        timeout_ms=1_000, memory_limit_mb=1_024,
    )
    store = CampaignInvocationStore(tmp_path)

    asyncio.run(store.clone_variant(
        7, 9, 12, invocation,
        coverage_arguments=("--encrypt",),
        coverage_environment=(("BIGEYE_MODE", "encrypted"),),
    ))

    assert "--encrypt" in store.load(7, 12).command
    coverage = store.load_coverage(7, 12)
    assert coverage.replay_command == (
        "/opt/bigeye/parser", "--file", "{input}", "--encrypt",
    )
    assert coverage.replay_environment == (("BIGEYE_MODE", "encrypted"),)
    assert not (tmp_path / "projects/7/assets").exists()


def test_clean_coverage_loader_rejects_string_pairs_in_replay_environment(tmp_path: Path) -> None:
    import json
    from dataclasses import asdict

    from backend.fuzzing.campaigns.coverage_contract import CampaignCoverageContract
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    campaign_root = _workspace(tmp_path)
    contract = CampaignCoverageContract(
        project_id=7, commit_sha=COMMIT,
        clean_image_id="sha256:" + "c" * 64,
        clean_content_hash="d" * 64, clean_parent_image_id=IMAGE_ID,
        target_asset_id=31, configuration_asset_id=32,
        clean_build_configuration_asset_id=32, coverage_asset_id=34,
        binary_path="/opt/bigeye/parser",
        replay_command=("/opt/bigeye/parser", "{input}"),
        replay_environment=(),
    )
    document = asdict(contract)
    document["replay_environment"] = ["AB"]
    (campaign_root / "config/coverage.json").write_text(json.dumps(document))

    with pytest.raises(ValueError, match="contract file is invalid"):
        CampaignInvocationStore(tmp_path).load_coverage(7, 9)


def test_clean_coverage_loader_rejects_a_missing_replay_environment(tmp_path: Path) -> None:
    import json
    from dataclasses import asdict

    from backend.fuzzing.campaigns.coverage_contract import CampaignCoverageContract
    from backend.services.campaigns.production_runtime import CampaignInvocationStore

    campaign_root = _workspace(tmp_path)
    contract = CampaignCoverageContract(
        project_id=7, commit_sha=COMMIT,
        clean_image_id="sha256:" + "c" * 64,
        clean_content_hash="d" * 64, clean_parent_image_id=IMAGE_ID,
        target_asset_id=31, configuration_asset_id=32,
        clean_build_configuration_asset_id=32, coverage_asset_id=34,
        binary_path="/opt/bigeye/parser",
        replay_command=("/opt/bigeye/parser", "{input}"),
        replay_environment=(("BIGEYE_MODE", "encrypted"),),
    )
    document = asdict(contract)
    del document["replay_environment"]
    (campaign_root / "config/coverage.json").write_text(json.dumps(document))

    with pytest.raises(ValueError, match="contract file is invalid"):
        CampaignInvocationStore(tmp_path).load_coverage(7, 9)


def test_artifact_state_is_keyed_by_project_and_campaign_without_a_read_cap() -> None:
    from backend.models.campaign_artifact import ProcessedCampaignArtifact
    from backend.repositories.campaign_artifact_repository import CampaignArtifactRepository

    class Pool:
        def __init__(self):
            self.values = {}
            self.campaign_projects = {9: 7, 10: 8}

        async def fetchrow(self, query, *args):
            if query.lstrip().startswith("SELECT"):
                return self.values.get(tuple(args))
            if self.campaign_projects.get(args[1]) != args[0]:
                return None
            record = {
                "project_id": args[0], "campaign_id": args[1], "kind": args[2],
                "content_sha256": args[3], "accepted": args[4], "evidence_id": args[5],
                "reason": args[6], "durable_relative_path": args[7],
            }
            key = tuple(args[:4])
            if key in self.values:
                return None
            self.values[key] = record
            return record

        async def fetchval(self, query, *args):
            return sum(
                value["accepted"] for key, value in self.values.items()
                if key[:3] == tuple(args)
            )

    async def exercise():
        pool = Pool()
        repository = CampaignArtifactRepository(pool)
        first = ProcessedCampaignArtifact(
            7, 9, "corpus", "a" * 64, True, "corpus:a", "retained", "campaigns/9/corpus/a",
        )
        other = ProcessedCampaignArtifact(
            8, 10, "corpus", "a" * 64, False, "corpus:b", "rejected", None,
        )
        await repository.record(first)
        await repository.record(other)
        assert await repository.get(7, 9, "corpus", "a" * 64) == first
        assert await repository.get(8, 10, "corpus", "a" * 64) == other
        assert await repository.accepted_count(7, 9, "corpus") == 1
        assert await repository.accepted_count(8, 10, "corpus") == 0
        wrong_project = ProcessedCampaignArtifact(
            8, 9, "crash", "b" * 64, True, "finding:b", "retained", "findings/b",
        )
        try:
            await repository.record(wrong_project)
        except ValueError as error:
            assert "different evidence" in str(error)
        else:
            raise AssertionError("cross-project campaign identity was accepted")

    asyncio.run(exercise())
    schema = Path("backend/database/schema.sql").read_text()
    assert "CREATE TABLE campaign_artifacts" in schema
    assert "PRIMARY KEY (project_id, campaign_id, kind, content_sha256)" in schema
    assert "LIMIT" not in schema[schema.index("CREATE TABLE campaign_artifacts"):]


def test_artifact_cursor_repository_is_project_owned_and_monotonic() -> None:
    from backend.repositories.campaign_artifact_repository import CampaignArtifactRepository

    class Pool:
        def __init__(self): self.values = {}; self.campaign_projects = {9: 7}

        async def fetch(self, query, *args):
            return [
                {"kind": kind, "last_seen_ns": value[0], "last_name": value[1]}
                for (project_id, campaign_id, kind), value in self.values.items()
                if (project_id, campaign_id) == tuple(args)
            ]

        async def fetchval(self, query, *args):
            project_id, campaign_id, kind, observed_ns, name = args
            if self.campaign_projects.get(campaign_id) != project_id:
                return None
            key = project_id, campaign_id, kind
            value = observed_ns, name
            if value > self.values.get(key, (-1, "")):
                self.values[key] = value
            return self.values[key]

    async def exercise():
        pool = Pool()
        repository = CampaignArtifactRepository(pool)
        assert await repository.cursors(7, 9) == {}
        await repository.advance_cursors(7, 9, (("queue", 20, "id:000511"),))
        await repository.advance_cursors(7, 9, (("queue", 10, "id:999999"),))
        assert await repository.cursors(7, 9) == {"queue": (20, "id:000511")}
        with pytest.raises(ValueError, match="campaign"):
            await repository.advance_cursors(8, 9, (("queue", 30, "id:000519"),))

    asyncio.run(exercise())
    schema = Path("backend/database/schema.sql").read_text()
    assert "CREATE TABLE campaign_artifact_cursors" in schema


def test_libfuzzer_crash_replay_preserves_target_configuration_flags() -> None:
    from backend.services.campaigns.production_artifacts import _crash_command

    invocation = SimpleNamespace(
        engine="libfuzzer",
        command=[
            "/opt/bigeye/parser", "--mode", "encrypted", "/campaign/corpus",
            "-artifact_prefix=/campaign/output/", "-timeout=1",
        ],
    )

    assert _crash_command(invocation) == (
        "/opt/bigeye/parser", "--mode", "encrypted", "-runs=1", "/bigeye/input/crash",
    )


def test_artifact_reader_rejects_an_intermediate_campaign_symlink(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
    from backend.services.campaigns.production_artifacts import ProductionCrashArtifactHandler

    campaign_root = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "crash-a").write_bytes(b"crash")
    campaign_root.joinpath("output").rmdir()
    campaign_root.joinpath("output").symlink_to(outside, target_is_directory=True)
    artifact = CampaignArtifactObservation(
        "crash", "output/crash-a", sha256(b"crash").hexdigest(), 5,
    )
    handler = ProductionCrashArtifactHandler(tmp_path, Journal(), SimpleNamespace())

    with pytest.raises((OSError, ValueError)):
        asyncio.run(handler.process(
            project=SimpleNamespace(id=7, commit_sha=COMMIT),
            campaign=SimpleNamespace(id=9, target_asset_id=31, configuration_asset_id=32),
            invocation=SimpleNamespace(
                engine="afl", image_id=IMAGE_ID,
                command=["afl-fuzz", "--", "/opt/bigeye/parser", "@@"],
                environment={},
            ),
            progress=_progress(artifact), artifact=artifact,
        ))


def test_factory_constructs_real_domain_evidence_services(tmp_path: Path) -> None:
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage
    from backend.fuzzing.crashes.triage import CrashPipeline
    from backend.services.campaigns.production_evidence_factory import (
        ProductionCampaignEvidenceFactory,
        ProductionNativeCorpusMinimisation,
    )

    tmp_path.mkdir(exist_ok=True)
    service = ProductionCampaignEvidenceFactory(
        workspace=tmp_path,
        contracts=SimpleNamespace(),
        assets=SimpleNamespace(),
        artifacts=SimpleNamespace(),
        traceability=SimpleNamespace(),
        findings=SimpleNamespace(),
        discovery=SimpleNamespace(),
    )(SimpleNamespace())

    assert isinstance(service._corpus._coverage, LlvmCoverage)
    assert isinstance(service._crashes._pipeline, CrashPipeline)
    assert isinstance(service._crashes._pipeline._minimiser, object)
    assert isinstance(service._minimiser, ProductionNativeCorpusMinimisation)


def test_docker_crash_replay_is_bounded_and_forces_linux_amd64(tmp_path: Path) -> None:
    from backend.fuzzing.crashes.quarantine import CrashObservation
    from backend.services.campaigns.production_evidence_factory import DockerCrashReplayExecutor

    class Container:
        def __init__(self):
            self.removed = []

        def start(self):
            return None

        def wait(self, timeout):
            assert timeout == 10
            return {"StatusCode": 134}

        def logs(self, **_kwargs):
            return [
                b"ERROR: AddressSanitizer\n",
                b"#0 0x123 in parse /src/parser.c:42\n",
            ]

        def remove(self, force=False):
            self.removed.append(force)

    class Containers:
        def __init__(self):
            self.container = Container()
            self.kwargs = None

        def create(self, *args, **kwargs):
            self.kwargs = (args, kwargs)
            return self.container

    containers = Containers()
    replay = DockerCrashReplayExecutor(SimpleNamespace(containers=containers), tmp_path)
    observation = CrashObservation(
        project_id=7, campaign_id=9, commit_sha=COMMIT, engine="libfuzzer",
        image_id=IMAGE_ID, target_asset_id=31, configuration_asset_id=32,
        sanitizer="address", command=("/opt/bigeye/parser", "-runs=1", "/bigeye/input/crash"),
        input_bytes=b"crash",
    )

    result = asyncio.run(replay.replay(observation, b"crash", "original"))

    assert result.crashed is True
    assert result.signal == "SIGABRT"
    assert result.sanitizer == "address"
    assert result.source_location == "parser.c:42"
    assert containers.kwargs[1]["platform"] == "linux/amd64"
    assert containers.kwargs[1]["network_mode"] == "none"
    assert containers.kwargs[1]["cap_drop"] == ["ALL"]
    assert containers.kwargs[1]["user"]
    assert containers.kwargs[1]["privileged"] is False
    assert containers.kwargs[1]["ipc_mode"] == "private"
    assert containers.kwargs[1]["cgroupns"] == "private"
    assert containers.kwargs[1]["restart_policy"] == {"Name": "no"}
    assert containers.kwargs[1]["publish_all_ports"] is False
    assert containers.kwargs[1]["tmpfs"] == {
        "/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777",
    }
    assert containers.container.removed == [True]


@pytest.mark.parametrize(
    ("exit_code", "output", "expected_crashed", "expected_signal", "expected_error"),
    [
        (1, b"invalid input\n", False, None, "target exited 1 without validated crash evidence"),
        (1, b"ERROR: AddressSanitizer\n#0 in parse /src/parser.c:4\n", True, None, None),
        (139, b"Segmentation fault\n", True, "SIGSEGV", None),
    ],
)
def test_docker_crash_replay_distinguishes_target_rejection_from_crash_evidence(
    tmp_path: Path, exit_code, output, expected_crashed, expected_signal, expected_error,
) -> None:
    from backend.fuzzing.crashes.quarantine import CrashObservation
    from backend.services.campaigns.production_evidence_factory import DockerCrashReplayExecutor

    class Container:
        def start(self): pass
        def wait(self, timeout): return {"StatusCode": exit_code}
        def logs(self, **_kwargs): return [output]
        def remove(self, force=False): pass

    class Containers:
        def create(self, *_args, **_kwargs): return Container()

    result = asyncio.run(DockerCrashReplayExecutor(
        SimpleNamespace(containers=Containers()), tmp_path,
    ).replay(CrashObservation(
        project_id=7, campaign_id=9, commit_sha=COMMIT, engine="libfuzzer",
        image_id=IMAGE_ID, target_asset_id=31, sanitizer="address",
        command=("/opt/bigeye/parser", "-runs=1", "/bigeye/input/crash"),
        input_bytes=b"input",
    ), b"input", "original"))

    assert result.crashed is expected_crashed
    assert result.signal == expected_signal
    assert result.error == expected_error


def test_docker_crash_replay_feeds_afl_stdin_bytes_without_adding_an_argv_path(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.crashes.quarantine import CrashObservation
    from backend.services.campaigns.production_evidence_factory import DockerCrashReplayExecutor

    class AttachedSocket:
        def __init__(self):
            self._sock = self
            self.sent = bytearray()
            self.shutdown_mode = None
            self.closed = False
            self.events = []
            self._response = SimpleNamespace(close=lambda: self.events.append("response"))

        def sendall(self, value): self.sent.extend(value)
        def shutdown(self, value): self.shutdown_mode = value
        def close(self): self.events.append("socket"); self.closed = True

    class Container:
        def __init__(self): self.socket = AttachedSocket()
        def attach_socket(self, params):
            assert params == {"stdin": 1, "stream": 1}
            return self.socket
        def start(self): pass
        def wait(self, timeout): return {"StatusCode": 139}
        def logs(self, **_kwargs): return [b"Segmentation fault\n"]
        def remove(self, force=False): pass

    class Containers:
        def __init__(self): self.container = Container(); self.kwargs = None
        def create(self, *args, **kwargs): self.kwargs = (args, kwargs); return self.container

    containers = Containers()
    result = asyncio.run(DockerCrashReplayExecutor(
        SimpleNamespace(containers=containers), tmp_path,
    ).replay(CrashObservation(
        project_id=7, campaign_id=9, commit_sha=COMMIT, engine="afl",
        image_id=IMAGE_ID, target_asset_id=31, sanitizer="address",
        command=("/opt/bigeye/stdin-parser", "--encrypted"), input_bytes=b"boom",
        input_mode="stdin",
    ), b"boom", "original"))

    assert containers.kwargs[0][1] == ["/opt/bigeye/stdin-parser", "--encrypted"]
    assert containers.kwargs[1]["detach"] is False
    assert containers.kwargs[1]["stdin_open"] is True
    assert containers.kwargs[1]["volumes"] == {}
    assert bytes(containers.container.socket.sent) == b"boom"
    assert containers.container.socket.shutdown_mode == socket.SHUT_WR
    assert containers.container.socket.closed is True
    assert containers.container.socket.events == ["response", "socket"]
    assert result.crashed is True


@pytest.mark.parametrize("timeout_shape", ["direct", "wrapped"])
def test_docker_crash_replay_retains_sanitizer_evidence_when_wait_transport_times_out(
    tmp_path: Path, timeout_shape: str,
) -> None:
    from requests.exceptions import ConnectionError as RequestsConnectionError
    from requests.exceptions import ReadTimeout
    from urllib3.exceptions import ReadTimeoutError

    from backend.fuzzing.crashes.quarantine import CrashObservation
    from backend.services.campaigns.production_evidence_factory import DockerCrashReplayExecutor

    class AttachedSocket:
        def __init__(self): self._sock = self
        def sendall(self, _value): pass
        def shutdown(self, _value): pass
        def close(self): pass

    class Container:
        def __init__(self): self.socket = AttachedSocket(); self.removed = False
        def attach_socket(self, params): return self.socket
        def start(self): pass
        def wait(self, timeout):
            if timeout_shape == "direct":
                raise ReadTimeout("emulated target did not exit")
            raise RequestsConnectionError(
                ReadTimeoutError(None, None, "emulated target did not exit"),
            )
        def logs(self, **_kwargs):
            return [
                b"ERROR: AddressSanitizer: stack-buffer-overflow\n",
                b"#0 0x123 in process_payload /src/src/main.c:20\n",
            ]
        def remove(self, force=False): self.removed = force

    container = Container()
    result = asyncio.run(DockerCrashReplayExecutor(
        SimpleNamespace(containers=SimpleNamespace(create=lambda *_args, **_kwargs: container)),
        tmp_path,
    ).replay(CrashObservation(
        project_id=7, campaign_id=9, commit_sha=COMMIT, engine="afl",
        image_id=IMAGE_ID, target_asset_id=31, sanitizer="address+undefined",
        command=("/opt/bigeye/stdin-parser",), input_bytes=b"boom", input_mode="stdin",
    ), b"boom", "original"))

    assert result.crashed is True
    assert result.exit_code is None
    assert result.sanitizer == "address"
    assert result.source_location == "src/main.c:20"
    assert result.error is None
    assert container.removed is True


def test_docker_crash_replay_preserves_wait_transport_failure_without_crash_evidence(
    tmp_path: Path,
) -> None:
    from requests.exceptions import ConnectionError as RequestsConnectionError

    from backend.fuzzing.crashes.quarantine import CrashObservation
    from backend.services.campaigns.production_evidence_factory import DockerCrashReplayExecutor

    class AttachedSocket:
        def __init__(self): self._sock = self
        def sendall(self, _value): pass
        def shutdown(self, _value): pass
        def close(self): pass

    class Container:
        def __init__(self): self.socket = AttachedSocket()
        def attach_socket(self, params): return self.socket
        def start(self): pass
        def wait(self, timeout): raise RequestsConnectionError("Docker transport unavailable")
        def logs(self, **_kwargs): return [b"target is still running\n"]
        def remove(self, force=False): pass

    with pytest.raises(RequestsConnectionError, match="Docker transport unavailable"):
        asyncio.run(DockerCrashReplayExecutor(
            SimpleNamespace(containers=SimpleNamespace(
                create=lambda *_args, **_kwargs: Container(),
            )),
            tmp_path,
        ).replay(CrashObservation(
            project_id=7, campaign_id=9, commit_sha=COMMIT, engine="afl",
            image_id=IMAGE_ID, target_asset_id=31, sanitizer="address+undefined",
            command=("/opt/bigeye/stdin-parser",), input_bytes=b"boom", input_mode="stdin",
        ), b"boom", "original"))


def test_docker_crash_replay_does_not_accept_logs_after_a_non_timeout_connection_failure(
    tmp_path: Path,
) -> None:
    from requests.exceptions import ConnectionError as RequestsConnectionError

    from backend.fuzzing.crashes.quarantine import CrashObservation
    from backend.services.campaigns.production_evidence_factory import DockerCrashReplayExecutor

    class AttachedSocket:
        def __init__(self): self._sock = self
        def sendall(self, _value): pass
        def shutdown(self, _value): pass
        def close(self): pass

    class Container:
        def __init__(self): self.socket = AttachedSocket(); self.logs_read = False
        def attach_socket(self, params): return self.socket
        def start(self): pass
        def wait(self, timeout): raise RequestsConnectionError("Docker connection closed")
        def logs(self, **_kwargs):
            self.logs_read = True
            return [b"ERROR: AddressSanitizer: stale output\n"]
        def remove(self, force=False): pass

    container = Container()
    with pytest.raises(RequestsConnectionError, match="Docker connection closed"):
        asyncio.run(DockerCrashReplayExecutor(
            SimpleNamespace(containers=SimpleNamespace(
                create=lambda *_args, **_kwargs: container,
            )),
            tmp_path,
        ).replay(CrashObservation(
            project_id=7, campaign_id=9, commit_sha=COMMIT, engine="afl",
            image_id=IMAGE_ID, target_asset_id=31, sanitizer="address+undefined",
            command=("/opt/bigeye/stdin-parser",), input_bytes=b"boom", input_mode="stdin",
        ), b"boom", "original"))

    assert container.logs_read is False


def test_native_corpus_runner_uses_the_complete_bounded_container_contract(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign
    from backend.services.campaigns.production_evidence_factory import DockerNativeCorpusRunner

    corpus = tmp_path / "corpus"
    output = tmp_path / "output"
    corpus.mkdir()
    output.mkdir()

    class Container:
        def start(self):
            native = output / ".bigeye-afl-cmin-output"
            native.mkdir()
            (native / "selected").write_bytes(b"seed")
        def wait(self, timeout): return {"StatusCode": 0}
        def logs(self, **_kwargs): return []
        def remove(self, force=False): pass

    class Containers:
        def create(self, *args, **kwargs): self.args = args; self.kwargs = kwargs; return Container()

    containers = Containers()
    runner = DockerNativeCorpusRunner(
        SimpleNamespace(containers=containers),
        SimpleNamespace(image_id=IMAGE_ID, memory_limit_mb=512, environment={}),
    )
    runner.run(
        CorpusCampaign("afl++", corpus, ("/opt/bigeye/parser", "@@"), 9, 7),
        ("afl-cmin", "-i", "/campaign/corpus", "-o", "/campaign/minimised", "--",
         "/opt/bigeye/parser", "@@"),
        output,
    )

    assert containers.kwargs["platform"] == "linux/amd64"
    assert containers.kwargs["network_mode"] == "none"
    assert containers.kwargs["ipc_mode"] == "private"
    assert containers.kwargs["cgroupns"] == "private"
    assert containers.kwargs["runtime"] == "runc"
    assert containers.kwargs["restart_policy"] == {"Name": "no"}
    assert containers.kwargs["publish_all_ports"] is False
    assert containers.kwargs["privileged"] is False
    assert containers.kwargs["user"]
    assert containers.kwargs["tmpfs"] == {
        "/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777",
    }
    assert containers.args[1][4] == "/campaign/minimised/.bigeye-afl-cmin-output"
    assert (output / "selected").read_bytes() == b"seed"
    assert not (output / ".bigeye-afl-cmin-output").exists()


def test_native_afl_tmin_runner_mounts_only_the_selected_cmin_input(tmp_path: Path) -> None:
    from backend.fuzzing.corpus.minimisation import CorpusCampaign
    from backend.services.campaigns.production_evidence_factory import DockerNativeCorpusRunner

    corpus = tmp_path / "corpus"
    selected = tmp_path / "cmin" / "selected"
    output = tmp_path / "tmin" / "selected"
    corpus.mkdir()
    selected.parent.mkdir()
    selected.write_bytes(b"seed")
    output.parent.mkdir()

    class Container:
        def start(self): output.write_bytes(b"min")
        def wait(self, timeout): return {"StatusCode": 0}
        def logs(self, **_kwargs): return []
        def remove(self, force=False): pass

    class Containers:
        def create(self, *args, **kwargs): self.args = args; self.kwargs = kwargs; return Container()

    containers = Containers()
    runner = DockerNativeCorpusRunner(
        SimpleNamespace(containers=containers),
        SimpleNamespace(image_id=IMAGE_ID, memory_limit_mb=512, environment={}),
    )
    runner.run(
        CorpusCampaign("afl++", corpus, ("/opt/bigeye/parser", "@@"), 9, 7),
        ("afl-tmin", "-i", "/campaign/minimised/selected", "-o",
         "/campaign/tmin/selected", "--", "/opt/bigeye/parser", "@@"),
        output,
        selected,
    )

    command = containers.args[1]
    assert command[2] == "/campaign/minimisation-input"
    assert containers.kwargs["volumes"][str(selected)] == {
        "bind": "/campaign/minimisation-input", "mode": "ro",
    }
    assert output.read_bytes() == b"min"


def _triage_evidence():
    from backend.fuzzing.crashes.triage import CrashTriageEvidence

    return CrashTriageEvidence(
        project_id=7, campaign_id=9, fingerprint="f" * 64, reproducible=True,
        original_attempts=3, matching_original_runs=3, signal="SIGSEGV",
        sanitizer="address", source_location="src/parser.c:4", stack=("parse",),
        coverage=("src/parser.c:4",), compatible_variants=(), clean_variant=None,
        minimisation={"reduced": True}, correction=None, harness_misuse_evidence=(),
        evidence_ids=("replay:original:1",),
    )


def _triage_context(tmp_path: Path, source: str = "int parse(const char *input);\n"):
    from backend.agents.context import AgentContext
    from backend.fuzzing.discovery.retrieval import EvidenceRetriever

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "parser.c").write_text(source, encoding="utf-8")
    return AgentContext(
        7, COMMIT, repository, tmp_path / "generated", EvidenceRetriever(repository),
    )


def _triage_output(evidence_ids):
    return {
        "classification": "true vulnerability", "description": "stable fault",
        "evidence_ids": list(evidence_ids), "uncertainty": "impact unknown",
        "priority_rationale": "stable", "repair_intent": "inspect parser",
    }


def _triage_result(output, citation: str | None = None):
    raw_responses = ()
    if citation is not None:
        raw_responses = (SimpleNamespace(output=[{
            "type": "message", "content": [{
                "type": "output_text", "text": "official documentation", "annotations": [{
                    "type": "url_citation", "url": citation,
                }],
            }],
        }]),)
    return SimpleNamespace(
        final_output=output, raw_responses=raw_responses, new_items=(),
    )


async def _retrieve_for_triage(agent, context, question: str, limit: int):
    from agents import RunConfig
    from agents.tool_context import ToolContext

    tool = next(item for item in agent.tools if item.name == "retrieve_repository_evidence")
    arguments = json.dumps({"question": question, "limit": limit})
    return await tool.on_invoke_tool(ToolContext(
        context, tool_name=tool.name, tool_call_id="retrieve-" + question[:20],
        tool_arguments=arguments, run_config=RunConfig(), agent=agent,
    ), arguments)


def test_crash_triage_luna_registers_repository_evidence_returned_by_its_tool(
    tmp_path: Path,
) -> None:
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist

    context = _triage_context(tmp_path)
    calls = []

    async def runner(agent, _prompt, **kwargs):
        calls.append((agent.model, kwargs["max_turns"]))
        excerpts = await _retrieve_for_triage(agent, context, "parse input", 1)
        return _triage_result(_triage_output([
            excerpts[0]["evidence_id"], "replay:original:1",
        ]))

    result = asyncio.run(ProductionCrashTriageSpecialist(
        SimpleNamespace(context=lambda _project_id: context), runner=runner,
    ).triage(_triage_evidence()))

    assert result.classification == "true vulnerability"
    assert result.evidence_ids == ["replay:original:1"]
    assert calls == [("gpt-5.6-luna", 14)]


def test_crash_triage_terra_registers_only_its_own_retry_retrieval(
    tmp_path: Path,
) -> None:
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist

    context = _triage_context(
        tmp_path,
        "int luna_parser(const char *input);\nint terra_parser(const char *input);\n",
    )
    calls = []
    retrieved = {}

    async def runner(agent, _prompt, **kwargs):
        calls.append((agent.model, kwargs["max_turns"]))
        model = "luna" if agent.model == "gpt-5.6-luna" else "terra"
        excerpts = await _retrieve_for_triage(agent, context, f"{model} parser", 1)
        retrieved[model] = excerpts[0]["evidence_id"]
        cited = [excerpts[0]["evidence_id"]]
        if model == "terra":
            cited.append("replay:original:1")
        return _triage_result(_triage_output(cited))

    result = asyncio.run(ProductionCrashTriageSpecialist(
        SimpleNamespace(context=lambda _project_id: context), runner=runner,
    ).triage(_triage_evidence()))

    assert result.classification == "true vulnerability"
    assert result.evidence_ids == ["replay:original:1"]
    assert retrieved["luna"] != retrieved["terra"]
    assert calls == [("gpt-5.6-luna", 14), ("gpt-5.6-terra", 14)]


def test_crash_triage_fails_after_two_attempts_invent_evidence_and_traces_raw_results(
    tmp_path: Path,
) -> None:
    from backend.agents.tools.agent_dispatch import SpecialistValidationError
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist
    from backend.services.observability.event_store import ProjectEventStore

    context = _triage_context(tmp_path)
    store = ProjectEventStore(tmp_path)
    calls = []

    async def runner(agent, _prompt, **kwargs):
        calls.append((agent.model, kwargs["max_turns"]))
        return _triage_result(_triage_output(["invented:" + agent.model]))

    with pytest.raises(
        SpecialistValidationError, match="failed deterministic validation twice",
    ):
        asyncio.run(ProductionCrashTriageSpecialist(
            SimpleNamespace(context=lambda _project_id: context), events=store, runner=runner,
        ).triage(_triage_evidence()))

    debug = [
        event.payload
        for event in asyncio.run(store.read(7, "debug", -1, 100))
    ]
    assert calls == [("gpt-5.6-luna", 14), ("gpt-5.6-terra", 14)]
    assert [event["event"] for event in debug] == [
        "workflow.result", "specialist.retry", "workflow.result", "workflow.error",
    ]
    assert [event["output"]["evidence_ids"] for event in debug if event["event"] == "workflow.result"] == [
        ["invented:gpt-5.6-luna"], ["invented:gpt-5.6-terra"],
    ]


def test_crash_triage_accepts_an_exact_official_citation_id(tmp_path: Path) -> None:
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist

    context = _triage_context(tmp_path)
    citation = "https://llvm.org/docs/LibFuzzer.html"
    calls = []

    async def runner(agent, _prompt, **kwargs):
        calls.append((agent.model, kwargs["max_turns"]))
        return _triage_result(
            _triage_output([citation, "replay:original:1"]), citation,
        )

    result = asyncio.run(ProductionCrashTriageSpecialist(
        SimpleNamespace(context=lambda _project_id: context), runner=runner,
    ).triage(_triage_evidence()))

    assert result.evidence_ids == ["replay:original:1"]
    assert calls == [("gpt-5.6-luna", 14)]


def test_crash_triage_retries_a_nonofficial_citation_then_accepts_terra_official_source(
    tmp_path: Path,
) -> None:
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist

    context = _triage_context(tmp_path)
    rejected = "https://example.org/fuzzing"
    accepted = "https://llvm.org/docs/LibFuzzer.html"
    calls = []

    async def runner(agent, _prompt, **kwargs):
        calls.append((agent.model, kwargs["max_turns"]))
        citation = rejected if agent.model == "gpt-5.6-luna" else accepted
        return _triage_result(
            _triage_output([citation, "replay:original:1"]), citation,
        )

    result = asyncio.run(ProductionCrashTriageSpecialist(
        SimpleNamespace(context=lambda _project_id: context), runner=runner,
    ).triage(_triage_evidence()))

    assert result.evidence_ids == ["replay:original:1"]
    assert calls == [("gpt-5.6-luna", 14), ("gpt-5.6-terra", 14)]


def test_crash_triage_retrieval_bounds_requests_and_caps_dynamic_evidence_at_64(
    tmp_path: Path,
) -> None:
    from backend.agents.tools.evidence_retrieval import evidence_request_error
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist

    source = "".join(
        f"int group{group}_parser_{index}(const char *input);\n"
        for group in range(6) for index in range(12)
    )
    context = _triage_context(tmp_path, source)
    observations = {}

    async def runner(agent, _prompt, **kwargs):
        tool = next(item for item in agent.tools if item.name == "retrieve_repository_evidence")
        observations["question_schema"] = tool.params_json_schema["properties"]["question"]
        observations["limit_schema"] = tool.params_json_schema["properties"]["limit"]
        retained = []
        for group in range(5):
            retained.extend(await _retrieve_for_triage(agent, context, f"group{group}", 12))
        retained.extend(await _retrieve_for_triage(agent, context, "group5", 4))
        observations["overflow"] = await _retrieve_for_triage(agent, context, "group5", 5)
        observations["overlong"] = await _retrieve_for_triage(agent, context, "x" * 201, 12)
        observations["max_turns"] = kwargs["max_turns"]
        return _triage_result(_triage_output([
            retained[-1]["evidence_id"], "replay:original:1",
        ]))

    result = asyncio.run(ProductionCrashTriageSpecialist(
        SimpleNamespace(context=lambda _project_id: context), runner=runner,
    ).triage(_triage_evidence()))

    correction = evidence_request_error(None, ValueError("bounded"))
    assert result.classification == "true vulnerability"
    assert result.evidence_ids == ["replay:original:1"]
    assert observations["question_schema"]["maxLength"] == 200
    assert observations["limit_schema"]["maximum"] == 12
    assert observations["overflow"] == correction
    assert observations["overlong"] == correction
    assert observations["max_turns"] == 14


def test_crash_triage_retries_invalid_luna_output_once_with_terra_and_same_evidence() -> None:
    from backend.fuzzing.crashes.triage import CrashTriageEvidence
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist

    evidence = CrashTriageEvidence(
        project_id=7, campaign_id=9, fingerprint="f" * 64, reproducible=True,
        original_attempts=3, matching_original_runs=3, signal="SIGSEGV",
        sanitizer="address", source_location="src/parser.c:4", stack=("parse",),
        coverage=("src/parser.c:4",), compatible_variants=(), clean_variant=None,
        minimisation={"reduced": True}, correction=None, harness_misuse_evidence=(),
        evidence_ids=("replay:original:1",),
    )
    valid = {
        "classification": "true vulnerability", "description": "stable fault",
        "evidence_ids": ["replay:original:1"], "uncertainty": "impact unknown",
        "priority_rationale": "stable", "repair_intent": "inspect parser",
    }
    calls = []

    async def runner(agent, prompt, **kwargs):
        calls.append((agent.model, prompt, kwargs["context"]))
        output = {**valid, "classification": "invented"} if len(calls) == 1 else valid
        return SimpleNamespace(final_output=output, raw_responses=(), new_items=())

    context = SimpleNamespace(evidence=SimpleNamespace(inventory=SimpleNamespace(build_files=())))
    specialist = ProductionCrashTriageSpecialist(
        SimpleNamespace(context=lambda project_id: context), runner=runner,
    )
    result = asyncio.run(specialist.triage(evidence))

    assert result.classification == "true vulnerability"
    assert [model for model, _prompt, _context in calls] == [
        "gpt-5.6-luna", "gpt-5.6-terra",
    ]
    assert calls[0][1:] == calls[1][1:]


def test_crash_triage_does_not_escalate_a_transport_failure_to_terra() -> None:
    from backend.fuzzing.crashes.triage import CrashTriageEvidence
    from backend.services.campaigns.production_evidence_factory import ProductionCrashTriageSpecialist

    evidence = CrashTriageEvidence(
        project_id=7, campaign_id=9, fingerprint="f" * 64, reproducible=True,
        original_attempts=3, matching_original_runs=3, signal="SIGSEGV",
        sanitizer="address", source_location="src/parser.c:4", stack=("parse",),
        coverage=(), compatible_variants=(), clean_variant=None,
        minimisation={"reduced": True}, correction=None, harness_misuse_evidence=(),
        evidence_ids=("replay:original:1",),
    )
    calls = []

    async def runner(agent, prompt, **kwargs):
        calls.append((agent.model, kwargs.get("max_turns")))
        raise ConnectionError("transport unavailable")

    context = SimpleNamespace(evidence=SimpleNamespace(inventory=SimpleNamespace(build_files=())))
    specialist = ProductionCrashTriageSpecialist(
        SimpleNamespace(context=lambda project_id: context), runner=runner,
    )

    with pytest.raises(ConnectionError, match="transport unavailable"):
        asyncio.run(specialist.triage(evidence))
    assert calls == [("gpt-5.6-luna", 14)]


def test_replay_workspace_rejects_a_symlinked_intermediate_project_root(tmp_path: Path) -> None:
    from backend.fuzzing.crashes.quarantine import CrashObservation
    from backend.services.campaigns.production_evidence_factory import DockerCrashReplayExecutor

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "projects").mkdir()
    (tmp_path / "projects" / "7").symlink_to(outside, target_is_directory=True)
    observation = CrashObservation(
        project_id=7, campaign_id=9, commit_sha=COMMIT, engine="libfuzzer",
        image_id=IMAGE_ID, target_asset_id=31, sanitizer="address",
        command=("/opt/bigeye/parser", "-runs=1", "/bigeye/input/crash"),
        input_bytes=b"input",
    )

    with pytest.raises((OSError, ValueError)):
        asyncio.run(DockerCrashReplayExecutor(
            SimpleNamespace(containers=SimpleNamespace()), tmp_path,
        ).replay(observation, b"input", "original"))
    assert list(outside.iterdir()) == []


def test_application_wires_the_concrete_evidence_factory_and_artifact_schema(tmp_path: Path) -> None:
    from unittest.mock import AsyncMock

    from backend.api.dependencies import build_services
    from backend.services.campaigns.production_evidence_factory import (
        DeferredCampaignEvidenceProcessor,
        ProductionCampaignEvidenceFactory,
    )

    services = build_services(AsyncMock(), tmp_path)
    runtime = services.recovery._coordinator_factory(7)._runtime

    assert isinstance(runtime._evidence_processor, DeferredCampaignEvidenceProcessor)
    assert isinstance(runtime._evidence_processor._factory, ProductionCampaignEvidenceFactory)
    schema = Path("backend/database/schema.sql").read_text()
    assert "CREATE TABLE campaign_artifacts" in schema
    assert "COMMENT ON SCHEMA public IS 'bigeye-schema:release-1';" in schema
