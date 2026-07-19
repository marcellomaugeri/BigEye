"""Clean coverage replay and durable first-hit evidence."""

from __future__ import annotations

import asyncio
import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


def run(awaitable):
    return asyncio.run(awaitable)


class _CoverageExecutor:
    def __init__(self, exports: dict[str, dict], sources: dict[str, bytes] | None = None):
        self.exports = exports
        self.sources = sources or {}
        self.calls: list[tuple[str, tuple[str, ...], dict[str, str], Path]] = []

    def run(self, image_id, command, environment, workspace):
        self.calls.append((image_id, command, environment, workspace))
        if "LLVM_PROFILE_FILE" in environment:
            profile = environment["LLVM_PROFILE_FILE"].replace("/coverage/", "").replace("%p", "123")
            destination = workspace / profile
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"profile")
        if command[0] == "llvm-cov-18":
            profile = next(part.split("=", 1)[1] for part in command if part.startswith("-instr-profile="))
            key = Path(profile).stem
            return json.dumps(self.exports[key]).encode()
        if command[0] == "cat":
            return self.sources[command[1]]
        return b""


def _export(path: str = "/src/src/a.c", line: int = 12):
    return {
        "data": [{
            "files": [{"filename": path, "segments": [[line, 1, 1, True, True, False]]}],
            "functions": [{"name": "parse", "filenames": [path], "regions": [[line, 1, line + 2, 1, 1, 0, 0, 0]]}],
        }]
    }


def _campaign(tmp_path: Path, **changes):
    values = {
        "id": 4,
        "project_id": 7,
        "commit_sha": "a" * 40,
        "clean_image": "bigeye-coverage:7",
        "binary_path": "/src/build/clean-target",
        "replay_command": ("/src/build/clean-target", "{input}"),
        "target_asset_id": 31,
        "configuration_asset_id": 32,
        "strategy_asset_id": 33,
        "cpu_exposure_seconds": 8.5,
        "repository_root": tmp_path / "repository",
        "source_root": "/src",
    }
    return SimpleNamespace(**(values | changes))


def _client():
    return SimpleNamespace(api=SimpleNamespace(inspect_image=lambda _image: {
        "Id": "sha256:clean",
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"Labels": {
            "bigeye.project": "7", "bigeye.commit": "a" * 40, "bigeye.layer": "coverage",
        }},
    }))


def test_replay_uses_unique_profiles_exact_tools_and_only_clean_project_source(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src/a.c").write_text("int parse(void) { return 0; }\n")
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    exports = {
        "input-000000": _export(),
        "input-000001": _export("/usr/include/stdio.h", 2),
        "merged": _export(),
    }
    executor = _CoverageExecutor(exports, {"/src/src/a.c": b"int parse(void) { return 0; }\n"})

    snapshot = LlvmCoverage(_client(), executor, tmp_path / "work").replay(
        _campaign(tmp_path), [first, second]
    )

    commands = [call[1] for call in executor.calls]
    replay_calls = [call for call in executor.calls if call[1][0] == "/src/build/clean-target"]
    assert [call[2]["LLVM_PROFILE_FILE"] for call in replay_calls] == [
        "/coverage/profiles/input-000000-%p.profraw",
        "/coverage/profiles/input-000001-%p.profraw",
    ]
    assert sum(command[0] == "llvm-profdata-18" for command in commands) == 3
    assert sum(command[0] == "llvm-cov-18" for command in commands) == 3
    assert [command for command in commands if command[0] == "cat"] == [("cat", "/src/src/a.c")]
    assert all(not isinstance(command, str) for command in commands)
    assert {(line.source_path, line.line_number) for line in snapshot.lines} == {("src/a.c", 12)}
    assert len(snapshot.hits) == 1
    assert snapshot.hits[0].testcase == b"first"


@pytest.mark.parametrize("labels", [
    {"bigeye.project": "7", "bigeye.commit": "b" * 40, "bigeye.layer": "coverage"},
    {"bigeye.project": "7", "bigeye.commit": "a" * 40, "bigeye.layer": "target"},
])
def test_replay_rejects_non_clean_or_wrong_commit_image(tmp_path: Path, labels):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError, LlvmCoverage

    client = SimpleNamespace(api=SimpleNamespace(inspect_image=lambda _image: {
        "Id": "sha256:image", "Os": "linux", "Architecture": "amd64", "Config": {"Labels": labels},
    }))
    executor = _CoverageExecutor({})

    with pytest.raises(CoverageIntegrityError):
        LlvmCoverage(client, executor, tmp_path / "work").replay(_campaign(tmp_path), [])
    assert executor.calls == []


def test_replay_rejects_shell_wrapped_target_command(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    with pytest.raises(ValueError, match="shell"):
        LlvmCoverage(_client(), _CoverageExecutor({}), tmp_path / "work").replay(
            _campaign(tmp_path, replay_command=("/bin/sh", "-c", "{input}")), []
        )


def test_docker_executor_is_isolated_and_returns_stdout_only(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import DockerCoverageExecutor

    class Container:
        def __init__(self):
            self.started = False
            self.removed = False

        def start(self):
            self.started = True

        def wait(self, timeout):
            assert timeout == 30
            return {"StatusCode": 0}

        def logs(self, **kwargs):
            assert kwargs == {"stdout": True, "stderr": False, "stream": True, "follow": False}
            return [b"res", b"ult"]

        def remove(self, force):
            self.removed = force

    container = Container()
    created = {}

    def create(*args, **kwargs):
        created.update(kwargs)
        return container

    containers = SimpleNamespace(create=create)
    client = SimpleNamespace(containers=containers)

    result = DockerCoverageExecutor(client, timeout_seconds=30).run(
        "sha256:clean", ("llvm-cov-18", "export"), {}, tmp_path
    )

    assert result == b"result"
    assert container.started is True
    assert container.removed is True
    assert created["platform"] == "linux/amd64"
    assert created["network_mode"] == "none"
    assert created["read_only"] is True
    assert created["cap_drop"] == ["ALL"]
    assert created["user"] == f"{__import__('os').getuid()}:{__import__('os').getgid()}"


def test_fuzz_patch_paths_cannot_enter_reported_coverage(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import (
        CoverageHit,
        CoverageIntegrityError,
        CoverageLine,
        CoverageSnapshot,
    )
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository = AsyncMock()
    repository.list_for_project.return_value = []
    snapshot = CoverageSnapshot(
        project_id=7, campaign_id=4, strategy_asset_id=33, commit_sha="a" * 40,
        clean_image_id="sha256:clean", target_asset_id=31, configuration_asset_id=32,
        replay_command=("/target", "{input}"), cpu_exposure_seconds=1.0,
        repository_root=tmp_path / "repository", build_kind="fuzz-target",
        lines=(CoverageLine("src/a.c", 12, "parse"),),
        hits=(CoverageHit("src/a.c", 12, b"seed", "1" * 64),),
    )

    with pytest.raises(CoverageIntegrityError):
        run(TraceabilityService(tmp_path, repository, lambda *_: True).record(snapshot))
    repository.create.assert_not_awaited()


def test_first_testcase_is_stable_per_strategy_and_replayed_before_insert(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageLine, CoverageSnapshot
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    (repository_root / "src/a.c").write_text("one\ntwo\nthree\n")
    repository = AsyncMock()
    repository.list_for_project.return_value = []
    repository.create.side_effect = lambda **values: SimpleNamespace(id=1, **values)
    observed = []

    def verifier(snapshot, hit, testcase):
        observed.append((testcase.read_bytes(), repository.create.await_count))
        return hit.testcase_sha256 == sha256(b"first").hexdigest()

    service = TraceabilityService(tmp_path, repository, verifier)
    base = dict(
        project_id=7, campaign_id=4, strategy_asset_id=33, commit_sha="a" * 40,
        clean_image_id="sha256:clean", target_asset_id=31, configuration_asset_id=32,
        replay_command=("/target", "{input}"), cpu_exposure_seconds=1.0,
        repository_root=repository_root, build_kind="clean",
        lines=(CoverageLine("src/a.c", 2, "parse"),),
    )
    first_digest = sha256(b"first").hexdigest()
    first = CoverageSnapshot(**base, hits=(CoverageHit("src/a.c", 2, b"first", first_digest),))
    later = CoverageSnapshot(**base, hits=(CoverageHit("src/a.c", 2, b"later", sha256(b"later").hexdigest()),))

    created = run(service.record(first))
    repository.list_for_project.return_value = created
    ignored = run(service.record(later))

    assert observed == [(b"first", 0)]
    assert repository.create.await_count == 1
    assert ignored == []
    metadata = json.loads(next((tmp_path / "projects/7/coverage/4/33").glob("*.json")).read_text())
    assert metadata == {
        "campaign_id": 4,
        "clean_image_id": "sha256:clean",
        "configuration_asset_id": 32,
        "replay_command": ["/target", "{input}"],
        "strategy_asset_id": 33,
        "target_asset_id": 31,
        "testcase_sha256": first_digest,
        "source_sha256": sha256(b"one\ntwo\nthree\n").hexdigest(),
    }


def test_failed_replay_never_commits_evidence(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageIntegrityError, CoverageLine, CoverageSnapshot
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    (repository_root / "src/a.c").write_text("x\n")
    repository = AsyncMock()
    repository.list_for_project.return_value = []
    snapshot = CoverageSnapshot(
        7, 4, 33, "a" * 40, "sha256:clean", 31, None, ("/target", "{input}"), 1.0,
        repository_root, "clean", (CoverageLine("src/a.c", 1, None),),
        (CoverageHit("src/a.c", 1, b"seed", sha256(b"seed").hexdigest()),),
    )

    with pytest.raises(CoverageIntegrityError, match="did not reproduce"):
        run(TraceabilityService(tmp_path, repository, lambda *_: False).record(snapshot))
    repository.create.assert_not_awaited()
    assert list((tmp_path / "projects/7/coverage/4/33").glob("*.input")) == []
    assert list((tmp_path / "projects/7/coverage/4/33").glob("*.json")) == []


def test_strategy_directory_swap_during_replay_cannot_commit_or_delete_replacement(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageIntegrityError, CoverageLine, CoverageSnapshot
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    source = repository_root / "src/a.c"
    source.write_text("x\n")
    content = b"seed"
    snapshot = CoverageSnapshot(
        7, 4, 33, "a" * 40, "sha256:clean", 31, None, ("/target", "{input}"), 1.0,
        repository_root, "clean", (CoverageLine("src/a.c", 1, None, sha256(b"x\n").hexdigest()),),
        (CoverageHit("src/a.c", 1, content, sha256(content).hexdigest()),),
    )
    repository = AsyncMock()
    repository.list_for_project.return_value = []
    retired = tmp_path / "retired"

    def swap(_snapshot, _hit, testcase):
        strategy = testcase.parent
        strategy.rename(retired)
        strategy.mkdir()
        (strategy / "replacement").write_text("keep")
        return True

    with pytest.raises(CoverageIntegrityError, match="directory changed"):
        run(TraceabilityService(tmp_path, repository, swap).record(snapshot))

    repository.create.assert_not_awaited()
    assert (tmp_path / "projects/7/coverage/4/33/replacement").read_text() == "keep"
    assert any(retired.glob("*.input"))


def test_record_rejects_source_hash_not_bound_to_checkout(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageIntegrityError, CoverageLine, CoverageSnapshot
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    (repository_root / "src/a.c").write_text("x\n")
    content = b"seed"
    snapshot = CoverageSnapshot(
        7, 4, 33, "a" * 40, "sha256:clean", 31, None, ("/target", "{input}"), 1.0,
        repository_root, "clean", (CoverageLine("src/a.c", 1, None, "0" * 64),),
        (CoverageHit("src/a.c", 1, content, sha256(content).hexdigest()),),
    )
    repository = AsyncMock()
    repository.list_for_project.return_value = []

    with pytest.raises(CoverageIntegrityError, match="source hash"):
        run(TraceabilityService(tmp_path, repository, lambda *_: True).record(snapshot))
    repository.create.assert_not_awaited()


@pytest.mark.parametrize("source_path", ["build/a.c", "generated/a.c", "harness/a.c", "fuzz-target/a.c"])
def test_traceability_independently_rejects_non_project_source_trees(tmp_path: Path, source_path: str):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageIntegrityError, CoverageLine, CoverageSnapshot
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    source = repository_root / source_path
    source.parent.mkdir(parents=True)
    source.write_text("x\n")
    content = b"seed"
    snapshot = CoverageSnapshot(
        7, 4, 33, "a" * 40, "sha256:clean", 31, None, ("/target", "{input}"), 1.0,
        repository_root, "clean", (CoverageLine(source_path, 1, None),),
        (CoverageHit(source_path, 1, content, sha256(content).hexdigest()),),
    )
    repository = AsyncMock()
    repository.list_for_project.return_value = []

    with pytest.raises((CoverageIntegrityError, ValueError)):
        run(TraceabilityService(tmp_path, repository, lambda *_: True).record(snapshot))
    repository.create.assert_not_awaited()


def test_source_query_rejects_checkout_bytes_that_differ_from_clean_image(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "projects/7/repository"
    (checkout / "src").mkdir(parents=True)
    source = checkout / "src/a.c"
    source.write_text("modified\n")
    commit = "a" * 40
    metadata_root = tmp_path / "projects/7/coverage/4/33"
    metadata_root.mkdir(parents=True)
    digest = "b" * 64
    (metadata_root / f"{digest}.json").write_text(json.dumps({
        "campaign_id": 4, "clean_image_id": "sha256:clean", "configuration_asset_id": None,
        "replay_command": ["/target", "{input}"], "strategy_asset_id": 33,
        "target_asset_id": 31, "testcase_sha256": digest,
        "source_sha256": sha256(b"committed\n").hexdigest(),
    }))
    repository = AsyncMock()
    repository.list_for_project.return_value = [SimpleNamespace(
        commit_sha=commit, source_path="src/a.c", line_number=1, asset_id=33,
        cpu_exposure_seconds=1.0, function_name=None, campaign_id=4, first_testcase_sha256=digest,
    )]

    with pytest.raises(CoverageIntegrityError, match="clean image"):
        run(TraceabilityService(tmp_path, repository, lambda *_: True).source_file(7, "src/a.c", 1, 1))


def test_line_query_rejects_sidecar_identity_tampering(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    root = tmp_path / "projects/7/coverage/4/33"
    root.mkdir(parents=True)
    digest = "b" * 64
    (root / f"{digest}.json").write_text(json.dumps({
        "campaign_id": 999, "clean_image_id": "sha256:clean", "configuration_asset_id": None,
        "replay_command": ["/target", "{input}"], "strategy_asset_id": 33,
        "target_asset_id": 31, "testcase_sha256": digest, "source_sha256": "c" * 64,
    }))
    repository = AsyncMock()
    repository.list_for_project.return_value = [SimpleNamespace(
        commit_sha="a" * 40, source_path="src/a.c", line_number=1, asset_id=33,
        cpu_exposure_seconds=1.0, function_name=None, campaign_id=4, first_testcase_sha256=digest,
    )]

    with pytest.raises(CoverageIntegrityError, match="metadata identity"):
        run(TraceabilityService(tmp_path, repository, lambda *_: True).line_evidence(7, "src/a.c", 1))


def test_coverage_repository_inserts_existing_minimal_row_contract():
    from backend.repositories.coverage_repository import CoverageRepository

    pool = AsyncMock()
    pool.fetchrow.return_value = {
        "id": 1, "project_id": 7, "commit_sha": "a" * 40, "source_path": "src/a.c",
        "line_number": 12, "function_name": "parse", "campaign_id": 4, "asset_id": 33,
        "first_testcase_sha256": "b" * 64, "cpu_exposure_seconds": 1.5,
    }

    result = run(CoverageRepository(pool).create(
        project_id=7, commit_sha="a" * 40, source_path="src/a.c", line_number=12,
        function_name="parse", campaign_id=4, asset_id=33,
        first_testcase_sha256="b" * 64, cpu_exposure_seconds=1.5,
    ))

    assert result.id == 1
    assert "INSERT INTO coverage_evidence" in pool.fetchrow.await_args.args[0]
