"""Clean coverage replay and durable first-hit evidence."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from contextlib import asynccontextmanager
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
        self.calls: list[tuple[str, tuple[str, ...], dict[str, str], Path, Path | None]] = []

    def run(self, image_id, command, environment, profile_directory, input_file=None):
        self.calls.append((image_id, command, environment, profile_directory, input_file))
        if "LLVM_PROFILE_FILE" in environment:
            profile = Path(environment["LLVM_PROFILE_FILE"].replace("%p", "123")).name
            destination = profile_directory / profile
            destination.write_bytes(b"profile")
        if command[0] == "llvm-profdata-18":
            output = Path(command[command.index("-o") + 1]).name
            (profile_directory / output).write_bytes(b"profdata")
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
        "coverage_asset_id": 34,
        "cpu_exposure_seconds": 8.5,
        "repository_root": tmp_path / "repository",
        "source_root": "/src",
        "clean_image_id": "sha256:clean",
        "clean_content_hash": "c" * 64,
        "clean_parent_image_id": "sha256:parent",
    }
    return SimpleNamespace(**(values | changes))


def _client():
    return SimpleNamespace(api=SimpleNamespace(inspect_image=lambda _image: {
        "Id": "sha256:clean",
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"Labels": {
            "bigeye.project": "7", "bigeye.commit": "a" * 40, "bigeye.layer": "coverage",
            "bigeye.content-hash": "c" * 64, "bigeye.parent-image": "sha256:parent",
            "bigeye.target-asset-id": "31", "bigeye.configuration-asset-id": "32",
            "bigeye.coverage-asset-id": "34",
        }},
    }))


class _Registry:
    def __init__(self, root: Path):
        self.root = root
        self.valid = True

    async def resolve(self, project_id, commit_sha):
        from backend.fuzzing.coverage.traceability import TrustedCheckout

        if not self.valid:
            raise ValueError("checkout drift")
        details = self.root.stat()
        return TrustedCheckout(project_id, commit_sha, self.root, details.st_dev, details.st_ino)

    async def verify(self, checkout):
        if not self.valid:
            from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
            raise CoverageIntegrityError("checkout drift")
        details = self.root.stat()
        if (details.st_dev, details.st_ino) != (checkout.device, checkout.inode):
            raise ValueError("checkout drift")


class _MemoryCoverageRepository:
    def __init__(self):
        self.rows = []
        self.create_count = 0
        self.fail_create = False
        self.fail_commit = False

    @asynccontextmanager
    async def claim(self, **key):
        existing = next((row for row in self.rows if (
            row.project_id == key["project_id"] and row.commit_sha == key["commit_sha"]
            and row.source_path == key["source_path"] and row.line_number == key["line_number"]
            and row.asset_id == key["asset_id"]
        )), None)
        repository = self

        class Claim:
            async def create(self, **values):
                if repository.fail_create:
                    raise RuntimeError("database failed")
                repository.create_count += 1
                row = SimpleNamespace(
                    id=repository.create_count, project_id=key["project_id"], commit_sha=key["commit_sha"],
                    source_path=key["source_path"], line_number=key["line_number"], asset_id=key["asset_id"],
                    **values,
                )
                repository.rows.append(row)
                self.existing = row
                return row

        claim = Claim()
        claim.existing = existing
        row_count = len(self.rows)
        try:
            yield claim
            if self.fail_commit:
                raise RuntimeError("database commit failed")
        except BaseException:
            del self.rows[row_count:]
            raise

    async def list_commits(self, project_id):
        return sorted({row.commit_sha for row in self.rows if row.project_id == project_id})

    async def list_for_project(self, project_id, limit=1_000, offset=0):
        return [row for row in self.rows if row.project_id == project_id][offset:offset + limit]

    async def list_for_source(self, project_id, commit_sha, source_path, limit=1_000, offset=0):
        rows = [row for row in self.rows if (
            row.project_id == project_id and row.commit_sha == commit_sha and row.source_path == source_path
        )]
        return rows[offset:offset + limit]

    async def list_for_line(self, project_id, commit_sha, source_path, line_number, limit=500, offset=0):
        rows = [row for row in self.rows if (
            row.project_id == project_id and row.commit_sha == commit_sha and row.source_path == source_path
            and row.line_number == line_number
        )]
        return rows[offset:offset + limit]


def _snapshot(source_path="src/a.c", line=1, testcase=b"seed", build_kind="clean", source_hash=None):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageLine, CoverageSnapshot

    return CoverageSnapshot(
        project_id=7, campaign_id=4, strategy_asset_id=33, commit_sha="a" * 40,
        clean_image_id="sha256:clean", clean_content_hash="c" * 64,
        clean_parent_image_id="sha256:parent", target_asset_id=31, configuration_asset_id=32,
        coverage_asset_id=34, replay_command=("/target", "{input}"), cpu_exposure_seconds=1.0,
        build_kind=build_kind, lines=(CoverageLine(source_path, line, "parse", source_hash),),
        hits=(CoverageHit(source_path, line, testcase, sha256(testcase).hexdigest()),),
    )


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

    with pytest.raises(ValueError, match="binary"):
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

    with pytest.raises(ValueError, match="shell"):
        DockerCoverageExecutor(client, timeout_seconds=30).run(
            "sha256:clean", ("/bin/sh", "-c", "id"), {}, tmp_path
        )


def test_fuzz_patch_paths_cannot_enter_reported_coverage(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    with pytest.raises(CoverageIntegrityError):
        run(TraceabilityService(
            tmp_path, _MemoryCoverageRepository(), lambda _request: True,
            _Registry(tmp_path / "repository"),
        ).record(_snapshot(line=12, build_kind="fuzz-target")))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("clean_image_id", None),
        ("clean_parent_image_id", None),
        ("replay_command", ("x" * 4097,)),
        ("cpu_exposure_seconds", float("nan")),
    ],
)
def test_traceability_rejects_malformed_snapshot_provenance(tmp_path: Path, field, value):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    original = _snapshot()
    snapshot = original.__class__(**{
        name: value if name == field else getattr(original, name)
        for name in original.__dataclass_fields__
    })

    with pytest.raises(CoverageIntegrityError):
        run(TraceabilityService(
            tmp_path, _MemoryCoverageRepository(), lambda _request: True,
            _Registry(tmp_path / "repository"),
        ).record(snapshot))


def test_first_testcase_is_stable_per_strategy_and_replayed_before_insert(tmp_path: Path):
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    (repository_root / "src/a.c").write_text("one\ntwo\nthree\n")
    repository = _MemoryCoverageRepository()
    observed = []

    def verifier(request):
        observed.append((request.testcase_path.read_bytes(), repository.create_count))
        return request.testcase_sha256 == sha256(b"first").hexdigest()

    service = TraceabilityService(tmp_path, repository, verifier, _Registry(repository_root))
    first_digest = sha256(b"first").hexdigest()
    first = _snapshot(line=2, testcase=b"first")
    later = _snapshot(line=2, testcase=b"later")

    created = run(service.record(first))
    ignored = run(service.record(later))

    assert observed == [(b"first", 0)]
    assert repository.create_count == 1
    assert ignored == []
    metadata = json.loads(next((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json")).read_text())
    assert metadata["testcase_sha256"] == first_digest
    assert metadata["source_path"] == "src/a.c"
    assert metadata["line_number"] == 2
    assert metadata["coverage_asset_id"] == 34


def test_failed_replay_never_commits_evidence(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    (repository_root / "src/a.c").write_text("x\n")
    repository = _MemoryCoverageRepository()

    with pytest.raises(CoverageIntegrityError, match="did not reproduce"):
        run(TraceabilityService(
            tmp_path, repository, lambda _request: False, _Registry(repository_root)
        ).record(_snapshot()))
    assert repository.create_count == 0
    assert list((tmp_path / "projects/7/coverage/first-hits").rglob("*.input")) == []


def test_strategy_directory_swap_during_replay_cannot_commit_or_delete_replacement(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    source = repository_root / "src/a.c"
    source.write_text("x\n")
    repository = _MemoryCoverageRepository()
    retired = tmp_path / "retired"

    def swap(request):
        strategy = request.testcase_path.parent
        strategy.chmod(0o700)
        strategy.rename(retired)
        strategy.mkdir()
        (strategy / "replacement").write_text("keep")
        return True

    with pytest.raises(CoverageIntegrityError, match="directory changed"):
        run(TraceabilityService(tmp_path, repository, swap, _Registry(repository_root)).record(
            _snapshot(source_hash=sha256(b"x\n").hexdigest())
        ))

    assert repository.create_count == 0
    replacement = next((tmp_path / "projects/7/coverage/first-hits").rglob("replacement"))
    assert replacement.read_text() == "keep"
    assert any(retired.glob("*.input"))


def test_record_rejects_source_hash_not_bound_to_checkout(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    (repository_root / "src/a.c").write_text("x\n")
    repository = _MemoryCoverageRepository()

    with pytest.raises(CoverageIntegrityError, match="source hash"):
        run(TraceabilityService(
            tmp_path, repository, lambda _request: True, _Registry(repository_root)
        ).record(_snapshot(source_hash="0" * 64)))
    assert repository.create_count == 0


@pytest.mark.parametrize("source_path", ["build/a.c", "generated/a.c", "harness/a.c", "fuzz-target/a.c"])
def test_traceability_independently_rejects_non_project_source_trees(tmp_path: Path, source_path: str):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    source = repository_root / source_path
    source.parent.mkdir(parents=True)
    source.write_text("x\n")
    repository = _MemoryCoverageRepository()

    with pytest.raises((CoverageIntegrityError, ValueError)):
        run(TraceabilityService(
            tmp_path, repository, lambda _request: True, _Registry(repository_root)
        ).record(_snapshot(source_path=source_path)))
    assert repository.create_count == 0


def test_source_query_rejects_checkout_bytes_that_differ_from_clean_image(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    source = checkout / "src/a.c"
    source.write_text("committed\n")
    repository = _MemoryCoverageRepository()
    service = TraceabilityService(tmp_path, repository, lambda _request: True, _Registry(checkout))
    run(service.record(_snapshot(source_hash=sha256(b"committed\n").hexdigest())))
    source.write_text("modified\n")

    with pytest.raises(CoverageIntegrityError, match="clean image"):
        run(service.source_file(7, "src/a.c", 1, 1))


def test_line_query_rejects_sidecar_identity_tampering(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src/a.c").write_text("x\n")
    repository = _MemoryCoverageRepository()
    service = TraceabilityService(tmp_path, repository, lambda _request: True, _Registry(checkout))
    run(service.record(_snapshot(source_hash=sha256(b"x\n").hexdigest())))
    metadata = next((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json"))
    directory = metadata.parent
    directory.chmod(0o700)
    metadata.chmod(0o600)
    document = json.loads(metadata.read_text())
    document["campaign_id"] = 999
    metadata.write_text(json.dumps(document))
    metadata.chmod(0o400)
    directory.chmod(0o500)

    with pytest.raises(CoverageIntegrityError, match="metadata identity"):
        run(service.line_evidence(7, "src/a.c", 1))


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


def test_llvm_cov_regions_span_lines_skip_gaps_and_use_region_file_ids(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src/a.c").write_text("\n" * 40)
    (repository / "src/b.c").write_text("\n" * 40)
    document = {"data": [{
        "files": [
            {"filename": "/src/src/a.c", "segments": [
                [10, 3, 1, True, True, False], [12, 1, 0, True, True, False],
                [30, 1, 1, True, True, True], [31, 1, 0, True, True, False],
            ]},
            {"filename": "/src/src/b.c", "segments": [
                [20, 1, 1, True, True, False], [20, 5, 0, True, True, False],
            ]},
        ],
        "functions": [{
            "name": "multi", "filenames": ["/src/src/a.c", "/src/src/b.c"],
            "regions": [
                [10, 3, 12, 1, 1, 0, 0, 0],
                [20, 1, 20, 5, 1, 1, 0, 0],
            ],
        }],
    }]}

    lines = LlvmCoverage(_client(), _CoverageExecutor({}), tmp_path / "work")._parse_export(
        json.dumps(document).encode(), _campaign(tmp_path)
    )

    assert [(line.source_path, line.line_number, line.function_name) for line in lines] == [
        ("src/a.c", 10, "multi"), ("src/a.c", 11, "multi"), ("src/b.c", 20, "multi"),
    ]


def test_replay_requires_exact_binary_argv_and_bounded_arguments(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    coverage = LlvmCoverage(_client(), _CoverageExecutor({}), tmp_path / "work")
    with pytest.raises(ValueError, match="binary"):
        coverage.replay(_campaign(tmp_path, replay_command=("/different", "{input}")), [])
    with pytest.raises(ValueError, match="argument"):
        coverage.replay(_campaign(tmp_path, replay_command=("/src/build/clean-target", "x" * 4097, "{input}")), [])


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return False


def test_repository_claim_holds_transaction_advisory_lock_and_inserts_first_winner():
    from unittest.mock import MagicMock

    from backend.repositories.coverage_repository import CoverageRepository

    row = {
        "id": 1, "project_id": 7, "commit_sha": "a" * 40, "source_path": "src/a.c",
        "line_number": 12, "function_name": "parse", "campaign_id": 4, "asset_id": 33,
        "first_testcase_sha256": "b" * 64, "cpu_exposure_seconds": 1.5,
    }
    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=_Transaction())
    connection.fetchrow.side_effect = [None, row]
    pool = SimpleNamespace(acquire=lambda: _Acquire(connection))

    async def exercise():
        async with CoverageRepository(pool).claim(
            project_id=7, commit_sha="a" * 40, source_path="src/a.c", line_number=12, asset_id=33,
        ) as claim:
            assert claim.existing is None
            return await claim.create(
                function_name="parse", campaign_id=4, first_testcase_sha256="b" * 64,
                cpu_exposure_seconds=1.5,
            )

    created = run(exercise())

    assert created.id == 1
    assert "pg_advisory_xact_lock" in connection.execute.await_args.args[0]
    assert "source_path = $3" in connection.fetchrow.await_args_list[0].args[0]
    assert "INSERT INTO coverage_evidence" in connection.fetchrow.await_args_list[1].args[0]


def test_same_testcase_reaching_multiple_files_publishes_distinct_logical_hits(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageLine
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src/a.c").write_text("a\n")
    (checkout / "src/b.c").write_text("b\n")
    testcase = b"shared"
    base = _snapshot()
    snapshot = base.__class__(
        **{field: getattr(base, field) for field in base.__dataclass_fields__ if field not in {"lines", "hits"}},
        lines=(
            CoverageLine("src/a.c", 1, "a", sha256(b"a\n").hexdigest()),
            CoverageLine("src/b.c", 1, "b", sha256(b"b\n").hexdigest()),
        ),
        hits=(
            CoverageHit("src/a.c", 1, testcase, sha256(testcase).hexdigest()),
            CoverageHit("src/b.c", 1, testcase, sha256(testcase).hexdigest()),
        ),
    )
    repository = _MemoryCoverageRepository()

    created = run(TraceabilityService(
        tmp_path, repository, lambda _request: True, _Registry(checkout)
    ).record(snapshot))

    artifacts = list((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json"))
    assert len(created) == 2
    assert len(artifacts) == 2
    assert {json.loads(path.read_text())["source_path"] for path in artifacts} == {"src/a.c", "src/b.c"}
    assert all(stat.S_IMODE(path.parent.stat().st_mode) == 0o500 for path in artifacts)


def test_database_failure_removes_only_current_logical_artifact(tmp_path: Path):
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src/a.c").write_text("x\n")
    repository = _MemoryCoverageRepository()
    repository.fail_create = True

    with pytest.raises(RuntimeError, match="database failed"):
        run(TraceabilityService(
            tmp_path, repository, lambda _request: True, _Registry(checkout)
        ).record(_snapshot(source_hash=sha256(b"x\n").hexdigest())))

    assert list((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json")) == []


def test_database_commit_failure_removes_uncommitted_logical_artifact(tmp_path: Path):
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src/a.c").write_text("x\n")
    repository = _MemoryCoverageRepository()
    repository.fail_commit = True

    with pytest.raises(RuntimeError, match="database commit failed"):
        run(TraceabilityService(
            tmp_path, repository, lambda _request: True, _Registry(checkout)
        ).record(_snapshot(source_hash=sha256(b"x\n").hexdigest())))

    assert repository.rows == []
    assert list((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json")) == []


def test_checkout_drift_after_async_replay_rolls_back_artifact(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src/a.c").write_text("x\n")
    registry = _Registry(checkout)

    async def verifier(request):
        assert request.clean_image_id == "sha256:clean"
        assert request.clean_content_hash == "c" * 64
        assert request.clean_parent_image_id == "sha256:parent"
        assert (request.target_asset_id, request.configuration_asset_id, request.coverage_asset_id) == (31, 32, 34)
        await asyncio.sleep(0)
        registry.valid = False
        return True

    with pytest.raises(CoverageIntegrityError, match="drift"):
        run(TraceabilityService(
            tmp_path, _MemoryCoverageRepository(), verifier, registry
        ).record(_snapshot(source_hash=sha256(b"x\n").hexdigest())))

    assert list((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json")) == []


def test_replay_rejects_mutated_input_and_unexpected_profile_output(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError, LlvmCoverage

    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src/a.c").write_text("x\n")
    seed = tmp_path / "seed"
    seed.write_bytes(b"seed")

    class MutatingExecutor(_CoverageExecutor):
        def run(self, image_id, command, environment, profile_directory, input_file=None):
            result = super().run(image_id, command, environment, profile_directory, input_file)
            if input_file is not None:
                input_file.chmod(0o600)
                input_file.write_bytes(b"changed")
            return result

    with pytest.raises(CoverageIntegrityError, match="input changed"):
        LlvmCoverage(_client(), MutatingExecutor({}), tmp_path / "work").replay(_campaign(tmp_path), [seed])

    class ExtraOutputExecutor(_CoverageExecutor):
        def run(self, image_id, command, environment, profile_directory, input_file=None):
            result = super().run(image_id, command, environment, profile_directory, input_file)
            if environment:
                (profile_directory / "unexpected").write_bytes(b"x")
            return result

    seed.write_bytes(b"seed")
    with pytest.raises(CoverageIntegrityError, match="unexpected"):
        LlvmCoverage(_client(), ExtraOutputExecutor({}), tmp_path / "work2").replay(_campaign(tmp_path), [seed])

    class ReplacingProfileExecutor(_CoverageExecutor):
        def run(self, image_id, command, environment, profile_directory, input_file=None):
            result = super().run(image_id, command, environment, profile_directory, input_file)
            if command[0] == "llvm-profdata-18":
                raw = next(profile_directory.glob("*.profraw"))
                raw.write_bytes(b"replaced")
            return result

    seed.write_bytes(b"seed")
    with pytest.raises(CoverageIntegrityError, match="profile changed"):
        LlvmCoverage(_client(), ReplacingProfileExecutor({}), tmp_path / "work3").replay(_campaign(tmp_path), [seed])


def test_mixed_project_commits_fail_before_bounded_tree_query(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository = _MemoryCoverageRepository()

    async def commits(_project_id):
        return ["a" * 40, "b" * 40]

    repository.list_commits = commits
    with pytest.raises(CoverageIntegrityError, match="multiple commits"):
        run(TraceabilityService(
            tmp_path, repository, lambda _request: True, _Registry(tmp_path)
        ).project_tree(7, limit=10, offset=0))
