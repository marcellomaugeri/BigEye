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


CLEAN_IMAGE_ID = "sha256:" + "c" * 64
PARENT_IMAGE_ID = "sha256:" + "d" * 64


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
        "clean_build_configuration_asset_id": 32,
        "strategy_asset_id": 33,
        "coverage_asset_id": 34,
        "cpu_exposure_seconds": 8.5,
        "repository_root": tmp_path / "repository",
        "source_root": "/src",
        "clean_image_id": CLEAN_IMAGE_ID,
        "clean_content_hash": "c" * 64,
        "clean_parent_image_id": PARENT_IMAGE_ID,
    }
    return SimpleNamespace(**(values | changes))


def _client():
    return SimpleNamespace(api=SimpleNamespace(inspect_image=lambda _image: {
        "Id": CLEAN_IMAGE_ID,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"Labels": {
            "bigeye.project": "7", "bigeye.commit": "a" * 40, "bigeye.layer": "coverage",
            "bigeye.content-hash": "c" * 64, "bigeye.parent-image": PARENT_IMAGE_ID,
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

    async def aggregate_project(self, project_id, commit_sha, limit=1_000, offset=0):
        grouped = {}
        for row in self.rows:
            if row.project_id == project_id and row.commit_sha == commit_sha:
                group = grouped.setdefault(row.source_path, {"lines": set(), "cpu": 0.0})
                group["lines"].add(row.line_number)
                group["cpu"] += row.cpu_exposure_seconds
        items = tuple({
            "path": path,
            "covered_lines": len(grouped[path]["lines"]),
            "cpu_exposure_seconds": grouped[path]["cpu"],
        } for path in sorted(grouped))
        return SimpleNamespace(items=items[offset:offset + limit], total=len(items))

    async def list_for_source(self, project_id, commit_sha, source_path, limit=1_000, offset=0):
        rows = [row for row in self.rows if (
            row.project_id == project_id and row.commit_sha == commit_sha and row.source_path == source_path
        )]
        return rows[offset:offset + limit]

    async def first_for_source(self, project_id, commit_sha, source_path):
        rows = await self.list_for_source(project_id, commit_sha, source_path)
        return rows[0] if rows else None

    async def aggregate_source_range(self, project_id, commit_sha, source_path, start_line, end_line):
        grouped = {}
        for row in await self.list_for_source(project_id, commit_sha, source_path):
            if start_line <= row.line_number <= end_line:
                group = grouped.setdefault(row.line_number, {"assets": set(), "cpu": 0.0})
                group["assets"].add(row.asset_id)
                group["cpu"] += row.cpu_exposure_seconds
        return tuple({
            "line_number": line,
            "strategy_count": len(grouped[line]["assets"]),
            "cpu_exposure_seconds": grouped[line]["cpu"],
        } for line in sorted(grouped))

    async def aggregate_functions(self, project_id, commit_sha, source_path, limit=1_000, offset=0):
        grouped = {}
        for row in await self.list_for_source(project_id, commit_sha, source_path):
            if row.function_name:
                group = grouped.setdefault(row.function_name, {"lines": set(), "cpu": 0.0})
                group["lines"].add(row.line_number)
                group["cpu"] += row.cpu_exposure_seconds
        items = tuple({
            "name": name,
            "path": source_path,
            "covered_lines": len(grouped[name]["lines"]),
            "cpu_exposure_seconds": grouped[name]["cpu"],
        } for name in sorted(grouped))
        return SimpleNamespace(items=items[offset:offset + limit], total=len(items))

    async def list_for_line(self, project_id, commit_sha, source_path, line_number, limit=500, offset=0):
        rows = [row for row in self.rows if (
            row.project_id == project_id and row.commit_sha == commit_sha and row.source_path == source_path
            and row.line_number == line_number
        )]
        return rows[offset:offset + limit]

    async def page_for_line(self, project_id, commit_sha, source_path, line_number, limit=500, offset=0):
        rows = [row for row in self.rows if (
            row.project_id == project_id and row.commit_sha == commit_sha and row.source_path == source_path
            and row.line_number == line_number
        )]
        return SimpleNamespace(items=tuple(rows[offset:offset + limit]), total=len(rows))


def _snapshot(
    source_path="src/a.c", line=1, testcase=b"seed", build_kind="clean", source_hash=None,
    replay_environment=(),
):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageLine, CoverageSnapshot

    return CoverageSnapshot(
        project_id=7, campaign_id=4, strategy_asset_id=33, commit_sha="a" * 40,
        clean_image_id=CLEAN_IMAGE_ID, clean_content_hash="c" * 64,
        clean_parent_image_id=PARENT_IMAGE_ID, target_asset_id=31, configuration_asset_id=32,
        coverage_asset_id=34, replay_command=("/target", "{input}"), cpu_exposure_seconds=1.0,
        build_kind=build_kind, lines=(CoverageLine(source_path, line, "parse", source_hash),),
        hits=(CoverageHit(source_path, line, testcase, sha256(testcase).hexdigest()),),
        replay_environment=replay_environment,
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
        CLEAN_IMAGE_ID, ("llvm-cov-18", "export"), {}, tmp_path
    )

    assert result == b"result"
    assert container.started is True
    assert container.removed is True
    assert created["platform"] == "linux/amd64"
    assert created["network_mode"] == "none"
    assert created["read_only"] is True
    assert created["cap_drop"] == ["ALL"]
    assert created["user"] == f"{__import__('os').getuid()}:{__import__('os').getgid()}"
    assert created["detach"] is True

    with pytest.raises(ValueError, match="shell"):
        DockerCoverageExecutor(client, timeout_seconds=30).run(
            CLEAN_IMAGE_ID, ("/bin/sh", "-c", "id"), {}, tmp_path
        )


def test_docker_executor_reports_only_bounded_classified_stderr_on_failure(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import (
        CoverageIntegrityError,
        DockerCoverageExecutor,
    )

    class Container:
        def __init__(self):
            self.removed = False

        def start(self): pass
        def wait(self, timeout): return {"StatusCode": 1}

        def logs(self, **kwargs):
            assert kwargs == {
                "stdout": False, "stderr": True, "stream": True, "follow": False,
            }
            yield (
                b"ERROR: LeakSanitizer: fatal\n"
                b"Failed spawning a tracer thread (errno 22)\n"
                b"OPENAI_API_KEY=must-not-be-reported\n"
                + b"x" * 100_000
            )
            raise AssertionError("stderr collection must stop at its byte bound")

        def remove(self, force):
            self.removed = force

    container = Container()
    client = SimpleNamespace(
        containers=SimpleNamespace(create=lambda *_args, **_kwargs: container),
    )

    with pytest.raises(CoverageIntegrityError) as failure:
        DockerCoverageExecutor(client, timeout_seconds=30).run(
            CLEAN_IMAGE_ID, ("/opt/bigeye/build/target", "/coverage/input"), {}, tmp_path,
        )

    diagnostic = str(failure.value)
    assert "exit 1" in diagnostic
    assert "LeakSanitizer" in diagnostic
    assert "tracer thread" in diagnostic
    assert "OPENAI_API_KEY" not in diagnostic
    assert "must-not-be-reported" not in diagnostic
    assert len(diagnostic) < 300
    assert container.removed is True


def test_docker_coverage_executor_feeds_exact_stdin_without_mounting_input(tmp_path: Path):
    import socket

    from backend.fuzzing.coverage.llvm_coverage import DockerCoverageExecutor

    class AttachedSocket:
        def __init__(self):
            self._sock = self
            self.sent = bytearray()
            self.closed = False
            self.events = []
            self._response = SimpleNamespace(close=self._close_response)
        def sendall(self, value): self.sent.extend(value)
        def shutdown(self, value): self.shutdown_mode = value
        def _close_response(self): self.events.append("response")
        def close(self): self.events.append("socket"); self.closed = True

    class Container:
        def __init__(self): self.socket = AttachedSocket()
        def attach_socket(self, params): return self.socket
        def start(self): pass
        def wait(self, timeout): return {"StatusCode": 0}
        def logs(self, **kwargs): return []
        def remove(self, force): pass

    container = Container()
    class Containers:
        def create(self, *args, **kwargs): self.command = args[1]; self.kwargs = kwargs; return container

    containers = Containers()
    result = DockerCoverageExecutor(
        SimpleNamespace(containers=containers), timeout_seconds=30,
    ).run(
        CLEAN_IMAGE_ID, ("/opt/bigeye/stdin-parser", "--mode", "plain"), {}, tmp_path,
        stdin_bytes=b"\x00coverage\xff",
    )

    assert result == b""
    assert containers.command == ["/opt/bigeye/stdin-parser", "--mode", "plain"]
    assert containers.kwargs["volumes"] == {
        str(tmp_path.resolve()): {"bind": "/coverage/profiles", "mode": "rw"},
    }
    assert containers.kwargs["stdin_open"] is True
    assert containers.kwargs["detach"] is False
    assert bytes(container.socket.sent) == b"\x00coverage\xff"
    assert container.socket.shutdown_mode == socket.SHUT_WR
    assert container.socket.closed is True
    assert container.socket.events == ["response", "socket"]


def test_docker_coverage_executor_removes_container_when_stdin_attach_fails(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import DockerCoverageExecutor

    removed = []

    class Container:
        def attach_socket(self, params): raise RuntimeError("attach failed")
        def remove(self, force): removed.append(force)

    class Containers:
        def create(self, *args, **kwargs): return Container()

    with pytest.raises(RuntimeError, match="attach failed"):
        DockerCoverageExecutor(
            SimpleNamespace(containers=Containers()), timeout_seconds=30,
        ).run(
            CLEAN_IMAGE_ID, ("/opt/bigeye/stdin-parser",), {}, tmp_path,
            stdin_bytes=b"exact",
        )

    assert removed == [True]


def test_llvm_coverage_stdin_replay_strips_marker_and_preserves_input_identity(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src/a.c").write_bytes(b"int parse(void) { return 1; }\n")
    seed = tmp_path / "seed"
    seed.write_bytes(b"\x00stdin-seed\xff")

    class Executor(_CoverageExecutor):
        def run(self, image_id, command, environment, profile_directory, input_file=None, stdin_bytes=None):
            self.stdin_calls = getattr(self, "stdin_calls", [])
            if "LLVM_PROFILE_FILE" in environment:
                self.stdin_calls.append((command, input_file, stdin_bytes))
            return super().run(image_id, command, environment, profile_directory, input_file)

    executor = Executor(
        {"input-000000": _export(), "merged": _export()},
        {"/src/src/a.c": b"int parse(void) { return 1; }\n"},
    )
    snapshot = LlvmCoverage(_client(), executor, tmp_path / "work").replay(
        _campaign(tmp_path, replay_command=("/src/build/clean-target", "--plain", "{stdin}")),
        (seed,),
    )

    assert executor.stdin_calls == [
        (("/src/build/clean-target", "--plain"), None, b"\x00stdin-seed\xff"),
    ]
    assert snapshot.replay_command == ("/src/build/clean-target", "--plain", "{stdin}")
    assert snapshot.hits[0].testcase == b"\x00stdin-seed\xff"


@pytest.mark.parametrize(
    "replay_command",
    [
        ("/src/build/clean-target", "{stdin}", "{stdin}"),
        ("/src/build/clean-target", "{input}", "{stdin}"),
        ("/src/build/clean-target", "{input}", "--mode={stdin}"),
        ("/src/build/clean-target", "--file={input}", "{stdin}"),
        ("/src/build/clean-target", "plain"),
    ],
)
def test_llvm_coverage_rejects_invalid_input_marker_contract(tmp_path: Path, replay_command) -> None:
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    with pytest.raises(ValueError, match="input marker"):
        LlvmCoverage(_client(), _CoverageExecutor({}), tmp_path / "work").replay(
            _campaign(tmp_path, replay_command=replay_command), (),
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
    first = _snapshot(
        line=2, testcase=b"first", replay_environment=(("BIGEYE_MODE", "encrypted"),),
    )
    later = _snapshot(line=2, testcase=b"later")

    created = run(service.record(first))
    ignored = run(service.record(later))

    assert observed == [(b"first", 0)]
    assert repository.create_count == 1
    assert created[0].cpu_exposure_seconds == 0.0
    assert ignored == []
    metadata = json.loads(next((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json")).read_text())
    assert metadata["testcase_sha256"] == first_digest
    assert metadata["source_path"] == "src/a.c"
    assert metadata["line_number"] == 2
    assert metadata["coverage_asset_id"] == 34
    assert metadata["replay_environment"] == [["BIGEYE_MODE", "encrypted"]]

    line = run(service.line_evidence(7, "src/a.c", 2))["evidence"][0]
    assert line["replay_environment"] == {"BIGEYE_MODE": "encrypted"}


@pytest.mark.parametrize("replay_environment", [
    (("BIGEYE_MODE", "x" * 4097),),
    tuple((f"MODE_{index}", "enabled") for index in range(33)),
    (("OPENAI_API_KEY", "must-not-be-persisted"),),
])
def test_traceability_rejects_unbounded_or_secret_replay_environment(
    tmp_path: Path, replay_environment,
):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src/a.c").write_text("x\n")

    with pytest.raises(CoverageIntegrityError, match="replay environment"):
        run(TraceabilityService(
            tmp_path, _MemoryCoverageRepository(), lambda _request: True, _Registry(checkout),
        ).record(_snapshot(
            source_hash=sha256(b"x\n").hexdigest(),
            replay_environment=replay_environment,
        )))

    assert list((tmp_path / "projects/7/coverage/first-hits").rglob("evidence.json")) == []


@pytest.mark.parametrize("replay_environment", [
    (("GITHUB_PAT", "github-secret"),),
    (("AWS_ACCESS_KEY_ID", "aws-secret"),),
    (("SERVICE_TOKEN", "service-secret"),),
    (("SERVICE_SECRET", "service-secret"),),
    (("SERVICE_PASSWORD", "service-secret"),),
    (("SERVICE_KEY", "service-secret"),),
    (("DATABASE_URL", "postgresql://user:password@db/bigeye"),),
    (("AUTHENTICATION", "Bearer bearer-secret"),),
    (("SIGNING_MATERIAL", "-----BEGIN PRIVATE KEY-----\nprivate-secret"),),
    (("REMOTE_ENDPOINT", "https://user:password@example.test/path"),),
    (("DATABASE_URL", "postgresql://db/bigeye?user=admin&password=secret"),),
    (("REMOTE_ENDPOINT", "https://example.test/?payload=Bearer%20must-not-persist"),),
    (("REMOTE_ENDPOINT", "https://example.test/?payload=bAsIc%20dXNlcjpwYXNz"),),
    ((
        "REMOTE_ENDPOINT",
        "https://example.test/?next=https%3A%2F%2Fuser%3Apass%40internal.test%2F",
    ),),
    (("REMOTE_ENDPOINT", "https://example.test/?%70assword="),),
])
def test_clean_coverage_contract_rejects_credential_shaped_replay_environment(
    replay_environment,
) -> None:
    from backend.fuzzing.campaigns.coverage_contract import valid_replay_environment

    assert valid_replay_environment(replay_environment) is False


def test_clean_coverage_contract_preserves_benign_replay_configuration() -> None:
    from backend.fuzzing.campaigns.coverage_contract import valid_replay_environment

    assert valid_replay_environment((
        ("BIGEYE_MODE", "encrypted"),
        ("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=1"),
        ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
        ("DATABASE_URL", "postgresql://db/bigeye"),
        ("REMOTE_ENDPOINT", "https://example.test/path?user=reader&mode=encrypted&ssl=true"),
        (
            "DOCUMENTATION_URL",
            "https://example.test/?mode=basic&description=basic%20fuzzing&next="
            "https%3A%2F%2Fdocs.example.test%2Fguide%3Fmode%3Dencrypted",
        ),
    )) is True


def test_clean_coverage_contract_scans_past_64_benign_query_fields() -> None:
    from backend.fuzzing.campaigns.coverage_contract import valid_replay_environment

    benign = "&".join(f"flag{index}=on" for index in range(65))
    late_secret = benign + "&payload=Basic%20dXNlcjpwYXNz"

    assert valid_replay_environment((
        ("REMOTE_ENDPOINT", f"https://example.test/?{benign}"),
    )) is True
    assert valid_replay_environment((
        ("REMOTE_ENDPOINT", f"https://example.test/?{late_secret}"),
    )) is False


def test_new_first_hit_invalidates_coverage_only_after_durable_publication(tmp_path: Path):
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository_root = tmp_path / "repository"
    (repository_root / "src").mkdir(parents=True)
    (repository_root / "src/a.c").write_text("x\n")
    repository = _MemoryCoverageRepository()
    events = AsyncMock()
    service = TraceabilityService(
        tmp_path, repository, lambda _request: True, _Registry(repository_root), events=events,
    )

    created = run(service.record(_snapshot(source_hash=sha256(b"x\n").hexdigest())))
    ignored = run(service.record(_snapshot(source_hash=sha256(b"x\n").hexdigest())))

    assert len(created) == 1
    assert ignored == []
    events.append.assert_awaited_once_with(7, "events", {"name": "coverage"})


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


@pytest.mark.parametrize("source_path", [
    "build/a.c",
    "generated/a.c",
    "harness/a.c",
    "fuzz-target/a.c",
    "src/.GiT/config.c",
    "src/.BigEye/generated.c",
    "src/Generated/a.c",
    "src/BUILD/a.c",
    "src/Harnesses/a.c",
    "src/FuZz/a.c",
    "src/fuzzer/a.c",
    "src/FUZZERS/a.c",
    "src/Fuzz_Target/a.c",
    "src/cmake-build-debug/a.c",
])
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


@pytest.mark.parametrize("source_path", [
    "src/.GiT/config.c",
    "src/.BigEye/generated.c",
    "src/Generated/a.c",
    "src/BUILD/a.c",
    "src/Harnesses/a.c",
    "src/FuZz/a.c",
    "src/fuzzer/a.c",
    "src/FUZZERS/a.c",
    "src/Fuzz-Target/a.c",
    "src/cmake-build-debug/a.c",
])
def test_clean_export_rejects_forbidden_segments_at_any_depth_case_insensitively(
    tmp_path: Path, source_path: str,
):
    from backend.fuzzing.coverage.llvm_coverage import LlvmCoverage

    repository = tmp_path / "repository"
    source = repository / source_path
    source.parent.mkdir(parents=True)
    source.write_text("int hidden(void) { return 0; }\n")

    assert LlvmCoverage._source_path(f"/src/{source_path}", _campaign(tmp_path)) is None


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


def test_line_query_rejects_invalid_persisted_replay_environment(tmp_path: Path):
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
    document["replay_environment"] = [["OPENAI_API_KEY", "must-not-be-exposed"]]
    metadata.write_text(json.dumps(document))
    metadata.chmod(0o400)
    directory.chmod(0o500)

    with pytest.raises(CoverageIntegrityError, match="metadata is invalid"):
        run(service.line_evidence(7, "src/a.c", 1))


def test_line_query_treats_missing_legacy_replay_environment_as_empty(tmp_path: Path):
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
    del document["replay_environment"]
    metadata.write_text(json.dumps(document))
    metadata.chmod(0o400)
    directory.chmod(0o500)

    line = run(service.line_evidence(7, "src/a.c", 1))["evidence"][0]

    assert line["replay_environment"] == {}


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


def test_release_schema_guarantees_one_coverage_hit_per_project_source_line_and_asset():
    from pathlib import Path

    schema = (Path(__file__).parents[1] / "database" / "schema.sql").read_text()

    assert "UNIQUE (project_id, commit_sha, source_path, line_number, asset_id)" in schema


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
    assert "ON CONFLICT (project_id, commit_sha, source_path, line_number, asset_id) DO NOTHING" in (
        connection.fetchrow.await_args_list[1].args[0]
    )


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
        assert request.clean_image_id == CLEAN_IMAGE_ID
        assert request.clean_content_hash == "c" * 64
        assert request.clean_parent_image_id == PARENT_IMAGE_ID
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


def test_project_tree_returns_truthful_empty_coverage_for_committed_project(tmp_path: Path):
    from backend.fuzzing.coverage.traceability import TraceabilityService

    repository = _MemoryCoverageRepository()
    checkout = tmp_path / "repository"
    checkout.mkdir()

    class Registry(_Registry):
        async def commit_for_project(self, project_id):
            assert project_id == 7
            return "a" * 40

    result = run(TraceabilityService(
        tmp_path, repository, lambda _request: True, Registry(checkout),
    ).project_tree(7, limit=10, offset=0))

    assert result == {
        "project_id": 7,
        "commit_sha": "a" * 40,
        "files": [],
        "pagination": {"limit": 10, "offset": 0, "total": 0},
    }


def test_llvm_segments_reject_attacker_span_before_range_expansion(tmp_path: Path, monkeypatch):
    import builtins

    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError, LlvmCoverage

    original_range = range

    def guarded_range(start, stop=None, step=1):
        actual_start, actual_stop = (0, start) if stop is None else (start, stop)
        if actual_stop - actual_start > 2_000_000:
            raise AssertionError("attacker-controlled range was expanded before validation")
        return original_range(start, stop, step) if stop is not None else original_range(start)

    monkeypatch.setattr(builtins, "range", guarded_range)
    with pytest.raises(CoverageIntegrityError, match="segment|span"):
        LlvmCoverage(_client(), _CoverageExecutor({}), tmp_path / "work")._segment_lines([
            [1, 1, 1, True, True, False],
            [10**12, 2, 0, True, True, False],
        ])


def test_checkout_registry_rejects_symbolic_branch_even_at_exact_commit(tmp_path: Path, monkeypatch):
    from backend.fuzzing.coverage import traceability
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError

    checkout = tmp_path / "projects/7/repository"
    checkout.mkdir(parents=True)
    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    projects = SimpleNamespace(get=AsyncMock(return_value=project))

    async def command(argv, cwd=None):
        del cwd
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return project.commit_sha
        if argv[1:4] == ["symbolic-ref", "-q", "HEAD"]:
            return "refs/heads/main"
        raise AssertionError(argv)

    monkeypatch.setattr(traceability, "run_command", command)
    with pytest.raises(CoverageIntegrityError, match="detached"):
        run(traceability.ProjectCheckoutRegistry(tmp_path, projects).resolve(7, project.commit_sha))


def test_first_hit_replay_verifier_requires_exact_clean_replay_identity(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageHit, CoverageLine
    from backend.fuzzing.coverage.replay_verifier import FirstHitReplayVerifier
    from backend.fuzzing.coverage.traceability import ReplayVerification

    testcase = tmp_path / "seed"
    testcase.write_bytes(b"seed")
    request = ReplayVerification(
        7, "a" * 40, 4, 33, 31, 32, 34,
        CLEAN_IMAGE_ID, "c" * 64, PARENT_IMAGE_ID,
        "src/a.c", 12, testcase, sha256(b"seed").hexdigest(),
        ("/src/build/clean-target", "{input}"),
        (("BIGEYE_MODE", "encrypted"),),
    )
    target = _campaign(tmp_path)

    class Resolver:
        async def resolve(self, selected):
            assert selected == request
            return target

    class Replay:
        async def replay(self, selected, inputs):
            assert selected is target
            assert inputs == (testcase,)
            snapshot = _snapshot(line=12, testcase=b"seed", source_hash=sha256(b"x\n").hexdigest())
            return snapshot.__class__(
                **{
                    name: getattr(snapshot, name)
                    for name in snapshot.__dataclass_fields__
                    if name not in {"replay_command", "replay_environment", "lines", "hits"}
                },
                replay_command=("/src/build/clean-target", "{input}"),
                lines=(CoverageLine("src/a.c", 12, "parse", sha256(b"x\n").hexdigest()),),
                hits=(CoverageHit("src/a.c", 12, b"seed", sha256(b"seed").hexdigest()),),
                replay_environment=(("BIGEYE_MODE", "encrypted"),),
            )

    assert run(FirstHitReplayVerifier(Resolver(), Replay())(request)) is True


def test_first_hit_replay_verifier_rejects_changed_replay_environment(tmp_path: Path):
    from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
    from backend.fuzzing.coverage.replay_verifier import FirstHitReplayVerifier
    from backend.fuzzing.coverage.traceability import ReplayVerification

    testcase = tmp_path / "seed"
    testcase.write_bytes(b"seed")
    request = ReplayVerification(
        7, "a" * 40, 4, 33, 31, 32, 34,
        CLEAN_IMAGE_ID, "c" * 64, PARENT_IMAGE_ID,
        "src/a.c", 12, testcase, sha256(b"seed").hexdigest(),
        ("/src/build/clean-target", "{input}"),
        (("BIGEYE_MODE", "encrypted"),),
    )

    class Resolver:
        async def resolve(self, _request):
            return _campaign(tmp_path, replay_environment=request.replay_environment)

    class Replay:
        async def replay(self, _target, _inputs):
            snapshot = _snapshot(
                line=12, testcase=b"seed", source_hash=sha256(b"x\n").hexdigest(),
                replay_environment=(("BIGEYE_MODE", "plain"),),
            )
            return snapshot.__class__(**{
                name: (
                    ("/src/build/clean-target", "{input}")
                    if name == "replay_command"
                    else getattr(snapshot, name)
                )
                for name in snapshot.__dataclass_fields__
            })

    with pytest.raises(CoverageIntegrityError, match="immutable coverage identity"):
        run(FirstHitReplayVerifier(Resolver(), Replay())(request))


def test_repository_conflict_returns_existing_first_winner():
    from unittest.mock import MagicMock

    from backend.repositories.coverage_repository import CoverageRepository

    winner = {
        "id": 9, "project_id": 7, "commit_sha": "a" * 40, "source_path": "src/a.c",
        "line_number": 12, "function_name": "parse", "campaign_id": 4, "asset_id": 33,
        "first_testcase_sha256": "c" * 64, "cpu_exposure_seconds": 2.0,
    }
    connection = AsyncMock()
    connection.transaction = MagicMock(return_value=_Transaction())
    connection.fetchrow.side_effect = [None, None, winner]
    pool = SimpleNamespace(acquire=lambda: _Acquire(connection))

    async def exercise():
        async with CoverageRepository(pool).claim(
            project_id=7, commit_sha="a" * 40, source_path="src/a.c", line_number=12, asset_id=33,
        ) as claim:
            evidence = await claim.create(
                function_name="parse", campaign_id=4, first_testcase_sha256="b" * 64,
                cpu_exposure_seconds=1.0,
            )
            return claim.created, evidence

    inserted, evidence = run(exercise())

    assert inserted is False
    assert evidence.id == 9
    assert evidence.first_testcase_sha256 == "c" * 64


def test_repository_aggregates_before_pagination_and_filters_source_range():
    from backend.repositories.coverage_repository import CoverageRepository

    pool = AsyncMock()
    pool.fetch.side_effect = [
        [{"source_path": "src/a.c", "covered_lines": 8, "cpu_exposure_seconds": 12.0, "total": 3}],
        [{"line_number": 12, "strategy_count": 2, "cpu_exposure_seconds": 4.0}],
    ]
    repository = CoverageRepository(pool)

    page = run(repository.aggregate_project(7, "a" * 40, limit=1, offset=1))
    lines = run(repository.aggregate_source_range(7, "a" * 40, "src/a.c", 10, 20))

    aggregate_sql = pool.fetch.await_args_list[0].args[0]
    source_sql = pool.fetch.await_args_list[1].args[0]
    assert "GROUP BY source_path" in aggregate_sql
    assert aggregate_sql.index("GROUP BY source_path") < aggregate_sql.index("LIMIT $3")
    assert page.total == 3
    assert page.items[0]["covered_lines"] == 8
    assert "line_number BETWEEN $4 AND $5" in source_sql
    assert pool.fetch.await_args_list[1].args[-2:] == (10, 20)
    assert lines[0]["strategy_count"] == 2


def test_production_first_hit_record_replays_through_bounded_docker_executor(tmp_path: Path):
    from backend.fuzzing.coverage.replay_verifier import (
        CleanCoverageTargetResolver,
        DeferredLlvmCoverage,
        FirstHitReplayVerifier,
    )
    from backend.fuzzing.coverage.traceability import TraceabilityService

    checkout = tmp_path / "repository"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src/a.c").write_text("x\n")

    class Container:
        def __init__(self, command, options):
            self.command = command
            self.options = options
            self.removed = False

        def start(self):
            profiles = next(
                Path(host) for host, mount in self.options["volumes"].items()
                if mount["bind"] == "/coverage/profiles"
            )
            environment = self.options["environment"]
            if "LLVM_PROFILE_FILE" in environment:
                name = Path(environment["LLVM_PROFILE_FILE"].replace("%p", "123")).name
                (profiles / name).write_bytes(b"raw")
            elif self.command[0] == "llvm-profdata-18":
                name = Path(self.command[self.command.index("-o") + 1]).name
                (profiles / name).write_bytes(b"profile")

        def wait(self, timeout):
            assert timeout == 120
            return {"StatusCode": 0}

        def logs(self, **_options):
            if self.command[0] == "llvm-cov-18":
                return [json.dumps(_export(line=1)).encode()]
            if self.command[0] == "cat":
                return [b"x\n"]
            return []

        def remove(self, force):
            assert force is True
            self.removed = True

    class Client:
        def __init__(self):
            self.calls = []
            self.closed = False
            self.api = SimpleNamespace(inspect_image=lambda _image: _client().api.inspect_image(_image))
            self.containers = SimpleNamespace(create=self.create)

        def create(self, image, command, **options):
            assert image == CLEAN_IMAGE_ID
            self.calls.append((tuple(command), options))
            return Container(command, options)

        def close(self):
            self.closed = True

    client = Client()
    docker_client = SimpleNamespace(connect=lambda: client)
    registry = _Registry(checkout)
    campaign = SimpleNamespace(
        id=4, project_id=7, target_asset_id=31, configuration_asset_id=32,
    )
    campaigns = SimpleNamespace(get=AsyncMock(return_value=campaign))
    assets = SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(
        id=32, project_id=7, kind="script", parent_id=None,
        validated_at=object(), error=None,
    )))
    verifier = FirstHitReplayVerifier(
        CleanCoverageTargetResolver(registry, campaigns, assets),
        DeferredLlvmCoverage(tmp_path / "replay", docker_client=docker_client),
    )
    service = TraceabilityService(tmp_path, _MemoryCoverageRepository(), verifier, registry)

    created = run(service.record(_snapshot(
        source_hash=sha256(b"x\n").hexdigest(),
        replay_environment=(("BIGEYE_MODE", "encrypted"),),
    )))

    assert len(created) == 1
    assert client.closed is True
    assert len(client.calls) >= 6
    assert all(call[1]["network_mode"] == "none" and call[1]["read_only"] is True for call in client.calls)
    assert any(
        mount["bind"] == "/coverage/input" and mount["mode"] == "ro"
        for _command, options in client.calls for mount in options["volumes"].values()
    )
    assert any(
        options["environment"].get("BIGEYE_MODE") == "encrypted"
        and "LLVM_PROFILE_FILE" in options["environment"]
        for command, options in client.calls
        if command[0] == "/target"
    )
