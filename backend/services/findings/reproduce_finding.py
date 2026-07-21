"""Exact, read-only execution of one verified frozen finding bundle."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import inspect
import json
from pathlib import Path
import re
from types import MappingProxyType

from backend.fuzzing.docker.container_runner import ContainerRunner, ContainerTimedOut
from backend.fuzzing.docker.image_inspector import ImageInspector
from backend.fuzzing.docker.stdin import MAX_STDIN_BYTES


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_TESTCASE = "/finding/input"


class FindingNotFound(LookupError):
    """The requested finding is absent or belongs to another project."""


class FindingNotReproducible(RuntimeError):
    """No complete verified frozen reproduction bundle is available."""


@dataclass(frozen=True)
class PreparedReproduction:
    project_id: int
    finding_id: int
    image_id: str
    command: tuple[str, ...]
    environment: MappingProxyType
    testcase: Path
    stdin_bytes: bytes | None = None
    run_id: str | None = None
    expected_sanitizer: str | None = None
    expected_function: str | None = None
    expected_source_location: str | None = None
    bundle_id: str | None = None
    testcase_sha256: str | None = None


@dataclass(frozen=True)
class ReproductionOutcome:
    exit_code: int | None
    terminal_reason: str
    timed_out: bool = False
    sanitizer_crash_observed: bool = False


class FindingReproductionService:
    """Resolve exact bundle inputs and execute them in an ephemeral container."""

    def __init__(
        self, workspace: Path, findings, bundles, docker, *, finding_artifacts=None,
        timeout: float = 30.0,
    ):
        self._workspace = Path(workspace).resolve(strict=True)
        self._findings = findings
        self._bundles = bundles
        self._docker = docker
        self._finding_artifacts = finding_artifacts
        self._timeout = timeout

    async def prepare(self, project_id: int, finding_id: int) -> PreparedReproduction:
        finding = await self._findings.get(finding_id)
        if finding is None or finding.project_id != project_id:
            raise FindingNotFound("finding not found")
        if not finding.reproducible or finding.error is not None:
            raise FindingNotReproducible("finding is not reproducible")
        try:
            bundle = self._bundles.load_sealed(project_id, finding_id)
        except Exception:
            try:
                bundle = await self._bundles.freeze_for_finding(project_id, finding_id)
            except Exception as error:
                raise FindingNotReproducible("finding reproduction bundle is unavailable") from error
        manifest_path, testcase = bundle.root / "manifest.json", bundle.root / "testcase.input"
        if manifest_path.is_symlink() or testcase.is_symlink() or not testcase.is_file():
            raise FindingNotReproducible("finding reproduction bundle is unsafe")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            content = testcase.read_bytes()
            command = tuple(manifest["command"])
            environment_items = tuple(tuple(item) for item in manifest["environment"])
            environment = dict(environment_items)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise FindingNotReproducible("finding reproduction bundle is incomplete") from error
        if (
            manifest.get("bundle_id") != bundle.bundle_id
            or manifest.get("project_id") != project_id
            or manifest.get("finding_id") != finding_id
            or sha256(content).hexdigest() != manifest.get("testcase_sha256")
            or _IMAGE.fullmatch(str(manifest.get("image_id"))) is None
            or not command or len(environment) != len(environment_items)
        ):
            raise FindingNotReproducible("finding reproduction bundle identity is invalid")
        command, uses_stdin = _resolve_input_marker(command)
        if uses_stdin and len(content) > MAX_STDIN_BYTES:
            raise FindingNotReproducible("finding reproduction testcase exceeds the stdin bound")
        expected = self._expected_crash(finding, manifest)
        client = None
        try:
            client = self._docker.connect()
            inspected = ImageInspector(client).inspect(manifest["image_id"])
            if inspected.image_id != manifest["image_id"]:
                raise FindingNotReproducible("finding reproduction image identity changed")
        except FindingNotReproducible:
            raise
        except Exception as error:
            raise FindingNotReproducible("finding reproduction image is unavailable") from error
        finally:
            close = getattr(client, "close", None) if client is not None else None
            if close is not None:
                try:
                    close()
                except Exception:
                    pass
        return PreparedReproduction(
            project_id, finding_id, manifest["image_id"], command,
            MappingProxyType(environment), testcase.resolve(strict=True),
            stdin_bytes=content if uses_stdin else None,
            expected_sanitizer=expected[0], expected_function=expected[1],
            expected_source_location=expected[2],
            bundle_id=bundle.bundle_id, testcase_sha256=manifest["testcase_sha256"],
        )

    async def execute(self, prepared: PreparedReproduction, emit) -> ReproductionOutcome:
        client = self._docker.connect()
        try:
            loop = __import__("asyncio").get_running_loop()

            def sink(stream: str, text: str) -> None:
                future = __import__("asyncio").run_coroutine_threadsafe(
                    emit("output", {"stream": stream, "text": text}), loop,
                )
                future.result()

            try:
                result = await ContainerRunner(client).run_reproduction(
                    prepared.image_id, list(prepared.command), self._timeout, sink,
                    prepared.testcase, environment=prepared.environment,
                    stdin_bytes=prepared.stdin_bytes,
                    run_id=prepared.run_id, project_id=prepared.project_id,
                    finding_id=prepared.finding_id,
                )
            except ContainerTimedOut as error:
                if _matches_expected_emulated_sanitizer_crash(prepared, error):
                    await emit("output", {
                        "stream": "stdout",
                        "text": (
                            "BigEye verified sanitizer evidence against retained replay: "
                            f"{prepared.expected_source_location} ({prepared.expected_function})\n"
                        ),
                    })
                    return ReproductionOutcome(
                        None,
                        "AddressSanitizer crash reproduced; emulator cleanup timed out",
                        timed_out=True,
                        sanitizer_crash_observed=True,
                    )
                raise
            return ReproductionOutcome(result.exit_code, "exited")
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                closed = close()
                if inspect.isawaitable(closed):
                    await closed

    def _expected_crash(self, finding, manifest: dict) -> tuple[str | None, str | None, str | None]:
        if self._finding_artifacts is None:
            return None, None, None
        try:
            detail = self._finding_artifacts.detail(finding)
            replay = detail["replay"]["clean_variant"]
            grouping = detail["grouping"]
            reproducer = detail["reproducer"]
            frame = grouping["frames"][0]
            sanitizer = replay["sanitizer"]
            function = frame["function"]
            source = replay["source_location"]
            grouped_source = frame["source_location"]
        except (KeyError, IndexError, OSError, TypeError, ValueError):
            return None, None, None
        if not all(isinstance(value, dict) for value in (replay, grouping, reproducer, frame)):
            return None, None, None
        if not all(isinstance(value, str) and value for value in (sanitizer, function, source, grouped_source)):
            return None, None, None
        if (
            sanitizer != manifest.get("sanitizer")
            or replay.get("image_id") != manifest.get("image_id")
            or replay.get("crashed") is not True
            or replay.get("error") is not None
            or grouping.get("failure_class") != sanitizer
            or grouping.get("reproducible") is not True
            or grouping.get("harness_misuse") is not False
            or grouping.get("minimised_sha256") != manifest.get("testcase_sha256")
            or reproducer.get("sha256") != manifest.get("testcase_sha256")
            or _source_identity(source) != _source_identity(grouped_source)
        ):
            return None, None, None
        return sanitizer, function, source

    def reconcile_orphan(self, identity: dict) -> None:
        client = self._docker.connect()
        try:
            ContainerRunner(client).reconcile_reproduction(identity)
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()


def _resolve_input_marker(command: tuple[object, ...]) -> tuple[tuple[str, ...], bool]:
    if any(
        not isinstance(argument, str) or not argument or "\x00" in argument
        for argument in command
    ):
        raise FindingNotReproducible("finding reproduction command marker is invalid")
    exact_markers = [argument for argument in command if argument in {"{input}", "{stdin}"}]
    if (
        len(exact_markers) != 1
        or any(
            ("{input}" in argument or "{stdin}" in argument)
            and argument not in {"{input}", "{stdin}"}
            for argument in command
        )
    ):
        raise FindingNotReproducible("finding reproduction command marker is invalid")
    uses_stdin = exact_markers[0] == "{stdin}"
    resolved = tuple(
        _CONTAINER_TESTCASE if argument == "{input}" else argument
        for argument in command
        if argument != "{stdin}"
    )
    if not resolved:
        raise FindingNotReproducible("finding reproduction command marker is invalid")
    return resolved, uses_stdin


def _source_identity(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _matches_expected_emulated_sanitizer_crash(
    prepared: PreparedReproduction, error: ContainerTimedOut,
) -> bool:
    if (
        not error.cleanup_verified
        or prepared.expected_sanitizer != "address"
        or not prepared.expected_function
        or not prepared.expected_source_location
        or prepared.bundle_id is None
        or _DIGEST.fullmatch(prepared.bundle_id) is None
        or prepared.testcase_sha256 is None
        or _DIGEST.fullmatch(prepared.testcase_sha256) is None
        or not _has_exact_prepared_input(prepared)
        or any("{input}" in item or "{stdin}" in item for item in prepared.command)
    ):
        return False
    try:
        content = prepared.testcase.read_bytes()
        if (
            sha256(content).hexdigest() != prepared.testcase_sha256
            or prepared.stdin_bytes is not None and prepared.stdin_bytes != content
        ):
            return False
    except OSError:
        return False
    stderr = error.stderr
    return bool(
        re.search(r"ERROR: AddressSanitizer: [A-Za-z0-9_-]+", stderr)
        and re.search(r"==\d+==ABORTING", stderr)
        and "qemu: uncaught target signal 6" in stderr.casefold()
    )


def _has_exact_prepared_input(prepared: PreparedReproduction) -> bool:
    if prepared.stdin_bytes is None:
        return prepared.command.count(_CONTAINER_TESTCASE) == 1
    return (
        isinstance(prepared.stdin_bytes, bytes)
        and len(prepared.stdin_bytes) <= MAX_STDIN_BYTES
        and _CONTAINER_TESTCASE not in prepared.command
    )
