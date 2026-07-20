"""Exact, read-only execution of one verified frozen finding bundle."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import inspect
import json
from pathlib import Path
import re
from types import MappingProxyType

from backend.fuzzing.docker.container_runner import ContainerRunner
from backend.fuzzing.docker.image_inspector import ImageInspector


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")


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
    run_id: str | None = None


@dataclass(frozen=True)
class ReproductionOutcome:
    exit_code: int | None
    terminal_reason: str


class FindingReproductionService:
    """Resolve exact bundle inputs and execute them in an ephemeral container."""

    def __init__(self, workspace: Path, findings, bundles, docker, *, timeout: float = 30.0):
        self._workspace = Path(workspace).resolve(strict=True)
        self._findings = findings
        self._bundles = bundles
        self._docker = docker
        self._timeout = timeout

    async def prepare(self, project_id: int, finding_id: int) -> PreparedReproduction:
        finding = await self._findings.get(finding_id)
        if finding is None or finding.project_id != project_id:
            raise FindingNotFound("finding not found")
        if not finding.reproducible or finding.error is not None:
            raise FindingNotReproducible("finding is not reproducible")
        try:
            bundle = self._bundles.load_sealed(project_id, finding_id)
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

            result = await ContainerRunner(client).run_reproduction(
                prepared.image_id, list(prepared.command), self._timeout, sink,
                prepared.testcase, environment=prepared.environment,
                run_id=prepared.run_id, project_id=prepared.project_id,
                finding_id=prepared.finding_id,
            )
            return ReproductionOutcome(result.exit_code, "exited")
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                closed = close()
                if inspect.isawaitable(closed):
                    await closed

    def reconcile_orphan(self, identity: dict) -> None:
        client = self._docker.connect()
        try:
            ContainerRunner(client).reconcile_reproduction(identity)
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()
