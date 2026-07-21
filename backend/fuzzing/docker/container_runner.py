"""Run short, tightly bounded verification containers through the SDK."""

import asyncio
from collections.abc import Mapping
import re
import threading
from dataclasses import dataclass
from uuid import uuid4
import docker

from requests.exceptions import ReadTimeout

from backend.fuzzing.docker.image_builder import PLATFORM
from backend.fuzzing.docker.stdin import (
    MAX_STDIN_BYTES,
    close_attached_stdin,
    send_exact_stdin,
)
from backend.fuzzing.crashes.artifacts import sanitise_terminal_output


class ContainerTimedOut(RuntimeError):
    """Raised when a verification container exceeds its bounded wait."""

    def __init__(self, message: str, *, stderr: str = "", cleanup_verified: bool = False):
        super().__init__(message)
        self.stderr = stderr
        self.cleanup_verified = cleanup_verified


class ContainerOutputExceeded(RuntimeError):
    """Raised when a verification container emits too much output."""


class ContainerCancelled(RuntimeError):
    """Raised in the worker after its caller has already cancelled it."""


class ContainerCleanupFailed(RuntimeError):
    """A managed reproduction container could not be proven absent."""


MAX_OUTPUT_BYTES = 1_048_576
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_MAX_ENVIRONMENT_ENTRIES = 16
_MAX_ENVIRONMENT_VALUE_BYTES = 4_096
_MAX_ENVIRONMENT_BYTES = 16 * 1_024
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_PURPOSE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


def ephemeral_container_identity(run_id: str, purpose: str, project_id: int = 0) -> dict:
    if (
        _RUN_ID.fullmatch(run_id or "") is None
        or _PURPOSE.fullmatch(purpose or "") is None
        or type(project_id) is not int
        or project_id < 0
    ):
        raise ValueError("ephemeral container identity is invalid")
    return {
        "run_id": run_id,
        "name": f"bigeye-ephemeral-{run_id}",
        "labels": {
            "com.bigeye.managed": "bounded-verification",
            "com.bigeye.ephemeral.run_id": run_id,
            "com.bigeye.purpose": purpose,
            "com.bigeye.project_id": str(project_id),
        },
    }


def reproduction_container_identity(run_id: str, project_id: int, finding_id: int) -> dict:
    if _RUN_ID.fullmatch(run_id or "") is None or type(project_id) is not int or project_id <= 0 or type(finding_id) is not int or finding_id <= 0:
        raise ValueError("reproduction container identity is invalid")
    return {
        "run_id": run_id,
        "name": f"bigeye-reproduction-{run_id}",
        "labels": {
            "com.bigeye.managed": "finding-reproduction",
            "com.bigeye.reproduction.run_id": run_id,
            "com.bigeye.project_id": str(project_id),
            "com.bigeye.finding_id": str(finding_id),
        },
    }


@dataclass(frozen=True)
class ContainerResult:
    exit_code: int
    output: str


class ContainerRunner:
    def __init__(self, client):
        self._client = client

    async def run(
        self, image: str, command: list[str], timeout: float, sink, *,
        stdin_bytes: bytes | None = None,
        environment: Mapping[str, str] | None = None,
        project_id: int = 0,
        purpose: str = "verification",
    ) -> ContainerResult:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if stdin_bytes is not None and (
            not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > MAX_STDIN_BYTES
        ):
            raise ValueError("container stdin exceeds its byte bound")
        bounded_environment = _bounded_environment(environment)
        identity = ephemeral_container_identity(uuid4().hex, purpose, project_id)
        holder: dict[str, object] = {"cancel_requested": False, "cleanup_started": False, "lock": threading.Lock()}
        worker = asyncio.create_task(asyncio.to_thread(
            self._run_blocking, holder, image, command, timeout, sink, stdin_bytes,
            bounded_environment, identity,
        ))
        worker.add_done_callback(self._observe_worker)
        try:
            return await self._await_worker(worker, timeout)
        except asyncio.TimeoutError as error:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            await self._settle_worker(worker)
            raise ContainerTimedOut(f"container exceeded {timeout} seconds") from error
        except BaseException:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            await self._settle_worker(worker)
            raise

    async def run_reproduction(
        self, image: str, command: list[str], timeout: float, sink,
        testcase_path, *, environment: Mapping[str, str] | None = None,
        stdin_bytes: bytes | None = None,
        run_id: str, project_id: int, finding_id: int,
    ) -> ContainerResult:
        """Stream one sealed testcase by a read-only mount or bounded stdin."""
        from pathlib import Path

        if timeout <= 0:
            raise ValueError("timeout must be positive")
        testcase = Path(testcase_path)
        if testcase.is_symlink() or not testcase.is_file():
            raise ValueError("reproduction testcase is unavailable or unsafe")
        testcase = testcase.resolve(strict=True)
        if stdin_bytes is not None and (
            not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > MAX_STDIN_BYTES
        ):
            raise ValueError("reproduction stdin exceeds its byte bound")
        if stdin_bytes is not None and (
            testcase.stat().st_size > MAX_STDIN_BYTES
            or testcase.read_bytes() != stdin_bytes
        ):
            raise ValueError("reproduction stdin does not match the sealed testcase")
        bounded_environment = _bounded_environment(environment)
        identity = reproduction_container_identity(run_id, project_id, finding_id)
        holder: dict[str, object] = {
            "cancel_requested": False, "cleanup_started": False,
            "lock": threading.Lock(), "strict_cleanup": True,
            "stderr_chunks": [], "cleanup_verified": False,
        }
        worker = asyncio.create_task(asyncio.to_thread(
            self._run_reproduction_blocking, holder, image, command, timeout,
            sink, testcase, stdin_bytes, bounded_environment, identity,
        ))
        worker.add_done_callback(self._observe_worker)
        try:
            return await self._await_worker(worker, timeout)
        except asyncio.TimeoutError as error:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            await self._settle_worker(worker)
            raise ContainerTimedOut(
                f"container exceeded {timeout} seconds",
                stderr="".join(holder["stderr_chunks"]),
                cleanup_verified=bool(holder["cleanup_verified"]),
            ) from error
        except ContainerTimedOut as error:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            await self._settle_worker(worker)
            error.stderr = "".join(holder["stderr_chunks"])
            error.cleanup_verified = bool(holder["cleanup_verified"])
            raise
        except BaseException:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            await self._settle_worker(worker)
            raise

    def _run_reproduction_blocking(
        self, holder, image: str, command: list[str], timeout: float, sink,
        testcase, stdin_bytes: bytes | None, environment: dict[str, str], identity: dict,
    ) -> ContainerResult:
        options = {
            "platform": PLATFORM, "network_disabled": True, "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"],
            "pids_limit": 64, "mem_limit": "512m", "nano_cpus": 1_000_000_000,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,exec,size=64m,mode=1777"},
            "detach": True, "user": "65534:65534",
            "name": identity["name"], "labels": identity["labels"],
        }
        if stdin_bytes is None:
            options["volumes"] = {str(testcase): {"bind": "/finding/input", "mode": "ro"}}
        else:
            options.update({"stdin_open": True, "tty": False})
        if environment:
            options["environment"] = environment
        container = self._client.containers.create(image, command, **options)
        with holder["lock"]:
            holder["container"] = container
            cancelled = holder["cancel_requested"]
        failed = True
        attached = None
        chunks: list[str] = []
        output_size = 0
        try:
            if cancelled:
                raise ContainerCancelled(f"container {container.id} was cancelled before start")
            if stdin_bytes is not None:
                attached = container.attach_socket(params={"stdin": 1, "stream": 1})
                with holder["lock"]:
                    holder["attached"] = attached
                    cancelled = holder["cancel_requested"] or holder["cleanup_started"]
                if cancelled:
                    try:
                        close_attached_stdin(attached)
                    finally:
                        raise ContainerCancelled(
                            f"container {container.id} was cancelled during stdin attachment"
                        )
            container.start()
            if attached is not None:
                send_exact_stdin(attached, stdin_bytes, timeout)
            output = container.attach(
                stream=True, logs=True, stdout=True, stderr=True, demux=True,
            )
            with holder["lock"]:
                holder["output"] = output
                cancelled = holder["cancel_requested"] or holder["cleanup_started"]
            if cancelled:
                close = getattr(output, "close", None)
                if close is not None:
                    close()
                raise ContainerCancelled(f"container {container.id} was cancelled during output attachment")
            for item in output:
                stdout, stderr = item if isinstance(item, tuple) else (item, None)
                for stream, chunk in (("stdout", stdout), ("stderr", stderr)):
                    if chunk is None:
                        continue
                    raw_size = len(chunk) if isinstance(chunk, bytes) else len(str(chunk).encode("utf-8"))
                    output_size += raw_size
                    if output_size > MAX_OUTPUT_BYTES:
                        message = f"container output exceeded {MAX_OUTPUT_BYTES} bytes\n"
                        sink("stderr", message)
                        raise ContainerOutputExceeded(message.rstrip())
                    text = sanitise_terminal_output(chunk)
                    chunks.append(text)
                    if stream == "stderr":
                        with holder["lock"]:
                            holder["stderr_chunks"].append(text)
                    sink(stream, text)
            try:
                waited = container.wait(timeout=timeout)
            except (TimeoutError, ReadTimeout) as error:
                raise ContainerTimedOut(
                    f"container {container.id} exceeded {timeout} seconds",
                    stderr="".join(holder["stderr_chunks"]),
                ) from error
            failed = False
            return ContainerResult(int(waited["StatusCode"]), "".join(chunks))
        finally:
            self._cleanup_holder_blocking(holder, stop=failed)

    def _run_blocking(
        self, holder, image: str, command: list[str], timeout: float, sink,
        stdin_bytes: bytes | None, environment: dict[str, str], identity: dict,
    ) -> ContainerResult:
        options = {
            "platform": PLATFORM, "network_disabled": True, "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"], "pids_limit": 64,
            "mem_limit": "512m", "nano_cpus": 1_000_000_000, "detach": True,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,exec,size=64m,mode=1777"},
            "name": identity["name"], "labels": identity["labels"],
        }
        if stdin_bytes is not None:
            options.update({"detach": False, "stdin_open": True, "tty": False})
        if environment:
            options["environment"] = environment
        container = self._client.containers.create(image, command, **options)
        with holder["lock"]:
            holder["container"] = container
            cancelled = holder["cancel_requested"]
        failed = True
        attached = None
        try:
            if cancelled:
                raise ContainerCancelled(f"container {container.id} was cancelled before start")
            if stdin_bytes is not None:
                attached = container.attach_socket(params={"stdin": 1, "stream": 1})
                with holder["lock"]:
                    holder["attached"] = attached
                    cancelled = holder["cancel_requested"] or holder["cleanup_started"]
                if cancelled:
                    try:
                        close_attached_stdin(attached)
                    finally:
                        raise ContainerCancelled(
                            f"container {container.id} was cancelled during stdin attachment"
                        )
            container.start()
            if attached is not None:
                send_exact_stdin(attached, stdin_bytes, timeout)
            try:
                waited = container.wait(timeout=timeout)
            except (TimeoutError, ReadTimeout) as error:
                raise ContainerTimedOut(f"container {container.id} exceeded {timeout} seconds") from error
            chunks, output_size = [], 0
            for chunk in container.logs(stream=True, follow=False):
                text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk)
                output_size += len(chunk) if isinstance(chunk, bytes) else len(text.encode("utf-8"))
                if output_size > MAX_OUTPUT_BYTES:
                    sink(f"container output exceeded {MAX_OUTPUT_BYTES} bytes\n")
                    raise ContainerOutputExceeded(f"container output exceeded {MAX_OUTPUT_BYTES} bytes")
                chunks.append(text)
                sink(text)
            failed = False
            return ContainerResult(int(waited["StatusCode"]), "".join(chunks))
        finally:
            self._cleanup_holder_blocking(holder, stop=failed)

    async def _cleanup_holder(self, holder, stop: bool) -> None:
        await asyncio.to_thread(self._cleanup_holder_blocking, holder, stop)

    @staticmethod
    def _request_cancellation(holder) -> None:
        with holder["lock"]:
            holder["cancel_requested"] = True

    @staticmethod
    def _observe_worker(worker: asyncio.Task) -> None:
        if not worker.cancelled():
            worker.exception()

    @staticmethod
    async def _settle_worker(worker: asyncio.Task) -> None:
        try:
            await worker
        except BaseException:
            pass

    @staticmethod
    async def _await_worker(worker: asyncio.Task, timeout: float) -> ContainerResult:
        done, _pending = await asyncio.wait({worker}, timeout=timeout)
        if not done:
            raise asyncio.TimeoutError
        return await worker

    def _cleanup_holder_blocking(self, holder, stop: bool) -> None:
        with holder["lock"]:
            container = holder.get("container")
            if container is None or holder["cleanup_started"]:
                return
            holder["cleanup_started"] = True
            attached = holder.get("attached")
        if attached is not None:
            try:
                close_attached_stdin(attached)
            except Exception:
                pass
        output = holder.get("output")
        if output is not None:
            close = getattr(output, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:
                    pass
        if holder.get("strict_cleanup"):
            self._cleanup_reproduction(container, stop)
            with holder["lock"]:
                holder["cleanup_verified"] = True
        else:
            self._cleanup(container, stop)

    def _cleanup_reproduction(self, container, stop: bool) -> None:
        if stop:
            for operation in (lambda: container.stop(timeout=0), container.kill):
                for _attempt in range(2):
                    try:
                        operation()
                        break
                    except Exception:
                        continue
        not_found = getattr(self._client, "errors", docker.errors).NotFound
        for _attempt in range(2):
            try:
                container.remove(force=True)
            except Exception:
                pass
            try:
                self._client.containers.get(container.id)
            except not_found:
                return
            except Exception:
                continue
        raise ContainerCleanupFailed("reproduction container removal could not be verified")

    def reconcile_reproduction(self, identity: dict) -> None:
        expected = reproduction_container_identity(
            identity.get("run_id"), int(identity.get("labels", {}).get("com.bigeye.project_id", 0)),
            int(identity.get("labels", {}).get("com.bigeye.finding_id", 0)),
        )
        if identity != expected:
            raise ContainerCleanupFailed("persisted reproduction container identity is invalid")
        filters = {"label": [f"{key}={value}" for key, value in expected["labels"].items()]}
        candidates = self._client.containers.list(all=True, filters=filters)
        for container in candidates:
            labels = getattr(container, "labels", None) or getattr(container, "attrs", {}).get("Config", {}).get("Labels", {})
            if labels == expected["labels"] and getattr(container, "name", expected["name"]) == expected["name"]:
                self._cleanup_reproduction(container, stop=True)
        remaining = self._client.containers.list(all=True, filters=filters)
        if any(
            (getattr(item, "labels", None) or getattr(item, "attrs", {}).get("Config", {}).get("Labels", {})) == expected["labels"]
            for item in remaining
        ):
            raise ContainerCleanupFailed("orphan reproduction container removal could not be verified")

    def reconcile_ephemeral(self) -> None:
        """Remove only bounded containers carrying an exact BigEye-owned identity."""
        managed = "com.bigeye.managed=bounded-verification"
        candidates = self._client.containers.list(all=True, filters={"label": [managed]})
        for container in candidates:
            labels = (
                getattr(container, "labels", None)
                or getattr(container, "attrs", {}).get("Config", {}).get("Labels", {})
            )
            try:
                project_id = int(labels.get("com.bigeye.project_id", ""))
                expected = ephemeral_container_identity(
                    labels.get("com.bigeye.ephemeral.run_id"),
                    labels.get("com.bigeye.purpose"),
                    project_id,
                )
            except (TypeError, ValueError):
                continue
            bigeye_labels = {
                key: value for key, value in labels.items()
                if isinstance(key, str) and key.startswith("com.bigeye.")
            }
            if (
                bigeye_labels == expected["labels"]
                and getattr(container, "name", None) == expected["name"]
            ):
                self._cleanup_reproduction(container, stop=True)

        remaining = self._client.containers.list(all=True, filters={"label": [managed]})
        if any(self._is_exact_ephemeral(item) for item in remaining):
            raise ContainerCleanupFailed("orphan ephemeral container removal could not be verified")

    @staticmethod
    def _is_exact_ephemeral(container) -> bool:
        labels = (
            getattr(container, "labels", None)
            or getattr(container, "attrs", {}).get("Config", {}).get("Labels", {})
        )
        try:
            expected = ephemeral_container_identity(
                labels.get("com.bigeye.ephemeral.run_id"),
                labels.get("com.bigeye.purpose"),
                int(labels.get("com.bigeye.project_id", "")),
            )
        except (TypeError, ValueError):
            return False
        bigeye_labels = {
            key: value for key, value in labels.items()
            if isinstance(key, str) and key.startswith("com.bigeye.")
        }
        return (
            bigeye_labels == expected["labels"]
            and getattr(container, "name", None) == expected["name"]
        )

    @staticmethod
    def _cleanup(container, stop: bool) -> None:
        if stop:
            try:
                container.stop(timeout=0)
            except Exception:
                pass
            try:
                container.kill()
            except Exception:
                pass
        try:
            container.remove(force=True)
        except Exception:
            pass


class DeferredEphemeralContainerRecovery:
    """Recover exact BigEye-owned bounded containers before project work resumes."""

    def __init__(self, docker_client):
        self._docker_client = docker_client

    async def recover(self) -> None:
        client = await asyncio.to_thread(self._docker_client.connect)
        try:
            await asyncio.to_thread(ContainerRunner(client).reconcile_ephemeral)
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                await asyncio.to_thread(close)


def _bounded_environment(environment: Mapping[str, str] | None) -> dict[str, str]:
    if environment is None:
        return {}
    if not isinstance(environment, Mapping) or len(environment) > _MAX_ENVIRONMENT_ENTRIES:
        raise ValueError("container environment exceeds its entry bound")
    result: dict[str, str] = {}
    total = 0
    for name, value in environment.items():
        if not isinstance(name, str) or not _ENVIRONMENT_NAME.fullmatch(name):
            raise ValueError("container environment name is invalid")
        if (
            not isinstance(value, str) or "\x00" in value
            or len(value.encode("utf-8")) > _MAX_ENVIRONMENT_VALUE_BYTES
        ):
            raise ValueError("container environment value is invalid or unbounded")
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if total > _MAX_ENVIRONMENT_BYTES:
            raise ValueError("container environment exceeds its byte bound")
        result[name] = value
    return result
