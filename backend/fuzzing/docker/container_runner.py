"""Run short, tightly bounded verification containers through the SDK."""

import asyncio
from collections.abc import Mapping
import re
import threading
from dataclasses import dataclass

from requests.exceptions import ReadTimeout

from backend.fuzzing.docker.image_builder import PLATFORM
from backend.fuzzing.docker.stdin import (
    MAX_STDIN_BYTES,
    close_attached_stdin,
    send_exact_stdin,
)


class ContainerTimedOut(RuntimeError):
    """Raised when a verification container exceeds its bounded wait."""


class ContainerOutputExceeded(RuntimeError):
    """Raised when a verification container emits too much output."""


class ContainerCancelled(RuntimeError):
    """Raised in the worker after its caller has already cancelled it."""


MAX_OUTPUT_BYTES = 1_048_576
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_MAX_ENVIRONMENT_ENTRIES = 16
_MAX_ENVIRONMENT_VALUE_BYTES = 4_096
_MAX_ENVIRONMENT_BYTES = 16 * 1_024


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
    ) -> ContainerResult:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if stdin_bytes is not None and (
            not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > MAX_STDIN_BYTES
        ):
            raise ValueError("container stdin exceeds its byte bound")
        bounded_environment = _bounded_environment(environment)
        holder: dict[str, object] = {"cancel_requested": False, "cleanup_started": False, "lock": threading.Lock()}
        worker = asyncio.create_task(asyncio.to_thread(
            self._run_blocking, holder, image, command, timeout, sink, stdin_bytes,
            bounded_environment,
        ))
        worker.add_done_callback(self._observe_worker)
        try:
            return await asyncio.wait_for(worker, timeout=timeout)
        except asyncio.TimeoutError as error:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            raise ContainerTimedOut(f"container exceeded {timeout} seconds") from error
        except BaseException:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            raise

    def _run_blocking(
        self, holder, image: str, command: list[str], timeout: float, sink,
        stdin_bytes: bytes | None, environment: dict[str, str],
    ) -> ContainerResult:
        options = {
            "platform": PLATFORM, "network_disabled": True, "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"], "pids_limit": 64,
            "mem_limit": "512m", "nano_cpus": 1_000_000_000, "detach": True,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,exec,size=64m,mode=1777"},
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

    def _cleanup_holder_blocking(self, holder, stop: bool) -> None:
        with holder["lock"]:
            container = holder.get("container")
            if container is None or holder["cleanup_started"]:
                return
            holder["cleanup_started"] = True
            attached = holder.get("attached")
        if attached is not None:
            close_attached_stdin(attached)
        self._cleanup(container, stop)

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
