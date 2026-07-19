"""Run short, tightly bounded verification containers through the SDK."""

import asyncio
import threading
from dataclasses import dataclass

from requests.exceptions import ReadTimeout

from backend.fuzzing.docker.image_builder import PLATFORM


class ContainerTimedOut(RuntimeError):
    """Raised when a verification container exceeds its bounded wait."""


class ContainerOutputExceeded(RuntimeError):
    """Raised when a verification container emits too much output."""


class ContainerCancelled(RuntimeError):
    """Raised in the worker after its caller has already cancelled it."""


MAX_OUTPUT_BYTES = 1_048_576


@dataclass(frozen=True)
class ContainerResult:
    exit_code: int
    output: str


class ContainerRunner:
    def __init__(self, client):
        self._client = client

    async def run(self, image: str, command: list[str], timeout: float, sink) -> ContainerResult:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        holder: dict[str, object] = {"cancel_requested": False, "cleanup_started": False, "lock": threading.Lock()}
        worker = asyncio.create_task(asyncio.to_thread(self._run_blocking, holder, image, command, timeout, sink))
        try:
            return await asyncio.wait_for(asyncio.shield(worker), timeout=timeout)
        except asyncio.TimeoutError as error:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            raise ContainerTimedOut(f"container exceeded {timeout} seconds") from error
        except BaseException:
            self._request_cancellation(holder)
            await self._cleanup_holder(holder, stop=True)
            raise

    def _run_blocking(self, holder, image: str, command: list[str], timeout: float, sink) -> ContainerResult:
        container = self._client.containers.create(
            image, command, platform=PLATFORM, network_disabled=True, read_only=True,
            cap_drop=["ALL"], security_opt=["no-new-privileges"], pids_limit=64,
            mem_limit="512m", nano_cpus=1_000_000_000, detach=True,
            tmpfs={"/tmp": "rw,nosuid,nodev,exec,size=64m,mode=1777"},
        )
        with holder["lock"]:
            holder["container"] = container
            cancelled = holder["cancel_requested"]
        failed = True
        try:
            if cancelled:
                raise ContainerCancelled(f"container {container.id} was cancelled before start")
            container.start()
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

    def _cleanup_holder_blocking(self, holder, stop: bool) -> None:
        with holder["lock"]:
            container = holder.get("container")
            if container is None or holder["cleanup_started"]:
                return
            holder["cleanup_started"] = True
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
