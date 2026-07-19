"""Run short, tightly bounded verification containers through the SDK."""

import asyncio
from dataclasses import dataclass

from requests.exceptions import ReadTimeout

from backend.fuzzing.docker.image_builder import PLATFORM


class ContainerTimedOut(RuntimeError):
    """Raised when a verification container exceeds its bounded wait."""


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
        holder: dict[str, object] = {}
        worker = asyncio.create_task(asyncio.to_thread(self._run_blocking, holder, image, command, timeout, sink))
        try:
            return await asyncio.wait_for(asyncio.shield(worker), timeout=timeout)
        except asyncio.TimeoutError as error:
            await self._cleanup_holder(holder, stop=True)
            raise ContainerTimedOut(f"container exceeded {timeout} seconds") from error
        except BaseException:
            await self._cleanup_holder(holder, stop=True)
            raise

    def _run_blocking(self, holder, image: str, command: list[str], timeout: float, sink) -> ContainerResult:
        container = self._client.containers.create(
            image, command, platform=PLATFORM, network_disabled=True, read_only=True,
            cap_drop=["ALL"], security_opt=["no-new-privileges"], pids_limit=64,
            mem_limit="512m", nano_cpus=1_000_000_000, detach=True,
        )
        holder["container"] = container
        failed = True
        try:
            container.start()
            try:
                waited = container.wait(timeout=timeout)
            except (TimeoutError, ReadTimeout) as error:
                raise ContainerTimedOut(f"container {container.id} exceeded {timeout} seconds") from error
            chunks = []
            for chunk in container.logs(stream=True, follow=False):
                text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk)
                chunks.append(text)
                sink(text)
            failed = False
            return ContainerResult(int(waited["StatusCode"]), "".join(chunks))
        finally:
            self._cleanup(container, stop=failed)
            holder.pop("container", None)

    async def _cleanup_holder(self, holder, stop: bool) -> None:
        container = holder.get("container")
        if container is not None:
            await asyncio.to_thread(self._cleanup, container, stop)

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
