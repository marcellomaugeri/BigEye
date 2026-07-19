"""Late-bound Docker work so API startup does not require a daemon."""

import asyncio
from pathlib import Path

from docker.errors import DockerException

from backend.fuzzing.docker.client import DOCKER_REQUEST_TIMEOUT_SECONDS, DockerClient, DockerUnavailable
from backend.fuzzing.docker.container_runner import ContainerOutputExceeded, ContainerRunner, ContainerTimedOut
from backend.fuzzing.docker.image_builder import ImageBuilder
from backend.fuzzing.docker.image_inspector import ImageInspector, MissingImage
from backend.fuzzing.toolchain.builder import ToolchainBuilder
from backend.fuzzing.toolchain.service import ToolchainService
from backend.fuzzing.toolchain.verifier import ToolchainVerifier, ToolchainVerificationFailed
from backend.fuzzing.docker.image_inspector import UnsupportedImagePlatform


CANCELLATION_CLEANUP_TIMEOUT_SECONDS = DOCKER_REQUEST_TIMEOUT_SECONDS + 1


class _NoTaskPersistence:
    async def finish(self, task_id, error=None) -> None:
        return None


class DeferredToolchain:
    """Connect, run one real SDK operation, then close that exact client."""

    def __init__(self, dockerfile: Path, logs, docker_client=None):
        self._dockerfile = Path(dockerfile)
        self._logs = logs
        self._docker_client = docker_client or DockerClient()

    async def _with_client(self, operation):
        connection = asyncio.create_task(asyncio.to_thread(self._docker_client.connect))
        try:
            client = await asyncio.shield(connection)
        except asyncio.CancelledError:
            def close_when_connected(future):
                if future.cancelled(): return
                try: connected = future.result()
                except Exception: return
                asyncio.create_task(asyncio.to_thread(connected.close))
            connection.add_done_callback(close_when_connected)
            raise
        work = asyncio.create_task(operation(client))
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError as cancellation:
            work.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(work), timeout=CANCELLATION_CLEANUP_TIMEOUT_SECONDS)
            except BaseException:
                pass
            raise cancellation
        finally:
            await asyncio.to_thread(client.close)

    async def prepare(self, task) -> None:
        async def prepare_connected(client):
            inspector = ImageInspector(client)
            service = ToolchainService(
                _NoTaskPersistence(), self._logs,
                ToolchainBuilder(self._dockerfile, ImageBuilder(client), inspector),
                ToolchainVerifier(inspector, ContainerRunner(client)),
                persist_terminal=False,
            )
            await service.prepare(task)
        await self._with_client(prepare_connected)

    async def docker_available(self) -> bool:
        try:
            return await self._with_client(lambda client: _true())
        except (DockerUnavailable, DockerException):
            return False

    async def toolchain_available(self) -> bool:
        try:
            return await self._with_client(self._inspect_toolchain)
        except DockerUnavailable:
            return False

    async def _inspect_toolchain(self, client) -> bool:
        inspector = ImageInspector(client)
        builder = ToolchainBuilder(self._dockerfile, ImageBuilder(client), inspector)
        try:
            image = await asyncio.to_thread(inspector.inspect, builder.tag())
            await ToolchainVerifier(inspector, ContainerRunner(client)).verify(image.image_id, lambda text: None)
        except (DockerException, MissingImage, UnsupportedImagePlatform, ToolchainVerificationFailed,
                ContainerTimedOut, ContainerOutputExceeded):
            return False
        return True


async def _true() -> bool:
    return True
