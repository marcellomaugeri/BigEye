"""Late-bound Docker work so API startup does not require a daemon."""

import asyncio
from pathlib import Path

from backend.fuzzing.docker.client import DockerClient, DockerUnavailable
from backend.fuzzing.docker.container_runner import ContainerRunner
from backend.fuzzing.docker.image_builder import ImageBuilder
from backend.fuzzing.docker.image_inspector import ImageInspector, MissingImage
from backend.fuzzing.toolchain.builder import ToolchainBuilder
from backend.fuzzing.toolchain.service import ToolchainService
from backend.fuzzing.toolchain.verifier import ToolchainVerifier


class _NoTaskPersistence:
    async def finish(self, task_id, error=None) -> None:
        return None


class DeferredToolchain:
    """Connect, run one real SDK operation, then close that exact client."""

    def __init__(self, dockerfile: Path, logs, docker_client=None):
        self._dockerfile = Path(dockerfile)
        self._logs = logs
        self._docker_client = docker_client or DockerClient()

    async def prepare(self, task) -> None:
        connection = asyncio.create_task(asyncio.to_thread(self._docker_client.connect))
        try:
            client = await asyncio.shield(connection)
        except asyncio.CancelledError:
            def close_when_connected(operation):
                if operation.cancelled():
                    return
                try:
                    connected = operation.result()
                except Exception:
                    return
                asyncio.create_task(asyncio.to_thread(connected.close))
            connection.add_done_callback(close_when_connected)
            raise
        try:
            inspector = ImageInspector(client)
            service = ToolchainService(
                _NoTaskPersistence(), self._logs,
                ToolchainBuilder(self._dockerfile, ImageBuilder(client), inspector),
                ToolchainVerifier(inspector, ContainerRunner(client)),
            )
            await service.prepare(task)
        finally:
            await asyncio.to_thread(client.close)

    async def docker_available(self) -> bool:
        try:
            client = await asyncio.to_thread(self._docker_client.connect)
        except DockerUnavailable:
            return False
        try:
            return True
        finally:
            await asyncio.to_thread(client.close)

    async def toolchain_available(self) -> bool:
        try:
            client = await asyncio.to_thread(self._docker_client.connect)
        except DockerUnavailable:
            return False
        try:
            builder = ToolchainBuilder(self._dockerfile, ImageBuilder(client), ImageInspector(client))
            try:
                ImageInspector(client).inspect(builder.tag())
            except MissingImage:
                return False
            except Exception:
                return False
            return True
        finally:
            await asyncio.to_thread(client.close)
