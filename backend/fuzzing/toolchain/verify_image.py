"""Build or reuse the maintained toolchain image and verify it end to end."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys

from backend.fuzzing.docker.client import DockerClient
from backend.fuzzing.docker.container_runner import ContainerRunner
from backend.fuzzing.docker.image_builder import ImageBuilder
from backend.fuzzing.docker.image_inspector import ImageInspector
from backend.fuzzing.toolchain.builder import ToolchainBuilder
from backend.fuzzing.toolchain.verifier import ToolchainVerifier


DOCKERFILE = Path(__file__).parents[1] / "images" / "Dockerfile"


def connect():
    return DockerClient().connect()


def create_builder(client) -> ToolchainBuilder:
    inspector = ImageInspector(client)
    return ToolchainBuilder(DOCKERFILE, ImageBuilder(client), inspector)


def create_verifier(client) -> ToolchainVerifier:
    inspector = ImageInspector(client)
    return ToolchainVerifier(inspector, ContainerRunner(client))


def _write(text: str) -> None:
    print(text, end="" if text.endswith("\n") else "\n", flush=True)


async def verify() -> str:
    client = await asyncio.to_thread(connect)
    try:
        image = await asyncio.to_thread(create_builder(client).ensure, _write)
        await create_verifier(client).verify(image.image_id, _write)
        return image.image_id
    finally:
        await asyncio.to_thread(client.close)


def main() -> int:
    try:
        image_id = asyncio.run(verify())
    except Exception as error:
        print(str(error) or type(error).__name__, file=sys.stderr)
        return 1
    print(f"{image_id} linux/amd64 LLVM 18 AFL++ 4.40c verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
