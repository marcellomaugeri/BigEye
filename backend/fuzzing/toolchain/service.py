"""Persist a truthful LLVM toolchain task result for one project."""

import asyncio
from pathlib import Path


class ToolchainService:
    """A narrow callback for project orchestration after its task is created."""

    def __init__(self, tasks, logs, builder, verifier):
        self._tasks = tasks
        self._logs = logs
        self._builder = builder
        self._verifier = verifier

    async def prepare(self, task) -> None:
        path = Path(self._logs.path_for(task))
        path.parent.mkdir(parents=True, exist_ok=True)

        def sink(text) -> None:
            with path.open("a", encoding="utf-8") as log:
                log.write(text)

        try:
            image = await asyncio.to_thread(self._builder.ensure, sink)
            await self._verifier.verify(image.image_id, sink)
        except BaseException as error:
            if not isinstance(error, asyncio.CancelledError):
                message = str(error) or type(error).__name__
                sink(message if message.endswith("\n") else f"{message}\n")
                await self._tasks.finish(task.id, message)
            raise
        await self._tasks.finish(task.id)
