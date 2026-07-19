"""Persist a truthful LLVM toolchain task result for one project."""

import asyncio


class ToolchainService:
    """A narrow callback for project orchestration after its task is created."""

    def __init__(self, tasks, logs, builder, verifier):
        self._tasks = tasks
        self._logs = logs
        self._builder = builder
        self._verifier = verifier

    async def prepare(self, task) -> None:
        def sink(text) -> None:
            self._logs.append_sync(task, str(text))

        try:
            build = asyncio.create_task(asyncio.to_thread(self._builder.ensure, sink))
            try:
                image = await asyncio.shield(build)
            except asyncio.CancelledError as cancellation:
                try:
                    await asyncio.shield(build)
                except BaseException:
                    pass
                raise cancellation
            await self._verifier.verify(image.image_id, sink)
        except BaseException as error:
            if not isinstance(error, asyncio.CancelledError):
                message = str(error) or type(error).__name__
                sink(message if message.endswith("\n") else f"{message}\n")
                await self._tasks.finish(task.id, message)
            raise
        await self._tasks.finish(task.id)
