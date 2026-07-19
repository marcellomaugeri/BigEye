"""Persist a truthful LLVM toolchain task result for one project."""

import asyncio
import inspect
import threading


class ToolchainService:
    """A narrow callback for project orchestration after its task is created."""

    def __init__(self, tasks, logs, builder, verifier, persist_terminal: bool = True):
        self._tasks = tasks
        self._logs = logs
        self._builder = builder
        self._verifier = verifier
        self._persist_terminal = persist_terminal

    async def prepare(self, task) -> None:
        def sink(text) -> None:
            self._logs.append_sync(task, str(text))

        try:
            cancelled = threading.Event()
            ensure = self._builder.ensure
            parameters = inspect.signature(ensure).parameters
            kwargs = {"cancellation_signal": cancelled} if "cancellation_signal" in parameters else {}
            build = asyncio.create_task(asyncio.to_thread(ensure, sink, **kwargs))
            try:
                image = await asyncio.shield(build)
            except asyncio.CancelledError as cancellation:
                cancelled.set()
                try:
                    await asyncio.shield(build)
                except BaseException:
                    pass
                raise cancellation
            await self._verifier.verify(image.image_id, sink)
        except BaseException as error:
            if not isinstance(error, asyncio.CancelledError):
                message = str(error) or type(error).__name__
                if self._persist_terminal:
                    sink(message if message.endswith("\n") else f"{message}\n")
                    await self._tasks.finish(task.id, message)
            raise
        await self._tasks.finish(task.id)
