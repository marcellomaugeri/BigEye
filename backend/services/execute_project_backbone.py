"""Run the three persisted backbone capabilities for one project."""

import asyncio
from pathlib import Path

from backend.services.projects.clone_repository import GitCommandFailed, contained_path
from backend.services.stream_task_output import TaskLogLimitExceeded


TASK_NAMES = ("repository clone", "LLVM toolchain preparation", "repository analysis")


class ExecuteProjectBackbone:
    """Keep task truth in one place while capabilities stay focused."""

    def __init__(self, projects, tasks, clone, toolchain, analysis, logs, workspace: Path, events=None):
        self._projects = projects
        self._tasks = tasks
        self._clone = clone
        self._toolchain = toolchain
        self._analysis = analysis
        self._logs = logs
        self._workspace = Path(workspace)
        self._events = events

    async def schedule(self, project_id: int) -> None:
        project = await self._projects.get(project_id)
        if project is None:
            return
        records = {task.name: task for task in await self._tasks.list_for_project(project_id)}
        if set(records) != set(TASK_NAMES):
            raise RuntimeError("project initial tasks are incomplete")
        clone_task, toolchain_task, analysis_task = (records[name] for name in TASK_NAMES)
        clone_job = asyncio.create_task(self._run_clone(project, clone_task))
        toolchain_job = asyncio.create_task(self._run_capability(toolchain_task, self._toolchain.prepare))
        try:
            clone_ok = await clone_job
            if clone_ok:
                await self._run_analysis(project, analysis_task)
            elif not self._terminal(analysis_task):
                await self._fail(analysis_task, "repository clone did not complete")
            await toolchain_job
        except asyncio.CancelledError:
            clone_job.cancel()
            toolchain_job.cancel()
            await asyncio.gather(clone_job, toolchain_job, return_exceptions=True)
            raise
        finally:
            if not toolchain_job.done():
                toolchain_job.cancel()
                await asyncio.gather(toolchain_job, return_exceptions=True)
        await self._persist_project_error(project_id)

    @staticmethod
    def _terminal(task) -> bool:
        return task.finished_at is not None or task.error is not None

    async def _run_clone(self, project, task) -> bool:
        if self._terminal(task):
            return task.error is None
        try:
            verify = getattr(self._clone, "verify_committed", None)
            if project.commit_sha and verify is not None and await verify(project):
                await self._tasks.finish(task.id)
                await self._task_completed(task)
                await self._project_invalidated(task.project_id)
                return True
            if project.commit_sha is None:
                recover = getattr(self._clone, "recover_published", None)
                if recover is not None:
                    recovered = await recover(project, task)
                    if recovered is not None:
                        await self._tasks.finish(task.id)
                        await self._task_completed(task)
                        await self._project_invalidated(task.project_id)
                        return True
            await self._clone.clone(project, task)
            await self._tasks.finish(task.id)
            await self._task_completed(task)
            await self._project_invalidated(task.project_id)
            return True
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await self._fail(task, error)
            return False

    async def _run_capability(self, task, capability) -> bool:
        if self._terminal(task):
            return task.error is None
        try:
            await capability(task)
            await self._tasks.finish(task.id)
            await self._task_completed(task)
            return True
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await self._fail(task, error)
            return False

    async def _run_analysis(self, project, task) -> bool:
        if self._terminal(task):
            return task.error is None
        root = contained_path(self._workspace, "projects", str(project.id), "repository")
        return await self._run_capability(task, lambda _: self._analysis.analyse(project.id, root))

    async def _fail(self, task, error: Exception | str) -> None:
        message = str(error) or type(error).__name__
        try:
            await self._logs.append(task, f"{message}\n")
        except TaskLogLimitExceeded:
            pass
        await self._tasks.finish(task.id, message)
        if self._events is not None:
            await self._events.append(task.project_id, "activity", {"task_id": task.id, "state": "failed"})

    async def _persist_project_error(self, project_id: int) -> None:
        tasks = await self._tasks.list_for_project(project_id)
        if not all(self._terminal(task) for task in tasks):
            return
        errors = [f"{task.name}: {task.error}" for task in tasks if task.error]
        await self._projects.finish(project_id, "; ".join(errors) if errors else None)
        await self._project_invalidated(project_id)

    async def _task_completed(self, task) -> None:
        if self._events is not None:
            await self._events.append(task.project_id, "activity", {"task_id": task.id, "state": "completed"})

    async def _project_invalidated(self, project_id: int) -> None:
        if self._events is not None:
            await self._events.append(project_id, "events", {"name": "project"})
