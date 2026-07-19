"""SQL access for tasks only."""

from backend.models.task import Task


class TaskRepository:
    def __init__(self, pool):
        self._pool = pool

    async def get(self, task_id: int) -> Task | None:
        row = await self._pool.fetchrow(
            """SELECT id, project_id, name, created_at, finished_at, error
               FROM tasks WHERE id = $1""", task_id
        )
        return self._task(row) if row else None

    async def list_for_project(self, project_id: int) -> list[Task]:
        rows = await self._pool.fetch(
            """SELECT id, project_id, name, created_at, finished_at, error
               FROM tasks WHERE project_id = $1 ORDER BY created_at, id""", project_id
        )
        return [self._task(row) for row in rows]

    async def finish(self, task_id: int, error: str | None = None) -> None:
        await self._pool.execute("UPDATE tasks SET finished_at = CURRENT_TIMESTAMP, error = $2 WHERE id = $1", task_id, error)

    @staticmethod
    def _task(row) -> Task:
        return Task(row["id"], row["project_id"], row["name"], row["created_at"], row["finished_at"], row["error"])
