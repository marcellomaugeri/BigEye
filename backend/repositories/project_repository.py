"""SQL access for projects only."""

from backend.models.project import Project


class ProjectRepository:
    def __init__(self, pool):
        self._pool = pool

    async def create_with_tasks(self, repository_url: str, worker_count: int, task_names: list[str]) -> Project:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                row = await connection.fetchrow(
                    """INSERT INTO projects (repository_url, worker_count)
                       VALUES ($1, $2)
                       RETURNING id, repository_url, worker_count, commit_sha, created_at, finished_at, error""",
                    repository_url,
                    worker_count,
                )
                for name in task_names:
                    await connection.execute(
                        "INSERT INTO tasks (project_id, name) VALUES ($1, $2)", row["id"], name
                    )
        return self._project(row)

    async def get(self, project_id: int) -> Project | None:
        row = await self._pool.fetchrow(
            """SELECT id, repository_url, worker_count, commit_sha, created_at, finished_at, error
               FROM projects WHERE id = $1""", project_id
        )
        return self._project(row) if row else None

    async def list(self) -> list[Project]:
        rows = await self._pool.fetch(
            """SELECT id, repository_url, worker_count, commit_sha, created_at, finished_at, error
               FROM projects ORDER BY created_at DESC, id DESC"""
        )
        return [self._project(row) for row in rows]

    async def list_unfinished(self) -> list[Project]:
        rows = await self._pool.fetch(
            """SELECT id, repository_url, worker_count, commit_sha, created_at, finished_at, error
               FROM projects WHERE finished_at IS NULL AND error IS NULL ORDER BY created_at, id"""
        )
        return [self._project(row) for row in rows]

    async def set_commit_sha(self, project_id: int, commit_sha: str) -> None:
        await self._pool.execute("UPDATE projects SET commit_sha = $2 WHERE id = $1", project_id, commit_sha)

    @staticmethod
    def _project(row) -> Project:
        return Project(row["id"], row["repository_url"], row["worker_count"], row["commit_sha"], row["created_at"], row["finished_at"], row["error"])
