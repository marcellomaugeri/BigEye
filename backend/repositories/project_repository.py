"""SQL access for projects only."""

from datetime import datetime

from backend.models.project import Project


class ProjectRepository:
    def __init__(self, pool):
        self._pool = pool

    async def create_with_tasks(
        self,
        repository_url: str,
        worker_count: int,
        task_names: list[str],
        requested_revision: str = "HEAD",
        repository_token: str | None = None,
    ) -> Project:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                if requested_revision == "HEAD" and repository_token is None:
                    row = await connection.fetchrow(
                        """INSERT INTO projects (repository_url, worker_count)
                           VALUES ($1, $2)
                           RETURNING id, repository_url, requested_revision, worker_count, commit_sha,
                                     repository_token IS NOT NULL AS token_present, created_at,
                                     manager_wake_at, manager_wake_reason, error""",
                        repository_url,
                        worker_count,
                    )
                else:
                    row = await connection.fetchrow(
                        """INSERT INTO projects (repository_url, requested_revision, worker_count, repository_token)
                           VALUES ($1, $2, $3, NULLIF($4, ''))
                           RETURNING id, repository_url, requested_revision, worker_count, commit_sha,
                                     repository_token IS NOT NULL AS token_present, created_at,
                                     manager_wake_at, manager_wake_reason, error""",
                        repository_url,
                        requested_revision,
                        worker_count,
                        repository_token,
                    )
                for name in task_names:
                    await connection.execute("INSERT INTO tasks (project_id, name) VALUES ($1, $2)", row["id"], name)
        return self._project(row)

    async def get(self, project_id: int) -> Project | None:
        row = await self._pool.fetchrow(
            """SELECT id, repository_url, requested_revision, worker_count, commit_sha,
                      repository_token IS NOT NULL AS token_present, created_at,
                      manager_wake_at, manager_wake_reason, error
               FROM projects WHERE id = $1""",
            project_id,
        )
        return self._project(row) if row else None

    async def list(self) -> list[Project]:
        rows = await self._pool.fetch(
            """SELECT id, repository_url, requested_revision, worker_count, commit_sha,
                      repository_token IS NOT NULL AS token_present, created_at,
                      manager_wake_at, manager_wake_reason, error
               FROM projects ORDER BY created_at DESC, id DESC"""
        )
        return [self._project(row) for row in rows]

    async def list_unfinished(self) -> list[Project]:
        rows = await self._pool.fetch(
            """SELECT id, repository_url, requested_revision, worker_count, commit_sha,
                      repository_token IS NOT NULL AS token_present, created_at,
                      manager_wake_at, manager_wake_reason, error
               FROM projects WHERE error IS NULL ORDER BY created_at, id"""
        )
        return [self._project(row) for row in rows]

    async def get_repository_token(self, project_id: int) -> str | None:
        return await self._pool.fetchval("SELECT repository_token FROM projects WHERE id = $1", project_id)

    async def update_settings(self, project_id: int, worker_count: int, repository_token: str | None) -> Project:
        row = await self._pool.fetchrow(
            """UPDATE projects
               SET worker_count = $2,
                   repository_token = CASE WHEN $3::text IS NULL THEN repository_token ELSE NULLIF($3, '') END
               WHERE id = $1
               RETURNING id, repository_url, requested_revision, worker_count, commit_sha,
                         repository_token IS NOT NULL AS token_present, created_at,
                         manager_wake_at, manager_wake_reason, error""",
            project_id,
            worker_count,
            repository_token,
        )
        if row is None:
            raise KeyError(project_id)
        return self._project(row)

    async def schedule_manager_review(
        self, project_id: int, wake_at: datetime, reason: str,
    ) -> None:
        """Persist the exact next project-manager wake."""
        await self._pool.execute(
            "UPDATE projects SET manager_wake_at = $2, manager_wake_reason = $3 WHERE id = $1",
            project_id, wake_at, reason,
        )

    async def clear_manager_review(self, project_id: int) -> None:
        """Clear a consumed project-manager wake."""
        await self._pool.execute(
            "UPDATE projects SET manager_wake_at = NULL, manager_wake_reason = NULL WHERE id = $1",
            project_id,
        )

    async def set_commit_sha(self, project_id: int, commit_sha: str) -> None:
        await self._pool.execute("UPDATE projects SET commit_sha = $2 WHERE id = $1", project_id, commit_sha)

    async def finish(self, project_id: int, error: str | None = None) -> None:
        await self._pool.execute("UPDATE projects SET error = $2 WHERE id = $1", project_id, error)

    @staticmethod
    def _project(row) -> Project:
        return Project(
            id=row["id"],
            repository_url=row["repository_url"],
            requested_revision=row["requested_revision"],
            worker_count=row["worker_count"],
            commit_sha=row["commit_sha"],
            token_present=row["token_present"],
            created_at=row["created_at"],
            manager_wake_at=row["manager_wake_at"],
            manager_wake_reason=row["manager_wake_reason"],
            error=row["error"],
        )
