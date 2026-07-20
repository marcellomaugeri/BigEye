"""PostgreSQL idempotency for deterministically processed campaign artifacts."""

from pathlib import PurePosixPath

from backend.models.campaign_artifact import ProcessedCampaignArtifact


class CampaignArtifactRepository:
    def __init__(self, pool):
        self._pool = pool

    async def get(
        self, project_id: int, campaign_id: int, kind: str, content_sha256: str,
    ) -> ProcessedCampaignArtifact | None:
        row = await self._pool.fetchrow(
            """SELECT project_id, campaign_id, kind, content_sha256, accepted,
                      evidence_id, reason, durable_relative_path
               FROM campaign_artifacts
               WHERE project_id = $1 AND campaign_id = $2 AND kind = $3
                 AND content_sha256 = $4""",
            project_id, campaign_id, kind, content_sha256,
        )
        return self._record(row) if row else None

    async def record(self, value: ProcessedCampaignArtifact) -> ProcessedCampaignArtifact:
        if not isinstance(value, ProcessedCampaignArtifact):
            raise TypeError("campaign artifact repository requires a validated record")
        row = await self._pool.fetchrow(
            """INSERT INTO campaign_artifacts
                      (project_id, campaign_id, kind, content_sha256, accepted,
                       evidence_id, reason, durable_relative_path)
               SELECT $1, $2, $3, $4, $5, $6, $7, $8
               FROM campaigns
               WHERE id = $2 AND project_id = $1
               ON CONFLICT (project_id, campaign_id, kind, content_sha256) DO NOTHING
               RETURNING project_id, campaign_id, kind, content_sha256, accepted,
                         evidence_id, reason, durable_relative_path""",
            value.project_id, value.campaign_id, value.kind, value.content_sha256,
            value.accepted, value.evidence_id, value.reason, value.durable_relative_path,
        )
        if row is not None:
            return self._record(row)
        existing = await self.get(
            value.project_id, value.campaign_id, value.kind, value.content_sha256,
        )
        if existing != value:
            raise ValueError("campaign artifact identity already has different evidence")
        return existing

    async def accepted_count(self, project_id: int, campaign_id: int, kind: str) -> int:
        value = await self._pool.fetchval(
            """SELECT COUNT(*) FROM campaign_artifacts
               WHERE project_id = $1 AND campaign_id = $2 AND kind = $3 AND accepted IS TRUE""",
            project_id, campaign_id, kind,
        )
        count = int(value)
        if count < 0:
            raise ValueError("campaign artifact count is invalid")
        return count

    async def cursors(self, project_id: int, campaign_id: int) -> dict[str, tuple[int, str]]:
        rows = await self._pool.fetch(
            """SELECT kind, last_seen_ns, last_name FROM campaign_artifact_cursors
               WHERE project_id = $1 AND campaign_id = $2 ORDER BY kind""",
            project_id, campaign_id,
        )
        values = {}
        for row in rows:
            kind, observed_ns, name = str(row["kind"]), int(row["last_seen_ns"]), str(row["last_name"])
            self._validate_cursor(kind, observed_ns, name)
            if kind in values:
                raise ValueError("campaign artifact cursor identity is duplicated")
            values[kind] = (observed_ns, name)
        return values

    async def advance_cursors(
        self, project_id: int, campaign_id: int, values: tuple[tuple[str, int, str], ...],
    ) -> None:
        if (
            type(project_id) is not int or project_id <= 0
            or type(campaign_id) is not int or campaign_id <= 0
            or not isinstance(values, tuple)
            or len(values) > 2
            or any(not isinstance(item, tuple) or len(item) != 3 for item in values)
            or len({item[0] for item in values}) != len(values)
        ):
            raise ValueError("campaign artifact cursors are invalid")
        for kind, observed_ns, name in values:
            self._validate_cursor(kind, observed_ns, name)
        for kind, observed_ns, name in values:
            selected = await self._pool.fetchval(
                """INSERT INTO campaign_artifact_cursors
                          (project_id, campaign_id, kind, last_seen_ns, last_name)
                   SELECT $1, $2, $3, $4, $5 FROM campaigns
                   WHERE id = $2 AND project_id = $1
                   ON CONFLICT (project_id, campaign_id, kind) DO UPDATE
                   SET last_name = EXCLUDED.last_name,
                       last_seen_ns = EXCLUDED.last_seen_ns
                   RETURNING last_name""",
                project_id, campaign_id, kind, observed_ns, name,
            )
            if selected is None:
                raise ValueError("campaign artifact cursor belongs to another campaign")

    @staticmethod
    def _validate_cursor(kind: str, observed_ns: int, name: str) -> None:
        path = PurePosixPath(name)
        if (
            kind not in {"queue", "crashes"}
            or type(observed_ns) is not int or observed_ns < 0
            or not isinstance(name, str) or len(name) > 500
            or (not name and observed_ns != 0)
            or path.is_absolute() or (name and len(path.parts) != 1)
            or (name and path.parts[0] in {".", ".."}) or "\x00" in name
        ):
            raise ValueError("campaign artifact cursor is invalid")

    @staticmethod
    def _record(row) -> ProcessedCampaignArtifact:
        return ProcessedCampaignArtifact(**dict(row))
