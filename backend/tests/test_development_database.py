"""Focused checks for the local PostgreSQL development foundation."""

from pathlib import Path
import re
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


class DevelopmentDatabaseTests(unittest.TestCase):
    def test_connection_uses_the_local_development_defaults(self) -> None:
        connection_file = ROOT / "backend/database/connection.py"
        self.assertTrue(connection_file.is_file())
        if not connection_file.is_file():
            return

        from backend.database.connection import database_url

        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(
                database_url(),
                "postgresql://bigeye:bigeye@127.0.0.1:5433/bigeye",
            )

    def test_compose_runs_only_loopback_postgres_with_the_required_settings(self) -> None:
        compose_file = ROOT / "compose.yaml"
        self.assertTrue(compose_file.is_file())
        if not compose_file.is_file():
            return
        compose = compose_file.read_text()

        self.assertIn("postgres:18.4-bookworm", compose)
        self.assertIn("platform: linux/amd64", compose)
        self.assertIn("127.0.0.1:${BIGEYE_POSTGRES_PORT:-5433}:5432", compose)
        self.assertIn("PGDATA: /var/lib/postgresql/18/docker", compose)
        self.assertIn("./workspace/postgres:/var/lib/postgresql", compose)
        self.assertIn("healthcheck:", compose)
        self.assertNotIn("0.0.0.0", compose)

    def test_schema_contains_only_the_minimal_project_and_task_fields(self) -> None:
        schema_file = ROOT / "backend/database/schema.sql"
        self.assertTrue(schema_file.is_file())
        if not schema_file.is_file():
            return
        schema = schema_file.read_text()

        project_columns = self._columns_for("projects", schema)
        task_columns = self._columns_for("tasks", schema)

        self.assertEqual(
            project_columns,
            {"id", "repository_url", "worker_count", "commit_sha", "created_at", "finished_at", "error"},
        )
        self.assertEqual(
            task_columns,
            {"id", "project_id", "name", "created_at", "finished_at", "error"},
        )

    def test_tasks_reference_projects_with_a_foreign_key(self) -> None:
        schema_file = ROOT / "backend/database/schema.sql"
        self.assertTrue(schema_file.is_file())
        if not schema_file.is_file():
            return
        schema = schema_file.read_text()

        self.assertRegex(
            schema,
            r"FOREIGN\s+KEY\s*\(project_id\)\s+REFERENCES\s+projects\s*\(id\)",
        )

    def test_reset_is_limited_to_the_bigeye_development_schema(self) -> None:
        reset_file = ROOT / "backend/database/reset.sh"
        self.assertTrue(reset_file.is_file())
        if not reset_file.is_file():
            return
        reset_script = reset_file.read_text()

        self.assertIn('current_database()', reset_script)
        self.assertIn('"$database_name" != "bigeye"', reset_script)
        self.assertIn("DROP SCHEMA IF EXISTS public CASCADE", reset_script)
        self.assertNotIn("DROP DATABASE", reset_script)
        self.assertNotIn("dropdb", reset_script)

    @staticmethod
    def _columns_for(table: str, schema: str) -> set[str]:
        match = re.search(
            rf"CREATE\s+TABLE\s+{table}\s*\((.*?)\);",
            schema,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if match is None:
            return set()

        return {
            line.strip().split()[0]
            for line in match.group(1).splitlines()
            if line.strip() and not line.lstrip().upper().startswith(("PRIMARY", "FOREIGN", "CHECK"))
        }


if __name__ == "__main__":
    unittest.main()
