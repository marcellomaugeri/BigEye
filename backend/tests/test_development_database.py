"""Focused checks for the local PostgreSQL development foundation."""

from pathlib import Path
import os
import re
import subprocess
import tempfile
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
        self.assertIn("./backend/database/schema.sql:/docker-entrypoint-initdb.d/schema.sql:ro", compose)
        self.assertIn("healthcheck:", compose)
        self.assertNotIn("0.0.0.0", compose)

    def test_release_schema_has_only_required_tables_and_no_enum_types(self) -> None:
        schema_file = ROOT / "backend/database/schema.sql"
        self.assertTrue(schema_file.is_file())
        if not schema_file.is_file():
            return
        schema = schema_file.read_text()

        for table in ("projects", "tasks", "assets", "campaigns", "coverage_evidence", "findings"):
            self.assertIn(f"CREATE TABLE {table}", schema)
        for table in ("coverage_source_summaries", "coverage_branch_evidence", "coverage_function_evidence"):
            self.assertIn(f"CREATE TABLE {table}", schema)
        self.assertNotIn("CREATE TYPE", schema)
        self.assertNotIn("metadata", schema.lower())

    def test_coverage_schema_keeps_exact_build_totals_without_persisted_activity_duplicates(self) -> None:
        schema = (ROOT / "backend/database/schema.sql").read_text()

        summaries = self._columns_for("coverage_source_summaries", schema)
        branches = self._columns_for("coverage_branch_evidence", schema)
        campaigns = self._columns_for("campaigns", schema)

        self.assertTrue({
            "commit_sha", "coverage_asset_id", "source_path", "source_sha256",
            "covered_lines", "total_lines", "covered_functions", "total_functions",
            "covered_branches", "total_branches",
        } <= summaries)
        self.assertTrue({"line_number", "branch_index", "outcome_index", "covered"} <= branches)
        self.assertNotIn("activity", campaigns)
        self.assertNotIn("type", campaigns)

    def test_projects_store_manager_review_deadlines_without_a_user_pause_state(self) -> None:
        schema = (ROOT / "backend/database/schema.sql").read_text()

        project_columns = self._columns_for("projects", schema)

        self.assertIn("manager_wake_at", project_columns)
        self.assertIn("manager_wake_reason", project_columns)
        self.assertNotIn("paused_at", project_columns)

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
        self.assertIn('docker compose -f "$compose_file" exec -T postgres psql', reset_script)
        self.assertNotIn('psql "$database_url"', reset_script)
        self.assertIn('project_dir=', reset_script)

    def test_documented_key_export_and_vite_proxy_are_explicit(self) -> None:
        readme = (ROOT / "README.md").read_text()
        vite = (ROOT / "frontend/vite.config.ts").read_text()
        self.assertIn("set -a; . ./.env; set +a", readme)
        self.assertIn("'/api': 'http://127.0.0.1:8000'", vite)
        with tempfile.TemporaryDirectory() as temporary_directory:
            environment_file = Path(temporary_directory) / ".env"
            environment_file.write_text("OPENAI_API_KEY=contract-test-key\n")
            result = subprocess.run(
                ["sh", "-c", 'set -a; . "$1"; set +a; test "$OPENAI_API_KEY" = contract-test-key', "sh", str(environment_file)],
                check=False,
            )
        self.assertEqual(result.returncode, 0)

    def test_reset_rejects_remote_databases_before_invoking_psql(self) -> None:
        reset_script = ROOT / "backend/database/reset.sh"

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            psql = temporary_path / "psql"
            psql.write_text(
                "#!/usr/bin/env sh\n"
                "touch \"$BIGEYE_PSQL_CALLED\"\n"
                "printf 'bigeye\\n'\n"
            )
            psql.chmod(0o755)
            psql_called = temporary_path / "psql-called"
            environment = {
                **os.environ,
                "DATABASE_URL": "postgresql://bigeye:bigeye@db.example.test:5433/bigeye",
                "BIGEYE_PSQL_CALLED": str(psql_called),
                "PATH": f"{temporary_path}{os.pathsep}{os.environ['PATH']}",
            }

            result = subprocess.run(
                ["sh", str(reset_script)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            psql_was_called = psql_called.exists()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback", result.stderr)
        self.assertFalse(psql_was_called)

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
