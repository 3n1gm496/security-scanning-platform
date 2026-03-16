"""
Tests for schema consistency between orchestrator and dashboard,
and for adapt_schema() PostgreSQL transformations.
"""

import sqlite3
import sys
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
sys.path.insert(0, str(root.parent))

from common.schema import MIGRATIONS, SCHEMA_SQL


def _create_db(schema_sql: str) -> dict:
    """Create an in-memory SQLite DB from schema and return sqlite_master rows."""
    conn = sqlite3.connect(":memory:")
    conn.executescript(schema_sql)
    rows = conn.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY type, name"
    ).fetchall()
    conn.close()
    return {(r[0], r[1]): r[2] for r in rows}


class TestSchemaConsistency:
    """Both components now import from common.schema — verify the schema is valid."""

    def test_schema_creates_scans_table(self):
        master = _create_db(SCHEMA_SQL)
        assert ("table", "scans") in master

    def test_schema_creates_findings_table(self):
        master = _create_db(SCHEMA_SQL)
        assert ("table", "findings") in master

    def test_schema_creates_schema_migrations_table(self):
        master = _create_db(SCHEMA_SQL)
        assert ("table", "schema_migrations") in master

    def test_schema_creates_indexes(self):
        master = _create_db(SCHEMA_SQL)
        expected_indexes = [
            "idx_findings_scan_id",
            "idx_findings_severity",
            "idx_findings_tool",
            "idx_findings_target_name",
            "idx_scans_created_at",
        ]
        for idx_name in expected_indexes:
            assert ("index", idx_name) in master, f"Missing index: {idx_name}"

    def test_default_values_present(self):
        """Verify that DEFAULT values are set on the four previously-divergent columns."""
        assert "DEFAULT ''" in SCHEMA_SQL
        assert "DEFAULT '{}'" in SCHEMA_SQL
        assert "DEFAULT '[]'" in SCHEMA_SQL

    def test_migrations_list_not_empty(self):
        assert len(MIGRATIONS) >= 1
        assert MIGRATIONS[0][0] == 1  # version
        assert MIGRATIONS[0][1] == "baseline marker"

    def test_alter_table_migrations_exist_for_git_sha_and_tenant_id(self):
        migration_sql = "\n".join(sql for version, _desc, sql in MIGRATIONS if version in (5, 6))
        assert "ADD COLUMN git_sha" in migration_sql
        assert "ADD COLUMN tenant_id" in migration_sql

    def test_orchestrator_imports_same_schema(self):
        """Orchestrator's storage.py should use the same SCHEMA_SQL."""
        from orchestrator.storage import SCHEMA_SQL as orch_schema

        assert orch_schema is SCHEMA_SQL

    def test_dashboard_uses_same_schema(self):
        """Dashboard's db.py should use the same SCHEMA_SQL."""
        from db import SCHEMA_SQL as dash_schema

        assert dash_schema is SCHEMA_SQL


class TestAdaptSchemaPostgres:
    """Test adapt_schema() transformations for PostgreSQL compatibility."""

    def test_autoincrement_to_serial(self):
        import importlib
        import os

        # Temporarily set DATABASE_URL to trigger PostgreSQL mode
        old = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/testdb"
        try:
            # Re-import to pick up new env var
            import db_adapter

            importlib.reload(db_adapter)
            result = db_adapter.adapt_schema("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)")
            assert "SERIAL PRIMARY KEY" in result
            assert "AUTOINCREMENT" not in result
        finally:
            if old is None:
                del os.environ["DATABASE_URL"]
            else:
                os.environ["DATABASE_URL"] = old
            importlib.reload(db_adapter)

    def test_insert_or_replace_transformed(self):
        import importlib
        import os

        old = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/testdb"
        try:
            import db_adapter

            importlib.reload(db_adapter)
            result = db_adapter.adapt_schema("INSERT OR REPLACE INTO foo (a, b) VALUES (1, 2)")
            assert "INSERT INTO" in result
            assert "OR REPLACE" not in result
            assert "ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b" in result
        finally:
            if old is None:
                del os.environ["DATABASE_URL"]
            else:
                os.environ["DATABASE_URL"] = old
            importlib.reload(db_adapter)

    def test_placeholder_adaptation_preserves_escaped_quotes(self):
        import importlib
        import os

        old = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/testdb"
        try:
            import db_adapter

            importlib.reload(db_adapter)
            result = db_adapter._adapt_sql("SELECT 'it''s ?', \"a\"\"b?\", ?")
            assert result == "SELECT 'it''s ?', \"a\"\"b?\", %s"
        finally:
            if old is None:
                del os.environ["DATABASE_URL"]
            else:
                os.environ["DATABASE_URL"] = old
            importlib.reload(db_adapter)

    def test_executescript_split_ignores_semicolons_in_strings(self):
        import importlib
        import os

        old = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/testdb"
        try:
            import db_adapter

            importlib.reload(db_adapter)
            statements = db_adapter._split_sql_statements(
                "INSERT INTO test VALUES ('a; b'); INSERT INTO test VALUES ('c'';d');"
            )
            assert statements == [
                "INSERT INTO test VALUES ('a; b')",
                "INSERT INTO test VALUES ('c'';d')",
            ]
        finally:
            if old is None:
                del os.environ["DATABASE_URL"]
            else:
                os.environ["DATABASE_URL"] = old
            importlib.reload(db_adapter)


class TestSQLitePooling:
    def test_reset_pool_closes_previous_connection_when_path_changes(self, tmp_path):
        import db_adapter

        first_path = str(tmp_path / "first.db")
        second_path = str(tmp_path / "second.db")

        first_conn = db_adapter.get_connection(first_path)
        first_conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        first_conn.commit()
        raw_first = first_conn._conn

        second_conn = db_adapter.get_connection(second_path)
        second_conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        second_conn.commit()

        with pytest.raises(sqlite3.ProgrammingError):
            raw_first.execute("SELECT 1")

        db_adapter.reset_pool()
