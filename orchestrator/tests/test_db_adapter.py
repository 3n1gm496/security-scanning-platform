"""Tests for orchestrator/db_adapter.py covering SQLite connection and wrapper classes."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from orchestrator.db_adapter import (
    _sqlite_connect,
    _adapt_sql,
    get_connection,
    adapt_schema,
    is_postgres,
    _RowProxy,
    _CursorWrapper,
    _ConnectionWrapper,
)

# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def test_is_postgres_default():
    """Without DATABASE_URL set, should not be postgres."""
    # The module is loaded without DATABASE_URL in test env
    assert is_postgres() is False


def test_adapt_sql_sqlite_passthrough():
    """In SQLite mode, SQL should be returned unchanged."""
    sql = "SELECT * FROM scans WHERE id = ?"
    assert _adapt_sql(sql) == sql


def test_adapt_schema_sqlite_passthrough():
    """In SQLite mode, schema should be returned unchanged."""
    schema = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);"
    result = adapt_schema(schema)
    assert result == schema


# ---------------------------------------------------------------------------
# _sqlite_connect
# ---------------------------------------------------------------------------


def test_sqlite_connect_in_memory():
    conn = _sqlite_connect(":memory:")
    assert conn is not None
    conn.close()


def test_sqlite_connect_file(tmp_path):
    db_path = str(tmp_path / "test.db")
    conn = _sqlite_connect(db_path)
    assert conn is not None
    # Verify it's a real connection by executing a query
    cur = conn.cursor()
    cur.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    assert Path(db_path).exists()


def test_sqlite_connect_creates_parent_dirs(tmp_path):
    db_path = str(tmp_path / "nested" / "dir" / "test.db")
    conn = _sqlite_connect(db_path)
    assert conn is not None
    conn.close()
    assert Path(db_path).exists()


def test_sqlite_connect_row_factory():
    """Row factory should be set to sqlite3.Row."""
    conn = _sqlite_connect(":memory:")
    assert conn.row_factory == sqlite3.Row
    conn.close()


# ---------------------------------------------------------------------------
# _RowProxy
# ---------------------------------------------------------------------------


def test_row_proxy_dict_access():
    proxy = _RowProxy({"name": "test", "value": 42})
    assert proxy["name"] == "test"
    assert proxy["value"] == 42


def test_row_proxy_integer_access():
    proxy = _RowProxy({"name": "test", "value": 42})
    assert proxy[0] == "test"
    assert proxy[1] == 42


def test_row_proxy_keys():
    proxy = _RowProxy({"a": 1, "b": 2})
    keys = proxy.keys()
    assert isinstance(keys, list)
    assert "a" in keys
    assert "b" in keys


# ---------------------------------------------------------------------------
# _CursorWrapper (SQLite mode)
# ---------------------------------------------------------------------------


def test_cursor_wrapper_execute():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    raw_cur = raw_conn.cursor()
    wrapper = _CursorWrapper(raw_cur, is_pg=False)
    wrapper.execute("CREATE TABLE t (id INTEGER, name TEXT)")
    wrapper.execute("INSERT INTO t VALUES (?, ?)", (1, "hello"))
    raw_conn.commit()
    wrapper.execute("SELECT * FROM t")
    row = wrapper.fetchone()
    assert row["id"] == 1
    assert row["name"] == "hello"
    raw_conn.close()


def test_cursor_wrapper_fetchall():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    raw_cur = raw_conn.cursor()
    wrapper = _CursorWrapper(raw_cur, is_pg=False)
    wrapper.execute("CREATE TABLE t (id INTEGER)")
    wrapper.executemany("INSERT INTO t VALUES (?)", [(1,), (2,), (3,)])
    raw_conn.commit()
    wrapper.execute("SELECT * FROM t ORDER BY id")
    rows = wrapper.fetchall()
    assert len(rows) == 3
    assert rows[0]["id"] == 1
    raw_conn.close()


def test_cursor_wrapper_fetchone_none():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    raw_cur = raw_conn.cursor()
    wrapper = _CursorWrapper(raw_cur, is_pg=False)
    wrapper.execute("CREATE TABLE t (id INTEGER)")
    raw_conn.commit()
    wrapper.execute("SELECT * FROM t")
    row = wrapper.fetchone()
    assert row is None
    raw_conn.close()


def test_cursor_wrapper_rowcount():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    raw_cur = raw_conn.cursor()
    wrapper = _CursorWrapper(raw_cur, is_pg=False)
    wrapper.execute("CREATE TABLE t (id INTEGER)")
    wrapper.executemany("INSERT INTO t VALUES (?)", [(1,), (2,)])
    raw_conn.commit()
    assert wrapper.rowcount == 2
    raw_conn.close()


def test_cursor_wrapper_executescript():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    raw_cur = raw_conn.cursor()
    wrapper = _CursorWrapper(raw_cur, is_pg=False)
    script = "CREATE TABLE a (id INTEGER); CREATE TABLE b (id INTEGER);"
    wrapper.executescript(script)
    # Verify both tables exist
    wrapper.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    rows = wrapper.fetchall()
    names = [r["name"] for r in rows]
    assert "a" in names
    assert "b" in names
    raw_conn.close()


# ---------------------------------------------------------------------------
# _ConnectionWrapper (SQLite mode)
# ---------------------------------------------------------------------------


def test_connection_wrapper_basic():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    wrapper = _ConnectionWrapper(raw_conn, is_pg=False)
    cur = wrapper.cursor()
    assert cur is not None
    wrapper.close()


def test_connection_wrapper_execute():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    wrapper = _ConnectionWrapper(raw_conn, is_pg=False)
    wrapper.execute("CREATE TABLE t (id INTEGER, val TEXT)")
    wrapper.execute("INSERT INTO t VALUES (?, ?)", (1, "test"))
    wrapper.commit()
    cur = wrapper.execute("SELECT * FROM t")
    row = cur.fetchone()
    assert row["id"] == 1
    wrapper.close()


def test_connection_wrapper_context_manager_commit():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    wrapper = _ConnectionWrapper(raw_conn, is_pg=False)
    with wrapper as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.execute("INSERT INTO t VALUES (?)", (42,))
    # After context manager, data should be committed
    cur = raw_conn.cursor()
    cur.execute("SELECT * FROM t")
    row = cur.fetchone()
    assert row[0] == 42
    raw_conn.close()


def test_connection_wrapper_context_manager_rollback():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    # Create table outside context
    raw_conn.execute("CREATE TABLE t (id INTEGER)")
    raw_conn.commit()
    wrapper = _ConnectionWrapper(raw_conn, is_pg=False)
    with pytest.raises(ValueError):
        with wrapper as conn:
            conn.execute("INSERT INTO t VALUES (?)", (99,))
            raise ValueError("intentional error")
    # After rollback, no data should be present
    cur = raw_conn.cursor()
    cur.execute("SELECT COUNT(*) FROM t")
    count = cur.fetchone()[0]
    assert count == 0
    raw_conn.close()


def test_connection_wrapper_executemany():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    wrapper = _ConnectionWrapper(raw_conn, is_pg=False)
    wrapper.execute("CREATE TABLE t (id INTEGER)")
    wrapper.executemany("INSERT INTO t VALUES (?)", [(1,), (2,), (3,)])
    wrapper.commit()
    cur = wrapper.execute("SELECT COUNT(*) as cnt FROM t")
    row = cur.fetchone()
    assert row["cnt"] == 3
    wrapper.close()


def test_connection_wrapper_executescript():
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row
    wrapper = _ConnectionWrapper(raw_conn, is_pg=False)
    script = "CREATE TABLE x (id INTEGER); INSERT INTO x VALUES (1);"
    wrapper.executescript(script)
    cur = wrapper.execute("SELECT * FROM x")
    row = cur.fetchone()
    assert row["id"] == 1
    wrapper.close()


def test_connection_wrapper_row_factory_setter():
    raw_conn = sqlite3.connect(":memory:")
    wrapper = _ConnectionWrapper(raw_conn, is_pg=False)
    wrapper.row_factory = sqlite3.Row
    assert raw_conn.row_factory == sqlite3.Row
    wrapper.close()


# ---------------------------------------------------------------------------
# get_connection
# ---------------------------------------------------------------------------


def test_get_connection_sqlite(tmp_path, monkeypatch):
    """get_connection should return a working SQLite connection."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("ORCH_DB_PATH", db_path)
    conn = get_connection()
    assert conn is not None
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()
    assert Path(db_path).exists()


def test_get_connection_explicit_path(tmp_path):
    """get_connection with explicit path should use that path."""
    db_path = str(tmp_path / "explicit.db")
    conn = get_connection(db_path=db_path)
    assert conn is not None
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()
    assert Path(db_path).exists()


def test_get_connection_in_memory():
    """get_connection with :memory: should work."""
    conn = get_connection(db_path=":memory:")
    assert conn is not None
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# WAL mode tests (issue #1)
# ---------------------------------------------------------------------------


def test_sqlite_connect_enables_wal_mode(tmp_path):
    """_sqlite_connect must set journal_mode=WAL for file-based databases."""
    db_path = str(tmp_path / "wal_test.db")
    conn = _sqlite_connect(db_path)
    row = conn.execute("PRAGMA journal_mode").fetchone()
    journal_mode = row[0] if row else None
    conn.close()
    assert journal_mode == "wal", f"Expected WAL mode, got: {journal_mode}"


def test_sqlite_connect_in_memory_does_not_raise_wal():
    """_sqlite_connect with :memory: should not raise even though WAL is silently ignored."""
    conn = _sqlite_connect(":memory:")
    # In-memory databases may ignore WAL silently — ensure no exception is raised
    assert conn is not None
    conn.close()


def test_sqlite_connect_sets_synchronous_normal(tmp_path):
    """_sqlite_connect must set synchronous=NORMAL when using WAL mode."""
    db_path = str(tmp_path / "sync_test.db")
    conn = _sqlite_connect(db_path)
    row = conn.execute("PRAGMA synchronous").fetchone()
    # SQLite returns integer: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
    synchronous = row[0] if row else None
    conn.close()
    assert synchronous == 1, f"Expected NORMAL (1) synchronous, got: {synchronous}"
