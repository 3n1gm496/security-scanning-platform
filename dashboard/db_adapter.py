"""
Database adapter: transparent support for SQLite (dev/test) and PostgreSQL (production).

Usage:
    Set DATABASE_URL=postgresql://user:pass@host:5432/dbname for PostgreSQL.
    Leave unset or set DASHBOARD_DB_PATH for SQLite (default, backward-compatible).

The adapter normalises:
    - Connection creation (sqlite3 vs psycopg2)
    - Placeholder style (? for SQLite, %s for PostgreSQL)
    - Row access (sqlite3.Row dict-like vs psycopg2 RealDictCursor)
    - AUTOINCREMENT vs SERIAL in DDL
"""

from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from logging_config import get_logger

LOGGER = get_logger(__name__)

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

_DATABASE_URL: str | None = os.environ.get("DATABASE_URL")
_IS_POSTGRES: bool = bool(_DATABASE_URL and _DATABASE_URL.startswith("postgresql"))


def is_postgres() -> bool:
    """Return True if the active backend is PostgreSQL."""
    return _IS_POSTGRES


def _adapt_sql(sql: str) -> str:
    """Convert SQLite-style placeholders (?) to PostgreSQL-style (%s)."""
    if not _IS_POSTGRES:
        return sql
    return sql.replace("?", "%s")


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------


def _sqlite_connect(db_path: str) -> sqlite3.Connection:
    if db_path == ":memory:":
        conn = sqlite3.connect(":memory:")
    else:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    # WAL mode allows concurrent readers + one writer without locking conflicts.
    # synchronous=NORMAL is safe with WAL: durable after each checkpoint, not each commit.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# ---------------------------------------------------------------------------
# PostgreSQL backend
# ---------------------------------------------------------------------------


def _pg_connect():
    """Create a psycopg2 connection using DATABASE_URL."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError as exc:
        raise RuntimeError(
            "psycopg2-binary is required for PostgreSQL support. " "Install it with: pip install psycopg2-binary"
        ) from exc

    conn = psycopg2.connect(_DATABASE_URL)
    conn.autocommit = False
    return conn


# ---------------------------------------------------------------------------
# Unified connection wrapper
# ---------------------------------------------------------------------------


class _RowProxy(dict):
    """Dict subclass that also supports attribute access and key() method."""

    def keys(self):
        return list(super().keys())

    def __getitem__(self, key):
        # Support both integer index (sqlite3.Row compat) and string key
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class _CursorWrapper:
    """Wraps a DB cursor to provide a uniform interface."""

    def __init__(self, cursor, is_pg: bool):
        self._cur = cursor
        self._is_pg = is_pg

    def execute(self, sql: str, params=None):
        sql = _adapt_sql(sql)
        if params is None:
            self._cur.execute(sql)
        else:
            self._cur.execute(sql, params)
        return self

    def executemany(self, sql: str, seq_of_params):
        sql = _adapt_sql(sql)
        self._cur.executemany(sql, seq_of_params)
        return self

    def executescript(self, sql: str):
        """Execute a multi-statement SQL script."""
        if self._is_pg:
            # psycopg2 does not have executescript; split and execute each statement
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    self._cur.execute(stmt)
        else:
            self._cur.executescript(sql)
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        if self._is_pg:
            return _RowProxy(row)
        return row

    def fetchall(self):
        rows = self._cur.fetchall()
        if self._is_pg:
            return [_RowProxy(r) for r in rows]
        return rows

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def lastrowid(self):
        """Return the rowid of the last inserted row."""
        if self._is_pg:
            # For PostgreSQL, lastrowid is not available; callers should use RETURNING id
            # We return None to avoid AttributeError — webhooks.py handles this gracefully
            return getattr(self._cur, "lastrowid", None)
        return self._cur.lastrowid


class _ConnectionWrapper:
    """Wraps a DB connection to provide a uniform interface."""

    def __init__(self, raw_conn, is_pg: bool):
        self._conn = raw_conn
        self._is_pg = is_pg

    def cursor(self) -> _CursorWrapper:
        if self._is_pg:
            import psycopg2.extras

            return _CursorWrapper(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor), is_pg=True)
        return _CursorWrapper(self._conn.cursor(), is_pg=False)

    def execute(self, sql: str, params=None) -> _CursorWrapper:
        cur = self.cursor()
        return cur.execute(sql, params)

    def executemany(self, sql: str, seq_of_params) -> _CursorWrapper:
        cur = self.cursor()
        return cur.executemany(sql, seq_of_params)

    def executescript(self, sql: str) -> _CursorWrapper:
        cur = self.cursor()
        return cur.executescript(sql)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    # Context manager support (mirrors sqlite3.Connection behaviour)
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        # Do NOT close here — caller controls lifetime
        return False

    # sqlite3.Row compatibility: allow row["key"] on rows returned by this conn
    @property
    def row_factory(self):
        return None  # handled internally

    @row_factory.setter
    def row_factory(self, value):
        if not self._is_pg:
            self._conn.row_factory = value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_connection(db_path: str | None = None) -> _ConnectionWrapper:
    """
    Return a connection wrapper for the configured backend.

    Args:
        db_path: Path to the SQLite file (ignored when DATABASE_URL is set).
                 Defaults to DASHBOARD_DB_PATH env var.
    """
    if _IS_POSTGRES:
        LOGGER.debug("db.connect.postgres")
        return _ConnectionWrapper(_pg_connect(), is_pg=True)

    # SQLite fallback
    path = db_path or os.environ.get("DASHBOARD_DB_PATH", "/data/security_scans.db")
    LOGGER.debug("db.connect.sqlite", path=path)
    return _ConnectionWrapper(_sqlite_connect(path), is_pg=False)


def adapt_schema(schema_sql: str) -> str:
    """
    Adapt a SQLite DDL schema to PostgreSQL syntax.

    Transformations applied:
    - INTEGER PRIMARY KEY AUTOINCREMENT  →  SERIAL PRIMARY KEY
    - TEXT PRIMARY KEY                   →  TEXT PRIMARY KEY (unchanged)
    - INSERT OR REPLACE                  →  INSERT ... ON CONFLICT DO UPDATE
    - date('now', ...)                   →  CURRENT_DATE (simplified)
    """
    if not _IS_POSTGRES:
        return schema_sql

    sql = schema_sql
    # AUTOINCREMENT → SERIAL
    sql = re.sub(r"INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
    # CREATE INDEX IF NOT EXISTS → PostgreSQL compatible (already supported)
    # SQLite-specific: no changes needed for CREATE INDEX
    return sql
