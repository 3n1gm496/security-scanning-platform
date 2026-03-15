"""
Database adapter for the orchestrator: transparent support for SQLite and PostgreSQL.

The orchestrator uses ORCH_DB_PATH for SQLite or DATABASE_URL for PostgreSQL.
This module mirrors the dashboard/db_adapter.py interface.
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

from orchestrator.logging_config import get_logger

LOGGER = get_logger(__name__)

_DATABASE_URL: str | None = os.environ.get("DATABASE_URL")
_IS_POSTGRES: bool = bool(_DATABASE_URL and _DATABASE_URL.startswith("postgresql"))


def is_postgres() -> bool:
    return _IS_POSTGRES


def _adapt_sql(sql: str) -> str:
    """Convert SQLite-style placeholders (?) to PostgreSQL-style (%s).

    Skips over string literals so that question marks inside quoted
    values are preserved.
    """
    if not _IS_POSTGRES:
        return sql
    result = []
    in_quote = False
    quote_char = None
    for ch in sql:
        if in_quote:
            result.append(ch)
            if ch == quote_char:
                in_quote = False
        elif ch in ("'", '"'):
            in_quote = True
            quote_char = ch
            result.append(ch)
        elif ch == "?":
            result.append("%s")
        else:
            result.append(ch)
    return "".join(result)


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
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _pg_connect():
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


class _RowProxy(dict):
    def keys(self):
        return list(super().keys())

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class _CursorWrapper:
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
        if self._is_pg:
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


class _ConnectionWrapper:
    def __init__(self, raw_conn, is_pg: bool):
        self._conn = raw_conn
        self._is_pg = is_pg

    def cursor(self) -> _CursorWrapper:
        if self._is_pg:
            import psycopg2.extras

            return _CursorWrapper(
                self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor),
                is_pg=True,
            )
        return _CursorWrapper(self._conn.cursor(), is_pg=False)

    def execute(self, sql: str, params=None) -> _CursorWrapper:
        return self.cursor().execute(sql, params)

    def executemany(self, sql: str, seq_of_params) -> _CursorWrapper:
        return self.cursor().executemany(sql, seq_of_params)

    def executescript(self, sql: str) -> _CursorWrapper:
        return self.cursor().executescript(sql)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        if self._is_pg:
            self.close()
        return False

    @property
    def row_factory(self):
        return None

    @row_factory.setter
    def row_factory(self, value):
        if not self._is_pg:
            self._conn.row_factory = value


def get_connection(db_path: str | None = None) -> _ConnectionWrapper:
    """
    Return a connection wrapper for the configured backend.

    Args:
        db_path: Path to the SQLite file (ignored when DATABASE_URL is set).
                 Defaults to ORCH_DB_PATH env var.
    """
    if _IS_POSTGRES:
        LOGGER.debug("db.connect", backend="postgresql")
        return _ConnectionWrapper(_pg_connect(), is_pg=True)

    path = db_path or os.environ.get("ORCH_DB_PATH", "/data/security_scans.db")
    LOGGER.debug("db.connect", backend="sqlite", path=path)
    return _ConnectionWrapper(_sqlite_connect(path), is_pg=False)


def adapt_schema(schema_sql: str) -> str:
    """Adapt SQLite DDL to PostgreSQL syntax."""
    if not _IS_POSTGRES:
        return schema_sql
    sql = schema_sql
    sql = re.sub(
        r"INTEGER PRIMARY KEY AUTOINCREMENT",
        "SERIAL PRIMARY KEY",
        sql,
        flags=re.IGNORECASE,
    )
    sql = re.sub(r"INSERT\s+OR\s+REPLACE\s+INTO", "INSERT INTO", sql, flags=re.IGNORECASE)
    return sql
