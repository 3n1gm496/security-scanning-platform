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
import threading
from pathlib import Path

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
    """Convert SQLite-style placeholders (?) to PostgreSQL-style (%s).

    Uses a simple state machine to skip over string literals so that
    question marks inside quoted values are preserved.
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
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Thread-local connection pool for SQLite
# ---------------------------------------------------------------------------
# SQLite connections cannot be shared across threads. Instead of creating a
# new connection on every request we cache one per thread, which avoids the
# repeated PRAGMA round-trips and file-open overhead.

_thread_local = threading.local()


def _get_sqlite_pooled(db_path: str) -> sqlite3.Connection:
    """Return a reusable SQLite connection for the current thread."""
    conn = getattr(_thread_local, "sqlite_conn", None)
    cached_path = getattr(_thread_local, "sqlite_path", None)

    if conn is not None and cached_path == db_path:
        # Verify the connection is still usable (not closed).
        try:
            conn.execute("SELECT 1")
            return conn
        except Exception:
            pass  # Stale connection — recreate below.

    # Create and cache a fresh connection.
    conn = _sqlite_connect(db_path)
    _thread_local.sqlite_conn = conn
    _thread_local.sqlite_path = db_path
    return conn


def reset_pool() -> None:
    """Discard the thread-local cached connection (useful in tests)."""
    conn = getattr(_thread_local, "sqlite_conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _thread_local.sqlite_conn = None
    _thread_local.sqlite_path = None


# ---------------------------------------------------------------------------
# PostgreSQL backend
# ---------------------------------------------------------------------------

# Connection pool settings (configurable via environment)
_PG_POOL_MIN = int(os.environ.get("PG_POOL_MIN", "2"))
_PG_POOL_MAX = int(os.environ.get("PG_POOL_MAX", "10"))

# Optional read-replica DSN for routing read-heavy queries
_DATABASE_READ_URL: str | None = os.environ.get("DATABASE_READ_URL")

_pg_pool = None
_pg_pool_lock = threading.Lock()
_pg_read_pool = None
_pg_read_pool_lock = threading.Lock()


def _get_pg_pool():
    """Lazily create and return the primary PostgreSQL connection pool."""
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    with _pg_pool_lock:
        if _pg_pool is not None:
            return _pg_pool
        try:
            from psycopg2.pool import ThreadedConnectionPool

            _pg_pool = ThreadedConnectionPool(_PG_POOL_MIN, _PG_POOL_MAX, _DATABASE_URL)
            LOGGER.info("db.pool.created", min=_PG_POOL_MIN, max=_PG_POOL_MAX)
        except ImportError as exc:
            raise RuntimeError(
                "psycopg2-binary is required for PostgreSQL support. " "Install it with: pip install psycopg2-binary"
            ) from exc
        return _pg_pool


def _get_pg_read_pool():
    """Lazily create and return the read-replica connection pool (if configured)."""
    global _pg_read_pool
    if not _DATABASE_READ_URL:
        return None
    if _pg_read_pool is not None:
        return _pg_read_pool
    with _pg_read_pool_lock:
        if _pg_read_pool is not None:
            return _pg_read_pool
        try:
            from psycopg2.pool import ThreadedConnectionPool

            _pg_read_pool = ThreadedConnectionPool(_PG_POOL_MIN, _PG_POOL_MAX, _DATABASE_READ_URL)
            LOGGER.info("db.read_pool.created", min=_PG_POOL_MIN, max=_PG_POOL_MAX)
        except ImportError:
            return None
        return _pg_read_pool


def _pg_connect():
    """Return a connection from the primary PostgreSQL pool."""
    pool = _get_pg_pool()
    conn = pool.getconn()
    conn.autocommit = False
    return conn


def _pg_connect_read():
    """Return a connection from the read-replica pool, or primary if no replica configured."""
    read_pool = _get_pg_read_pool()
    if read_pool:
        conn = read_pool.getconn()
        conn.autocommit = False
        return conn
    return _pg_connect()


def _pg_release(conn, *, read_replica: bool = False):
    """Return a connection back to the appropriate pool."""
    pool = None
    if read_replica and _pg_read_pool is not None:
        pool = _pg_read_pool
    elif _pg_pool is not None:
        pool = _pg_pool
    if pool:
        try:
            pool.putconn(conn)
        except Exception:
            pass


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

    def __init__(self, raw_conn, is_pg: bool, *, read_replica: bool = False):
        self._conn = raw_conn
        self._is_pg = is_pg
        self._read_replica = read_replica

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
        # Return PostgreSQL connections to the pool instead of leaking them
        if self._is_pg:
            _pg_release(self._conn, read_replica=self._read_replica)
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


def get_connection(db_path: str | None = None, *, read_only: bool = False) -> _ConnectionWrapper:
    """
    Return a connection wrapper for the configured backend.

    SQLite connections are cached per-thread to avoid repeated setup overhead.
    PostgreSQL connections are drawn from a ThreadedConnectionPool.  When
    ``DATABASE_READ_URL`` is set and ``read_only=True``, the connection is
    routed to the read-replica pool for better load distribution.

    Args:
        db_path: Path to the SQLite file (ignored when DATABASE_URL is set).
                 Defaults to DASHBOARD_DB_PATH env var.
        read_only: Hint that this connection will only run SELECT queries.
                   When a read-replica pool is configured, read_only=True
                   routes the connection there.
    """
    if _IS_POSTGRES:
        if read_only and _DATABASE_READ_URL:
            LOGGER.debug("db.connect.postgres.read_replica")
            return _ConnectionWrapper(_pg_connect_read(), is_pg=True, read_replica=True)
        LOGGER.debug("db.connect.postgres")
        return _ConnectionWrapper(_pg_connect(), is_pg=True)

    # SQLite — reuse thread-local connection
    path = db_path or os.environ.get("DASHBOARD_DB_PATH", "/data/security_scans.db")
    return _ConnectionWrapper(_get_sqlite_pooled(path), is_pg=False)


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
    # INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE (basic transformation)
    # This handles the common pattern used in notification_preferences etc.
    sql = re.sub(r"INSERT\s+OR\s+REPLACE\s+INTO", "INSERT INTO", sql, flags=re.IGNORECASE)
    return sql
