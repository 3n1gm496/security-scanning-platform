"""
Pytest configuration and shared fixtures for dashboard tests.
"""

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

# Set default test database path before any imports
_test_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
_test_db.close()
os.environ.setdefault("DASHBOARD_DB_PATH", _test_db.name)


@pytest.fixture(scope="function", autouse=True)
def isolated_db():
    """
    Ensure each test gets a clean database by dropping and recreating tables.
    """
    db_path = os.environ["DASHBOARD_DB_PATH"]

    # Clean existing tables
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Drop all tables except sqlite internal tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = cursor.fetchall()
    for table in tables:
        cursor.execute(f"DROP TABLE IF EXISTS {table[0]}")

    conn.commit()
    conn.close()

    # Recreate the schema so the app can start cleanly
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import db as _db
    _db.init_db(db_path)

    # Also initialise auxiliary tables created by app-level helpers
    try:
        import app as _app
        _app.init_finding_management_tables()
        _app.init_rbac_tables()
        _app.init_webhook_tables()
    except Exception:
        pass

    yield db_path

    # Reset the in-process rate limiter after each test to prevent
    # state leaking between tests (e.g. 429 Too Many Requests).
    try:
        import app as _app
        _app._rate_buckets.clear()
    except Exception:
        pass
