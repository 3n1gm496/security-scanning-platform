"""
Pytest configuration and shared fixtures for dashboard tests.
"""

import asyncio
import os
import sqlite3
import tempfile
from pathlib import Path

import fastapi.testclient as fastapi_testclient
import httpx
import pytest
import starlette.testclient as starlette_testclient

# Ensure real bcrypt is loaded before test modules that may install a fallback
# stub when "bcrypt" is missing from sys.modules.
try:
    import bcrypt  # noqa: F401
except Exception:
    pass

# Set default test database path before any imports
_test_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
_test_db.close()
os.environ.setdefault("DASHBOARD_DB_PATH", _test_db.name)
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_SESSION_SECRET", "test-session-secret")
os.environ.setdefault("DASHBOARD_DISABLE_LIFESPAN", "1")
os.environ.setdefault("DASHBOARD_TEST_CSRF_TOKEN", "test-csrf-token")


class SyncASGITestClient:
    """Minimal sync test client backed by httpx.ASGITransport.

    Starlette's TestClient currently hangs in this project because of an
    interaction with the app stack/lifecycle. For these tests we only need
    request/response behavior, cookies, and mutable default headers.
    """

    __test__ = False

    def __init__(self, app, base_url="http://testserver", headers=None, cookies=None, **_kwargs):
        self.app = app
        self.base_url = base_url
        self.headers = dict(headers or {})
        self.cookies = httpx.Cookies(cookies)

    async def _request_async(self, method, url, **kwargs):
        follow_redirects = kwargs.pop("follow_redirects", False)
        request_headers = dict(self.headers)
        request_headers.update(kwargs.pop("headers", {}) or {})
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=self.base_url,
            headers=request_headers,
            cookies=self.cookies,
            follow_redirects=follow_redirects,
        ) as client:
            response = await client.request(method, url, **kwargs)
            self.cookies = client.cookies
            return response

    def request(self, method, url, **kwargs):
        return asyncio.run(self._request_async(method, url, **kwargs))

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


fastapi_testclient.TestClient = SyncASGITestClient
starlette_testclient.TestClient = SyncASGITestClient


@pytest.fixture(scope="function", autouse=True)
def isolated_db():
    """
    Ensure each test gets a clean database by dropping and recreating tables.
    """
    db_path = os.environ["DASHBOARD_DB_PATH"]

    # Discard any pooled connection so it picks up the fresh schema.
    try:
        import db_adapter as _da

        _da.reset_pool()
    except Exception:
        pass

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
        import rate_limit as _rl

        _rl._rate_buckets.clear()
    except Exception:
        pass


def login_with_csrf(client, username="testuser", password="testpass"):
    """Log in and set the CSRF token header on the client for subsequent requests."""
    client.post("/login", data={"username": username, "password": password})
    token = os.environ.get("DASHBOARD_TEST_CSRF_TOKEN", "test-csrf-token")
    client.headers["X-CSRF-Token"] = token
    return client
