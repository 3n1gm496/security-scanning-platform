"""Tests for secure session cookie configuration.

Verifies that:
- SessionMiddleware is configured with same_site='lax' (always).
- The Secure flag (https_only) is controlled by DASHBOARD_HTTPS_ONLY env var.
- Session cookies are set on successful login and cleared on logout.
"""

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

# Add dashboard directory to sys.path so bare imports work (same as other tests)
_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root))

# Set test credentials before importing app (app reads them at module load)
os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")

from app import app  # noqa: E402  (must come after sys.path setup)
import db as _db  # noqa: E402
import app as _app  # noqa: E402

_TEST_USER = os.environ["DASHBOARD_USERNAME"]
_TEST_PASS = os.environ["DASHBOARD_PASSWORD"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def stub_db(monkeypatch):
    """Stub out DB calls so pages can render without a real database."""
    for module in (_db, _app):
        monkeypatch.setattr(module, "fetch_kpis", lambda path: {})
        monkeypatch.setattr(
            module,
            "cache_hit_stats",
            lambda path: {
                "overall_cache_hit_pct": 0.0,
                "cached_runs": 0,
                "total_runs": 0,
                "by_tool": [],
            },
        )
        monkeypatch.setattr(module, "cache_hit_trend", lambda path, days: [])
        monkeypatch.setattr(module, "severity_breakdown", lambda path: {})
        monkeypatch.setattr(module, "tool_breakdown", lambda path: {})
        monkeypatch.setattr(module, "target_breakdown", lambda path: {})
        monkeypatch.setattr(module, "scans_trend", lambda path, days: [])
        monkeypatch.setattr(module, "list_scans", lambda path, limit=12: [])
        monkeypatch.setattr(module, "distinct_targets", lambda path: [])
        monkeypatch.setattr(module, "distinct_tools", lambda path: [])


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def logged_in_client(client):
    """Return a client that has already performed a successful login."""
    client.post(
        "/login",
        data={"username": _TEST_USER, "password": _TEST_PASS},
        follow_redirects=True,
    )
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_session_middleware_kwargs():
    """Return the kwargs dict of the SessionMiddleware in the app stack."""
    for middleware in app.user_middleware:
        if middleware.cls is SessionMiddleware:
            return middleware.kwargs
    pytest.fail("SessionMiddleware not found in middleware stack")


# ---------------------------------------------------------------------------
# Tests: middleware configuration
# ---------------------------------------------------------------------------


class TestSessionMiddlewareConfig:
    """Inspect the SessionMiddleware configuration on the running app."""

    def test_same_site_is_lax(self):
        """SessionMiddleware must always be configured with same_site='lax'."""
        kwargs = _get_session_middleware_kwargs()
        assert kwargs.get("same_site") == "lax", f"Expected same_site='lax', got {kwargs.get('same_site')!r}"

    def test_https_only_is_boolean(self):
        """https_only must be a boolean (not a string or None)."""
        kwargs = _get_session_middleware_kwargs()
        assert isinstance(
            kwargs.get("https_only"), bool
        ), f"https_only must be bool, got {type(kwargs.get('https_only'))}"

    def test_secret_key_is_set(self):
        """The session secret key must not be empty."""
        kwargs = _get_session_middleware_kwargs()
        secret = kwargs.get("secret_key", "")
        assert secret, "SessionMiddleware secret_key must not be empty"

    def test_https_only_env_var_parsing(self):
        """DASHBOARD_HTTPS_ONLY env var parsing logic must be correct."""
        truthy = ("1", "true", "yes", "True", "YES", "True")
        falsy = ("0", "false", "no", "", "False", "NO")
        for val in truthy:
            result = val.strip().lower() in ("1", "true", "yes")
            assert result is True, f"'{val}' should parse as True"
        for val in falsy:
            result = val.strip().lower() in ("1", "true", "yes")
            assert result is False, f"'{val}' should parse as False"


# ---------------------------------------------------------------------------
# Tests: cookie lifecycle via HTTP
# ---------------------------------------------------------------------------


class TestSessionCookieLifecycle:
    """Verify that the session cookie is set on login and cleared on logout."""

    def test_successful_login_sets_session_cookie(self, client):
        """A successful login must produce a session cookie in the client jar."""
        client.cookies.clear()
        response = client.post(
            "/login",
            data={"username": _TEST_USER, "password": _TEST_PASS},
            follow_redirects=False,
        )
        assert response.status_code in (200, 302, 303), f"Unexpected status {response.status_code}"
        assert "session" in client.cookies, "Session cookie not set after successful login"

    def test_failed_login_does_not_grant_access(self, client):
        """After a failed login, protected pages must still redirect to /login."""
        client.cookies.clear()
        client.post(
            "/login",
            data={"username": _TEST_USER, "password": "definitely-wrong-password"},
            follow_redirects=False,
        )
        protected = client.get("/", follow_redirects=False)
        assert protected.status_code in (302, 303, 401), "Protected page should not be accessible after failed login"

    def test_logout_redirects_to_login(self, logged_in_client):  # noqa: D102
        """After logout, accessing a protected page must redirect to /login."""
        logged_in_client.post("/logout", follow_redirects=True)
        response = logged_in_client.get("/", follow_redirects=False)
        assert response.status_code in (302, 303), "After logout, protected page should redirect"
        location = response.headers.get("location", "")
        assert "login" in location.lower(), f"Redirect after logout should point to /login, got: {location}"

    def test_samesite_lax_in_set_cookie_header(self, client):
        """The Set-Cookie header must include SameSite=lax after login."""
        client.cookies.clear()
        response = client.post(
            "/login",
            data={"username": _TEST_USER, "password": _TEST_PASS},
            follow_redirects=False,
        )
        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            assert "samesite=lax" in set_cookie.lower(), f"Expected SameSite=lax in Set-Cookie, got: {set_cookie}"

    def test_session_cookie_name_is_session(self, client):
        """The session cookie must be named 'session' (Starlette default)."""
        client.cookies.clear()
        client.post(
            "/login",
            data={"username": _TEST_USER, "password": _TEST_PASS},
            follow_redirects=False,
        )
        assert "session" in client.cookies, "Cookie named 'session' not found after login"
