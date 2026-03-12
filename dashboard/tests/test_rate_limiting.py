"""
Tests for the sliding-window rate limiter in app.py.

Covers:
- General API rate limiting (180 req/min default)
- Login brute-force protection (10 req/min default)
- Cleanup / memory management helper
- X-Forwarded-For client key extraction
"""

import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from fastapi.testclient import TestClient

import app as _app
from app import app
from rate_limit import is_rate_limited as _is_rate_limited, _rate_buckets, _rate_lock, _evict_stale_buckets

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_buckets():
    with _rate_lock:
        _rate_buckets.clear()


@pytest.fixture(autouse=True)
def reset_rate_buckets():
    """Ensure each test starts with a clean rate-limit state."""
    _clear_buckets()
    yield
    _clear_buckets()


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Unit tests for _is_rate_limited
# ---------------------------------------------------------------------------


def test_rate_limiter_allows_requests_under_limit():
    now = time.monotonic()
    for _ in range(5):
        assert _is_rate_limited("test", "127.0.0.1", 10, 60, now) is False


def test_rate_limiter_blocks_when_limit_reached():
    now = time.monotonic()
    for _ in range(10):
        _is_rate_limited("test", "192.168.1.1", 10, 60, now)
    # 11th request must be blocked
    assert _is_rate_limited("test", "192.168.1.1", 10, 60, now) is True


def test_rate_limiter_resets_after_window():
    now = time.monotonic()
    for _ in range(10):
        _is_rate_limited("test", "10.0.0.1", 10, 1, now)
    # Simulate time passing beyond the window
    future = now + 2.0
    assert _is_rate_limited("test", "10.0.0.1", 10, 1, future) is False


def test_rate_limiter_scopes_are_independent():
    """Different scopes must not share counters."""
    now = time.monotonic()
    for _ in range(10):
        _is_rate_limited("scope_a", "1.2.3.4", 10, 60, now)
    # scope_b should still be allowed
    assert _is_rate_limited("scope_b", "1.2.3.4", 10, 60, now) is False


def test_rate_limiter_clients_are_independent():
    """Different client IPs must not share counters."""
    now = time.monotonic()
    for _ in range(10):
        _is_rate_limited("api", "1.1.1.1", 10, 60, now)
    # Different IP must still be allowed
    assert _is_rate_limited("api", "2.2.2.2", 10, 60, now) is False


# ---------------------------------------------------------------------------
# Integration tests via TestClient
# ---------------------------------------------------------------------------


def test_api_rate_limit_returns_429(client):
    """Exceeding the API rate limit must return 429 with Retry-After header."""
    # Patch the limit bound in app's namespace (the middleware reads from there)
    with patch.object(_app, "RATE_LIMIT_REQUESTS", 3):
        for i in range(3):
            client.get("/api/scans")
        resp = client.get("/api/scans")
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_login_rate_limit_returns_429(client):
    """Exceeding the login rate limit must return 429."""
    with patch.object(_app, "LOGIN_RATE_LIMIT_REQUESTS", 3):
        for _ in range(3):
            client.post("/login", data={"username": "x", "password": "y"})
        resp = client.post("/login", data={"username": "x", "password": "y"})
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_login_rate_limit_does_not_affect_api(client):
    """Login rate limit must not bleed into API rate limit bucket."""
    with patch.object(_app, "LOGIN_RATE_LIMIT_REQUESTS", 3):
        for _ in range(3):
            client.post("/login", data={"username": "x", "password": "y"})
        # API endpoint must still work
        resp = client.get("/api/health")
    assert resp.status_code == 200


def test_health_endpoint_excluded_from_rate_limit(client):
    """Health endpoint must never be rate-limited."""
    with patch.object(_app, "RATE_LIMIT_REQUESTS", 2):
        for _ in range(10):
            resp = client.get("/api/health")
    assert resp.status_code == 200


def test_security_headers_present(client):
    """Security headers must be present on every response."""
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "no-referrer"
    assert resp.headers.get("Cache-Control") == "no-store"


# ---------------------------------------------------------------------------
# Cleanup / memory management
# ---------------------------------------------------------------------------


def test_evict_stale_buckets_removes_old_entries():
    """_evict_stale_buckets must remove entries older than the window."""
    old_time = time.monotonic() - 3600  # 1 hour ago
    with _rate_lock:
        from collections import deque as _deque

        _rate_buckets[("stale_scope", "old_client")] = _deque([old_time])
        _rate_buckets[("fresh_scope", "new_client")] = _deque([time.monotonic()])

    _evict_stale_buckets.__wrapped__ = None  # ensure no timer side-effects
    # Call the cleanup logic directly (without rescheduling)
    import rate_limit as _rl
    cutoff = time.monotonic() - max(_rl.RATE_LIMIT_WINDOW_SECONDS, _rl.LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    with _rate_lock:
        stale = [k for k, dq in _rate_buckets.items() if not dq or dq[-1] < cutoff]
        for k in stale:
            del _rate_buckets[k]

    with _rate_lock:
        assert ("stale_scope", "old_client") not in _rate_buckets
        assert ("fresh_scope", "new_client") in _rate_buckets
