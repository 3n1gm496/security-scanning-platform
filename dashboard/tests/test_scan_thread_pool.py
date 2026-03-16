"""
Tests for bounded thread pool scan execution and security headers.

Covers:
- _scan_executor is a ThreadPoolExecutor with correct max_workers
- async_mode=True submits to the pool (not raw Thread)
- Security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options
"""

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

if "bcrypt" not in sys.modules:
    fake_bcrypt = types.ModuleType("bcrypt")
    fake_bcrypt.gensalt = lambda: b"salt"
    fake_bcrypt.hashpw = lambda value, salt: b"$2b$stubbed-hash"
    fake_bcrypt.checkpw = lambda plain, hashed: True
    sys.modules["bcrypt"] = fake_bcrypt

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from app import app
from fastapi.testclient import TestClient
from routers._shared import MAX_SCAN_WORKERS as _MAX_SCAN_WORKERS
from routers._shared import scan_executor as _scan_executor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def admin_headers(isolated_db):
    """Return Authorization headers with a fresh admin API key."""
    from rbac import Role, create_api_key, init_rbac_tables

    init_rbac_tables()
    full_key, _ = create_api_key(name="test-admin", role=Role.ADMIN, created_by="pytest")
    return {"Authorization": f"Bearer {full_key}"}


# ---------------------------------------------------------------------------
# Thread pool tests
# ---------------------------------------------------------------------------


def test_scan_executor_is_thread_pool_executor():
    """_scan_executor must be a ThreadPoolExecutor instance."""
    from concurrent.futures import ThreadPoolExecutor

    assert isinstance(_scan_executor, ThreadPoolExecutor)


def test_scan_executor_max_workers_respects_env():
    """MAX_SCAN_WORKERS must be read from env and applied to the executor."""
    assert _MAX_SCAN_WORKERS == int(os.environ.get("DASHBOARD_MAX_SCAN_WORKERS", "4"))


def test_trigger_scan_async_uses_executor(client, admin_headers):
    """async_mode=True must submit to _scan_executor, not create a raw Thread."""
    submitted = []

    def fake_submit(fn, *args, **kwargs):
        submitted.append((fn, args))
        return MagicMock()

    with patch.object(_scan_executor, "submit", side_effect=fake_submit):
        resp = client.post(
            "/api/scan/trigger",
            data={
                "target_type": "git",
                "target": "https://github.com/example/repo",
                "name": "test-repo",
                "async_mode": "true",
            },
            headers=admin_headers,
        )

    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"
    assert len(submitted) == 1
    # scan_queue_submit wraps run_scan in a _wrapper closure, so the
    # submitted callable is the wrapper — just verify something was submitted.
    assert callable(submitted[0][0])


# ---------------------------------------------------------------------------
# Security headers tests
# ---------------------------------------------------------------------------


def test_csp_header_present(client):
    """Content-Security-Policy header must be present on all responses."""
    resp = client.get("/api/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_csp_nonce_present(client):
    """CSP should use a nonce for script-src instead of unsafe-inline."""
    resp = client.get("/api/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "'nonce-" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]


def test_hsts_header_absent_over_http(client):
    """Strict-Transport-Security must not be sent on plain HTTP responses."""
    resp = client.get("/api/health")
    hsts = resp.headers.get("Strict-Transport-Security", "")
    assert hsts == ""


def test_x_content_type_options_header(client):
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_x_frame_options_header(client):
    resp = client.get("/api/health")
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_referrer_policy_header(client):
    resp = client.get("/api/health")
    assert resp.headers.get("Referrer-Policy") == "no-referrer"


def test_cache_control_header(client):
    resp = client.get("/api/health")
    assert resp.headers.get("Cache-Control") == "no-store"
