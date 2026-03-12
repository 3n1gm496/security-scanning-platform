"""
Tests for bounded thread pool scan execution and security headers.

Covers:
- _scan_executor is a ThreadPoolExecutor with correct max_workers
- async_mode=True submits to the pool (not raw Thread)
- Security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from fastapi.testclient import TestClient

import app as _app
from app import app, _scan_executor

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
    from rbac import init_rbac_tables, create_api_key, Role

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
    assert _app.MAX_SCAN_WORKERS == int(os.environ.get("DASHBOARD_MAX_SCAN_WORKERS", "4"))


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
    assert submitted[0][0].__name__ == "run_scan"


# ---------------------------------------------------------------------------
# Security headers tests
# ---------------------------------------------------------------------------


def test_csp_header_present(client):
    """Content-Security-Policy header must be present on all responses."""
    resp = client.get("/api/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_hsts_header_present(client):
    """Strict-Transport-Security header must be present on all responses."""
    resp = client.get("/api/health")
    hsts = resp.headers.get("Strict-Transport-Security", "")
    assert "max-age=" in hsts
    assert "includeSubDomains" in hsts


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
