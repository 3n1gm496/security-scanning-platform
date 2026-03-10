"""
Tests for /api/scan/trigger endpoint — path traversal protection and input validation.
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from fastapi.testclient import TestClient

from app import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_headers(isolated_db):
    """Create a fresh admin API key for each test, using the isolated DB."""
    from rbac import create_api_key, init_rbac_tables, Role

    init_rbac_tables()
    key, _ = create_api_key(name="test-admin", role=Role.ADMIN, created_by="pytest")
    return {"Authorization": f"Bearer {key}"}


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------


def test_trigger_scan_invalid_target_type(client, admin_headers):
    """target_type must be one of local/git/image."""
    resp = client.post(
        "/api/scan/trigger",
        data={"target_type": "ftp", "target": "/tmp/x", "name": "test"},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "target_type" in resp.text


def test_trigger_scan_missing_target(client, admin_headers):
    """Empty target must be rejected.

    FastAPI 0.115 + Pydantic v1: empty string passes Form validation, rejected
    with HTTP 400 by application logic.
    FastAPI 0.135 + Pydantic v2: empty string is treated as missing field,
    rejected with HTTP 422 by Pydantic before reaching application logic.
    Both are correct rejections; we accept any 4xx response.
    """
    resp = client.post(
        "/api/scan/trigger",
        data={"target_type": "git", "target": "", "name": "test"},
        headers=admin_headers,
    )
    assert resp.status_code in (400, 422), f"Expected 400 or 422, got {resp.status_code}"


def test_trigger_scan_missing_name(client, admin_headers):
    """Empty name must be rejected.

    FastAPI 0.115 + Pydantic v1: empty string passes Form validation, rejected
    with HTTP 400 by application logic.
    FastAPI 0.135 + Pydantic v2: empty string is treated as missing field,
    rejected with HTTP 422 by Pydantic before reaching application logic.
    Both are correct rejections; we accept any 4xx response.
    """
    resp = client.post(
        "/api/scan/trigger",
        data={"target_type": "git", "target": "https://github.com/example/repo", "name": ""},
        headers=admin_headers,
    )
    assert resp.status_code in (400, 422), f"Expected 400 or 422, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Path traversal protection tests
# ---------------------------------------------------------------------------


def test_trigger_scan_local_path_traversal_etc(client, admin_headers, tmp_path):
    """Absolute path outside workspace must be rejected with 400."""
    resp = client.post(
        "/api/scan/trigger",
        data={"target_type": "local", "target": "/etc/passwd", "name": "traversal"},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "workspace" in resp.text.lower()


def test_trigger_scan_local_path_traversal_dotdot(client, admin_headers, tmp_path):
    """Path with .. components that escape workspace must be rejected."""
    workspace = tmp_path / "workspaces"
    workspace.mkdir()
    inner = workspace / "project"
    inner.mkdir()

    with patch.dict(os.environ, {"WORKSPACE_DIR": str(workspace)}):
        resp = client.post(
            "/api/scan/trigger",
            data={
                "target_type": "local",
                "target": str(inner / ".." / ".." / "etc"),
                "name": "traversal",
            },
            headers=admin_headers,
        )
    assert resp.status_code == 400
    assert "workspace" in resp.text.lower()


def test_trigger_scan_local_valid_path_accepted(client, admin_headers, tmp_path):
    """A path inside the workspace directory must pass validation (scan itself may fail)."""
    workspace = tmp_path / "workspaces"
    workspace.mkdir()
    target_dir = workspace / "myproject"
    target_dir.mkdir()

    with patch.dict(os.environ, {"WORKSPACE_DIR": str(workspace)}):
        with patch("app.run_scan_async", return_value={"status": "completed", "output": {}, "returncode": 0}):
            resp = client.post(
                "/api/scan/trigger",
                data={
                    "target_type": "local",
                    "target": str(target_dir),
                    "name": "valid-project",
                },
                headers=admin_headers,
            )
    # Should not be rejected by path validation (400); scan itself returns completed
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


def test_trigger_scan_git_url_not_path_validated(client, admin_headers):
    """git and image targets must NOT be subject to path validation."""
    with patch("app.run_scan_async", return_value={"status": "completed", "output": {}, "returncode": 0}):
        resp = client.post(
            "/api/scan/trigger",
            data={
                "target_type": "git",
                "target": "https://github.com/example/repo",
                "name": "git-repo",
            },
            headers=admin_headers,
        )
    assert resp.status_code == 200


def test_trigger_scan_unauthenticated(client):
    """Unauthenticated requests must be rejected with 401/403."""
    resp = client.post(
        "/api/scan/trigger",
        data={"target_type": "git", "target": "https://github.com/example/repo", "name": "test"},
    )
    assert resp.status_code in (401, 403)
