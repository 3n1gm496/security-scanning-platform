"""
Tests targeting coverage gaps identified in the audit:
- db.py: list_findings and list_scans with filters
- finding_management.py: update_finding_status, get_finding_state
- app.py: /api/scans endpoint, Permissions-Policy header, scan trigger edge cases
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from app import app  # noqa: E402
import db as _db  # noqa: E402
import finding_management as _fm  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def client_with_data(isolated_db):
    """TestClient authenticated with two scans and three findings."""
    db_path = isolated_db
    with _db.get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (id, created_at, finished_at, target_type, target_name, "
            "target_value, status, policy_status, findings_count, critical_count, "
            "high_count, medium_count, low_count, info_count, unknown_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "scan-a",
                "2024-03-01T10:00:00",
                "2024-03-01T10:05:00",
                "git",
                "myrepo",
                "https://github.com/org/myrepo",
                "COMPLETED_WITH_FINDINGS",
                "FAIL",
                3,
                1,
                1,
                1,
                0,
                0,
                0,
            ),
        )
        conn.execute(
            "INSERT INTO scans (id, created_at, finished_at, target_type, target_name, "
            "target_value, status, policy_status, findings_count, critical_count, "
            "high_count, medium_count, low_count, info_count, unknown_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "scan-b",
                "2024-03-02T10:00:00",
                "2024-03-02T10:05:00",
                "git",
                "otherrepo",
                "https://github.com/org/otherrepo",
                "COMPLETED",
                "PASS",
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ),
        )
        conn.execute(
            "INSERT INTO findings (scan_id, timestamp, target_type, target_name, "
            "tool, category, severity, title, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("scan-a", "2024-03-01T10:01:00", "git", "myrepo", "bandit", "injection", "CRITICAL", "SQL Injection", "desc"),
        )
        conn.execute(
            "INSERT INTO findings (scan_id, timestamp, target_type, target_name, "
            "tool, category, severity, title, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("scan-a", "2024-03-01T10:02:00", "git", "myrepo", "bandit", "crypto", "HIGH", "Weak Crypto", "desc"),
        )
        conn.execute(
            "INSERT INTO findings (scan_id, timestamp, target_type, target_name, "
            "tool, category, severity, title, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("scan-a", "2024-03-01T10:03:00", "git", "myrepo", "semgrep", "xss", "MEDIUM", "XSS", "desc"),
        )

    with TestClient(app) as c:
        c.post("/login", data={"username": "testuser", "password": "testpass"})
        yield c, db_path


# ---------------------------------------------------------------------------
# db.py — list_findings with filters
# ---------------------------------------------------------------------------


def test_list_findings_filter_by_severity(client_with_data):
    """list_findings filters correctly by severity."""
    _, db_path = client_with_data
    results = _db.list_findings(db_path, severity="CRITICAL")
    assert len(results) == 1
    assert results[0]["severity"] == "CRITICAL"


def test_list_findings_filter_by_tool(client_with_data):
    """list_findings filters correctly by tool."""
    _, db_path = client_with_data
    results = _db.list_findings(db_path, tool="bandit")
    assert len(results) == 2
    for r in results:
        assert r["tool"] == "bandit"


def test_list_findings_filter_by_scan_id(client_with_data):
    """list_findings filters correctly by scan_id."""
    _, db_path = client_with_data
    results = _db.list_findings(db_path, scan_id="scan-a")
    assert len(results) == 3


def test_list_findings_no_results(client_with_data):
    """list_findings returns empty list when no match."""
    _, db_path = client_with_data
    results = _db.list_findings(db_path, severity="INFO")
    assert results == []


def test_list_scans_filter_by_status(client_with_data):
    """list_scans filters correctly by status."""
    _, db_path = client_with_data
    results = _db.list_scans(db_path, status="COMPLETED")
    assert len(results) == 1
    assert results[0]["status"] == "COMPLETED"


def test_list_scans_filter_by_target(client_with_data):
    """list_scans filters correctly by target_name."""
    _, db_path = client_with_data
    results = _db.list_scans(db_path, target="myrepo")
    assert len(results) == 1
    assert results[0]["target_name"] == "myrepo"


# ---------------------------------------------------------------------------
# finding_management.py — update_finding_status, get_finding_state
# ---------------------------------------------------------------------------


def test_update_and_get_finding_state(client_with_data):
    """update_finding_status persists state; get_finding_state retrieves it."""
    _, db_path = client_with_data
    with _db.get_connection(db_path) as conn:
        row = conn.execute("SELECT id FROM findings LIMIT 1").fetchone()
    finding_id = row["id"]

    # finding_management uses DASHBOARD_DB_PATH env var (set in conftest)
    _fm.update_finding_status(
        finding_id,
        _fm.FindingStatus.ACKNOWLEDGED,
        user="admin",
        notes="Triaged by admin",
        assigned_to="admin",
    )
    state = _fm.get_finding_state(finding_id)

    assert state is not None
    assert state["status"] == "acknowledged"
    assert state["assigned_to"] == "admin"
    assert state["resolution_notes"] == "Triaged by admin"


def test_update_finding_status_overwrite(client_with_data):
    """update_finding_status correctly overwrites a previous state."""
    _, db_path = client_with_data
    with _db.get_connection(db_path) as conn:
        row = conn.execute("SELECT id FROM findings LIMIT 1").fetchone()
    finding_id = row["id"]

    _fm.update_finding_status(finding_id, _fm.FindingStatus.ACKNOWLEDGED, user="admin", notes="First")
    _fm.update_finding_status(finding_id, _fm.FindingStatus.RESOLVED, user="admin", notes="Fixed in v2")
    state = _fm.get_finding_state(finding_id)

    assert state["status"] == "resolved"
    assert state["resolution_notes"] == "Fixed in v2"


def test_get_finding_state_not_found(client_with_data):
    """get_finding_state returns None for a finding with no state record."""
    _, db_path = client_with_data
    state = _fm.get_finding_state(99999)
    assert state is None


# ---------------------------------------------------------------------------
# app.py — /api/scans endpoint and security headers
# ---------------------------------------------------------------------------


def test_api_scans_returns_list(client_with_data):
    """GET /api/scans returns a list of scans."""
    client, _ = client_with_data
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 2


def test_api_scans_filter_by_status(client_with_data):
    """GET /api/scans?status=COMPLETED returns only matching scans."""
    client, _ = client_with_data
    resp = client.get("/api/scans?status=COMPLETED")
    assert resp.status_code == 200
    data = resp.json()
    for scan in data:
        assert scan["status"] == "COMPLETED"


def test_permissions_policy_header(client_with_data):
    """All responses include the Permissions-Policy security header."""
    client, _ = client_with_data
    resp = client.get("/api/kpi")
    assert resp.status_code == 200
    assert "permissions-policy" in resp.headers


def test_x_content_type_options_header(client_with_data):
    """All responses include X-Content-Type-Options: nosniff."""
    client, _ = client_with_data
    resp = client.get("/api/kpi")
    assert resp.headers.get("x-content-type-options") == "nosniff"


def test_x_frame_options_header(client_with_data):
    """All responses include X-Frame-Options: DENY."""
    client, _ = client_with_data
    resp = client.get("/api/kpi")
    assert resp.headers.get("x-frame-options") == "DENY"


def test_api_findings_paginated_with_scan_id_filter(client_with_data):
    """GET /api/findings/paginated?scan_id=scan-a returns only findings for that scan."""
    client, _ = client_with_data
    resp = client.get("/api/findings/paginated?scan_id=scan-a&page_size=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    for item in data["items"]:
        assert item["scan_id"] == "scan-a"


def test_api_findings_paginated_scan_id_no_results(client_with_data):
    """GET /api/findings/paginated?scan_id=nonexistent returns empty items."""
    client, _ = client_with_data
    resp = client.get("/api/findings/paginated?scan_id=nonexistent-scan-id&page_size=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["count"] == 0
