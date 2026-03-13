"""
End-to-end integration tests for critical user flows.

These tests exercise the full API surface through the FastAPI TestClient,
covering: login, dashboard, findings (paginate + triage + export), analytics,
settings (API keys + webhooks), and status-counts.
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

from app import app  # noqa: E402
import db as _db  # noqa: E402
from rbac import Role, create_api_key, init_rbac_tables  # noqa: E402
from finding_management import init_finding_management_tables  # noqa: E402
from webhooks import init_webhook_tables  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def full_db(isolated_db):
    """DB with scan, findings, RBAC, finding_management, and webhooks tables."""
    db_path = isolated_db
    init_rbac_tables()
    init_finding_management_tables()
    init_webhook_tables()

    with _db.get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (id, created_at, finished_at, target_type, target_name, "
            "target_value, status, policy_status, findings_count, critical_count, "
            "high_count, medium_count, low_count, info_count, unknown_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "scan-e2e", "2024-06-01T10:00:00", "2024-06-01T10:05:00",
                "git", "e2e-repo", "https://github.com/org/e2e",
                "COMPLETED_WITH_FINDINGS", "FAILED", 5, 2, 1, 1, 1, 0, 0,
            ),
        )
        for i, sev in enumerate(["CRITICAL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            conn.execute(
                "INSERT INTO findings (scan_id, timestamp, target_type, target_name, "
                "title, description, severity, tool, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "scan-e2e", f"2024-06-01T10:0{i}:00", "git", "e2e-repo",
                    f"E2E Finding {i}", f"Desc {i}", sev, "semgrep", "sast",
                ),
            )
    return db_path


@pytest.fixture
def auth_client(full_db):
    """Session-authenticated TestClient."""
    client = TestClient(app, raise_server_exceptions=True)
    client.post("/login", data={"username": "testuser", "password": "testpass"})
    return client


@pytest.fixture
def api_key_client(full_db):
    """API-key authenticated TestClient (admin role)."""
    key, _ = create_api_key(name="e2e-admin", role=Role.ADMIN, created_by="pytest")
    client = TestClient(app, raise_server_exceptions=True)
    client.headers["Authorization"] = f"Bearer {key}"
    return client


# ---------------------------------------------------------------------------
# Flow 1: Login and SPA access
# ---------------------------------------------------------------------------


class TestLoginFlow:
    def test_login_redirects_to_dashboard(self, full_db):
        client = TestClient(app)
        resp = client.post(
            "/login", data={"username": "testuser", "password": "testpass"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)

    def test_unauthenticated_api_returns_401(self, full_db):
        client = TestClient(app)
        resp = client.get("/api/kpi")
        assert resp.status_code == 401

    def test_spa_root_serves_vue_app(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200
        assert "vue" in resp.text.lower() or "createApp" in resp.text


# ---------------------------------------------------------------------------
# Flow 2: Dashboard KPIs and charts
# ---------------------------------------------------------------------------


class TestDashboardFlow:
    def test_kpi_endpoint(self, auth_client):
        resp = auth_client.get("/api/kpi")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scans" in data
        assert data["total_scans"] >= 1

    def test_chart_severity_distribution(self, auth_client):
        resp = auth_client.get("/api/chart/severity-distribution")
        assert resp.status_code == 200

    def test_trends(self, auth_client):
        resp = auth_client.get("/api/trends")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Flow 3: Findings paginate, triage, export
# ---------------------------------------------------------------------------


class TestFindingsFlow:
    def test_paginated_findings(self, auth_client):
        resp = auth_client.get("/api/findings/paginated?per_page=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 3
        assert data["pagination"]["count"] >= 3

    def test_pagination_includes_total_and_prev(self, auth_client):
        """Pagination response includes total_count, has_prev, prev_cursor."""
        resp = auth_client.get("/api/findings/paginated?per_page=2")
        assert resp.status_code == 200
        pag = resp.json()["pagination"]
        assert "total_count" in pag
        assert pag["total_count"] == 5
        assert pag["has_prev"] is False  # First page
        assert pag["has_next"] is True
        # Navigate to page 2
        resp2 = auth_client.get(f"/api/findings/paginated?per_page=2&cursor={pag['next_cursor']}")
        pag2 = resp2.json()["pagination"]
        assert pag2["has_prev"] is True
        assert pag2["prev_cursor"] is not None

    def test_filter_by_severity(self, auth_client):
        resp = auth_client.get("/api/findings/paginated?severity=CRITICAL&per_page=50")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert all(f["severity"] == "CRITICAL" for f in items)

    def test_filter_by_tool(self, auth_client):
        resp = auth_client.get("/api/findings/paginated?tool=semgrep&per_page=50")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 5

    def test_triage_update_status(self, auth_client):
        # Get first finding ID
        resp = auth_client.get("/api/findings/paginated?per_page=1")
        finding_id = resp.json()["items"][0]["id"]

        # Update status (form field is status_value)
        resp = auth_client.patch(
            f"/api/findings/{finding_id}/status",
            data={"status_value": "acknowledged", "notes": "E2E test"},
        )
        assert resp.status_code == 200

        # Verify state
        resp = auth_client.get(f"/api/findings/{finding_id}/state")
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    def test_status_counts_reflects_triage(self, auth_client):
        # Triage one finding
        resp = auth_client.get("/api/findings/paginated?per_page=1")
        fid = resp.json()["items"][0]["id"]
        auth_client.patch(
            f"/api/findings/{fid}/status",
            data={"status_value": "resolved"},
        )

        # Check counts
        resp = auth_client.get("/api/findings/status-counts")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("resolved", 0) >= 1
        assert data.get("new", 0) >= 1  # remaining untriaged

    def test_export_csv(self, auth_client):
        resp = auth_client.get("/api/export/findings?format=csv&limit=100")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        lines = resp.text.strip().split("\n")
        assert len(lines) >= 2  # header + at least 1 data row

    def test_export_json(self, auth_client):
        resp = auth_client.get("/api/export/findings?format=json&limit=100")
        assert resp.status_code == 200
        data = resp.json()
        # JSON export wraps findings in a dict with metadata
        assert "findings" in data
        assert len(data["findings"]) == 5

    def test_export_sarif(self, auth_client):
        resp = auth_client.get("/api/export/findings?format=sarif&limit=100")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("$schema") or data.get("version")  # SARIF structure


# ---------------------------------------------------------------------------
# Flow 4: Analytics
# ---------------------------------------------------------------------------


class TestAnalyticsFlow:
    def test_risk_distribution(self, auth_client):
        resp = auth_client.get("/api/analytics/risk-distribution")
        assert resp.status_code == 200

    def test_compliance(self, auth_client):
        resp = auth_client.get("/api/analytics/compliance")
        assert resp.status_code == 200

    def test_trends(self, auth_client):
        resp = auth_client.get("/api/analytics/trends?days=30")
        assert resp.status_code == 200

    def test_tool_effectiveness(self, auth_client):
        resp = auth_client.get("/api/analytics/tool-effectiveness")
        assert resp.status_code == 200

    def test_target_risk(self, auth_client):
        resp = auth_client.get("/api/analytics/target-risk")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Flow 5: Settings — API keys
# ---------------------------------------------------------------------------


class TestApiKeyFlow:
    def test_create_and_list_api_key(self, auth_client):
        resp = auth_client.post(
            "/api/keys",
            data={"name": "E2E Key", "role": "viewer"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "key" in data
        assert data["key"].startswith("ssp_")

        # List
        resp = auth_client.get("/api/keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert any(k["name"] == "E2E Key" for k in keys)

    def test_revoke_api_key(self, auth_client):
        resp = auth_client.post(
            "/api/keys",
            data={"name": "Revoke E2E", "role": "viewer"},
        )
        prefix = resp.json()["prefix"]

        resp = auth_client.delete(f"/api/keys/{prefix}")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Flow 6: Settings — Webhooks
# ---------------------------------------------------------------------------


class TestWebhookFlow:
    def test_create_list_delete_webhook(self, auth_client):
        # Create
        resp = auth_client.post(
            "/api/webhooks",
            data={
                "name": "E2E Hook",
                "url": "https://hooks.example.com/notify",
                "events": "scan.completed",
            },
        )
        assert resp.status_code == 200
        wid = resp.json()["id"]

        # List
        resp = auth_client.get("/api/webhooks")
        assert resp.status_code == 200
        assert any(w["id"] == wid for w in resp.json())

        # Delete
        resp = auth_client.delete(f"/api/webhooks/{wid}")
        assert resp.status_code == 200

    def test_webhook_ssrf_rejected(self, auth_client):
        resp = auth_client.post(
            "/api/webhooks",
            data={
                "name": "SSRF Hook",
                "url": "http://169.254.169.254/latest/meta-data/",
                "events": "scan.completed",
            },
        )
        assert resp.status_code == 400
        assert "private/reserved" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Flow 7: API key authentication
# ---------------------------------------------------------------------------


class TestApiKeyAuth:
    def test_api_key_can_access_endpoints(self, api_key_client):
        resp = api_key_client.get("/api/kpi")
        assert resp.status_code == 200

    def test_audit_log_export_csv(self, api_key_client):
        resp = api_key_client.get("/api/audit/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_audit_log_export_json(self, api_key_client):
        resp = api_key_client.get("/api/audit/export?format=json")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_invalid_api_key_rejected(self, full_db):
        client = TestClient(app)
        client.headers["Authorization"] = "Bearer ssp_invalid0000000000000000000000000000000000000000000000000000000000"
        resp = client.get("/api/kpi")
        assert resp.status_code == 401
