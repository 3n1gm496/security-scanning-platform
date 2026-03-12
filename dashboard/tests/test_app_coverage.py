"""Additional tests for dashboard/app.py to improve coverage.

Targets the following uncovered paths:
- /api/badge/{target_name}.svg  (no scan, clean, with_findings, blocked)
- /api/scans/compare  (happy path, 404 on missing scan)
- /api/chart/* endpoints (all 6 chart endpoints)
- /api/export/findings  (json, csv, sarif, html, invalid format → 422)
- /api/findings/paginated  (basic pagination)
- /api/scans/paginated  (basic pagination)
- /api/health, /api/ready, /api/metrics  (monitoring endpoints)
- /api/analytics/finding-risk/{id}  (404 + happy path)
- /api/remediation/{id}  (404 + happy path)
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
# Also add the project root so orchestrator.storage is importable
project_root = root.parent
sys.path.insert(0, str(project_root))

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402
import db as _db  # noqa: E402
import app as _app  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def stub_db(monkeypatch):
    """Stub out dashboard-level DB helpers that require real data."""
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
        monkeypatch.setattr(module, "recent_failed_scans", lambda path, n: [])


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_headers(isolated_db):
    """Create a fresh admin API key for each test."""
    from rbac import Role, create_api_key, init_rbac_tables

    init_rbac_tables()
    key, _ = create_api_key(name="test-admin", role=Role.ADMIN, created_by="pytest")
    return {"Authorization": f"Bearer {key}"}


def _init_tables(db_path: str) -> None:
    """Initialise all tables: orchestrator schema + finding_management tables."""
    import os

    # Set DB path so finding_management uses the test DB
    os.environ["DASHBOARD_DB_PATH"] = db_path
    from orchestrator.storage import init_db

    init_db(db_path)
    # Also init finding_management tables (finding_states, finding_comments, etc.)
    from finding_management import init_finding_management_tables

    init_finding_management_tables()


def _insert_scan(db_path: str, **kwargs) -> str:
    """Insert a minimal scan record and return its id."""
    import sqlite3

    _init_tables(db_path)
    scan_id = str(uuid.uuid4())
    defaults = {
        "id": scan_id,
        "target_name": "test-target",
        "target_type": "local",
        "target_value": "/tmp/test",
        "status": "COMPLETED_CLEAN",
        "policy_status": "PASS",
        "findings_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "unknown_count": 0,
        "tools_json": "[]",
        "artifacts_json": "{}",
        "raw_report_dir": "/tmp/reports",
        "normalized_report_path": "/tmp/reports/normalized.json",
        "error_message": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
    }
    defaults.update(kwargs)
    defaults["id"] = scan_id
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO scans
           (id, target_name, target_type, target_value, status, policy_status,
            findings_count, critical_count, high_count, medium_count, low_count,
            info_count, unknown_count, tools_json, artifacts_json,
            raw_report_dir, normalized_report_path, error_message,
            created_at, finished_at)
           VALUES (:id, :target_name, :target_type, :target_value, :status,
                   :policy_status, :findings_count, :critical_count, :high_count,
                   :medium_count, :low_count, :info_count, :unknown_count,
                   :tools_json, :artifacts_json, :raw_report_dir,
                   :normalized_report_path, :error_message,
                   :created_at, :finished_at)""",
        defaults,
    )
    conn.commit()
    conn.close()
    return scan_id


def _insert_finding(db_path: str, scan_id: str, **kwargs) -> int:
    """Insert a minimal finding record and return its rowid."""
    import sqlite3

    _init_tables(db_path)
    defaults = {
        "scan_id": scan_id,
        "target_name": "test-target",
        "target_type": "local",
        "tool": "bandit",
        "category": "code",
        "severity": "HIGH",
        "title": "Test finding",
        "description": "A test finding",
        "fingerprint": str(uuid.uuid4()),
        "file": "app.py",
        "line": 42,
        "cve": None,
        "remediation": None,
        "raw_reference": None,
        "package": None,
        "version": None,
        "timestamp": "2026-01-01T00:00:00+00:00",
    }
    defaults.update(kwargs)
    conn = sqlite3.connect(db_path)
    cursor = conn.execute(
        """INSERT INTO findings
           (scan_id, target_name, target_type, tool, category, severity,
            title, description, fingerprint, file, line, cve, remediation,
            raw_reference, package, version, timestamp)
           VALUES (:scan_id, :target_name, :target_type, :tool, :category,
                   :severity, :title, :description, :fingerprint, :file,
                   :line, :cve, :remediation, :raw_reference, :package,
                   :version, :timestamp)""",
        defaults,
    )
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


# ---------------------------------------------------------------------------
# Badge endpoint tests
# ---------------------------------------------------------------------------


class TestBadgeEndpoint:
    """Tests for /api/badge/{target_name}.svg"""

    def test_badge_no_scan_returns_unknown(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)  # ensure scans table exists
        resp = client.get("/api/badge/nonexistent-target.svg", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("image/svg+xml")
        assert "unknown" in resp.text

    def test_badge_clean_scan_returns_passing(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        _insert_scan(db_path, target_name="clean-target", status="COMPLETED_CLEAN")
        resp = client.get("/api/badge/clean-target.svg", headers=admin_headers)
        assert resp.status_code == 200
        assert "passing" in resp.text

    def test_badge_with_critical_findings_returns_red(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        _insert_scan(
            db_path,
            target_name="vuln-target",
            status="COMPLETED_WITH_FINDINGS",
            policy_status="BLOCK",
            critical_count=3,
        )
        resp = client.get("/api/badge/vuln-target.svg", headers=admin_headers)
        assert resp.status_code == 200
        assert "3 critical" in resp.text
        assert "#e05d44" in resp.text  # red colour

    def test_badge_with_high_findings_returns_orange(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        _insert_scan(
            db_path,
            target_name="high-target",
            status="COMPLETED_WITH_FINDINGS",
            high_count=2,
        )
        resp = client.get("/api/badge/high-target.svg", headers=admin_headers)
        assert resp.status_code == 200
        assert "2 high" in resp.text
        assert "#fe7d37" in resp.text  # orange colour


# ---------------------------------------------------------------------------
# Compare scans endpoint tests
# ---------------------------------------------------------------------------


class TestCompareScans:
    """Tests for /api/scans/compare"""

    def test_compare_returns_diff(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        scan_1 = _insert_scan(db_path, target_name="svc")
        scan_2 = _insert_scan(db_path, target_name="svc")
        fp = str(uuid.uuid4())
        _insert_finding(db_path, scan_1, fingerprint=fp)
        _insert_finding(db_path, scan_2, fingerprint=fp)
        resp = client.get(
            f"/api/scans/compare?scan_id_1={scan_1}&scan_id_2={scan_2}",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_1" in data
        assert "scan_2" in data
        assert "diff" in data
        assert "unchanged_count" in data["diff"]

    def test_compare_404_on_missing_scan(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        scan_1 = _insert_scan(db_path)
        resp = client.get(
            f"/api/scans/compare?scan_id_1={scan_1}&scan_id_2={uuid.uuid4()}",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    def test_compare_new_and_resolved_findings(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        scan_1 = _insert_scan(db_path, target_name="svc")
        scan_2 = _insert_scan(db_path, target_name="svc")
        fp_old = str(uuid.uuid4())
        fp_new = str(uuid.uuid4())
        _insert_finding(db_path, scan_1, fingerprint=fp_old)
        _insert_finding(db_path, scan_2, fingerprint=fp_new)
        resp = client.get(
            f"/api/scans/compare?scan_id_1={scan_1}&scan_id_2={scan_2}",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["diff"]["new_count"] == 1
        assert data["diff"]["resolved_count"] == 1


# ---------------------------------------------------------------------------
# Chart endpoints tests
# ---------------------------------------------------------------------------


class TestChartEndpoints:
    """Tests for /api/chart/* endpoints."""

    def test_severity_distribution(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/chart/severity-distribution", headers=admin_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_tool_effectiveness(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/chart/tool-effectiveness", headers=admin_headers)
        assert resp.status_code == 200

    def test_target_risk_heatmap(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/chart/target-risk-heatmap", headers=admin_headers)
        assert resp.status_code == 200

    def test_scan_trend(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/chart/scan-trend", headers=admin_headers)
        assert resp.status_code == 200

    def test_remediation_progress(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/chart/remediation-progress", headers=admin_headers)
        assert resp.status_code == 200

    def test_cve_distribution(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/chart/cve-distribution", headers=admin_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Export endpoint tests
# ---------------------------------------------------------------------------


class TestExportFindings:
    """Tests for /api/export/findings"""

    def test_export_json(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get(
            "/api/export/findings?format=json",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")

    def test_export_csv(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get(
            "/api/export/findings?format=csv",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_export_sarif(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get(
            "/api/export/findings?format=sarif",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")

    def test_export_html(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get(
            "/api/export/findings?format=html",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_export_invalid_format_returns_422(self, client, isolated_db, admin_headers):
        """FastAPI validates the format pattern and returns 422 for invalid values."""
        resp = client.get(
            "/api/export/findings?format=xlsx",
            headers=admin_headers,
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Pagination endpoints tests
# ---------------------------------------------------------------------------


class TestPaginationEndpoints:
    """Tests for /api/findings/paginated and /api/scans/paginated."""

    def test_paginate_findings_empty(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/findings/paginated", headers=admin_headers)
        assert resp.status_code == 200

    def test_paginate_scans_empty(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/scans/paginated", headers=admin_headers)
        assert resp.status_code == 200

    def test_paginate_findings_with_data(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        scan_id = _insert_scan(db_path)
        _insert_finding(db_path, scan_id, severity="HIGH")
        _insert_finding(db_path, scan_id, severity="LOW")
        resp = client.get(
            "/api/findings/paginated?per_page=1",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    def test_paginate_scans_with_data(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        _insert_scan(db_path, target_name="svc-a")
        _insert_scan(db_path, target_name="svc-b")
        resp = client.get(
            "/api/scans/paginated?per_page=1",
            headers=admin_headers,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Monitoring endpoints tests
# ---------------------------------------------------------------------------


class TestMonitoringEndpoints:
    """Tests for /api/health, /api/ready, /metrics (requires auth)."""

    def test_health_returns_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data
        assert "version" in data

    def test_ready_returns_200_or_503(self, client):
        resp = client.get("/api/ready")
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "ready" in data
        assert "checks" in data

    def test_metrics_requires_auth(self, client):
        """The /metrics endpoint requires authentication."""
        resp = client.get("/metrics")
        assert resp.status_code == 401

    def test_metrics_with_auth(self, client, isolated_db, admin_headers):
        """The /metrics endpoint returns Prometheus text format when authenticated."""
        _init_tables(isolated_db)
        resp = client.get("/metrics", headers=admin_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Analytics and remediation endpoints tests
# ---------------------------------------------------------------------------


class TestAnalyticsAndRemediation:
    """Tests for /api/analytics/finding-risk and /api/remediation."""

    def test_finding_risk_404_on_missing(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/analytics/finding-risk/99999", headers=admin_headers)
        assert resp.status_code == 404

    def test_finding_risk_happy_path(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        scan_id = _insert_scan(db_path)
        finding_id = _insert_finding(db_path, scan_id, severity="CRITICAL", cve="CVE-2024-1234")
        resp = client.get(
            f"/api/analytics/finding-risk/{finding_id}",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_score" in data
        assert data["severity"] == "CRITICAL"
        assert data["has_cve"] is True

    def test_remediation_404_on_missing(self, client, isolated_db, admin_headers):
        _init_tables(isolated_db)
        resp = client.get("/api/remediation/99999", headers=admin_headers)
        assert resp.status_code == 404

    def test_remediation_happy_path(self, client, isolated_db, admin_headers):
        db_path = isolated_db
        scan_id = _insert_scan(db_path)
        finding_id = _insert_finding(
            db_path,
            scan_id,
            severity="HIGH",
            title="SQL Injection",
            category="injection",
        )
        resp = client.get(
            f"/api/remediation/{finding_id}",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "remediation" in data
        assert data["finding_id"] == finding_id
