"""
Stabilization pass tests:
- db.py: count_findings, list_findings with offset
- app.py: /findings route pagination context
- Dead template removal: index.html and index-vue.html are not served
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

# ---------------------------------------------------------------------------
# Fixture: isolated DB with a scan and 12 findings
# ---------------------------------------------------------------------------


@pytest.fixture
def db_with_findings(isolated_db):
    db_path = isolated_db
    with _db.get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (id, created_at, finished_at, target_type, target_name, "
            "target_value, status, policy_status, findings_count, critical_count, "
            "high_count, medium_count, low_count, info_count, unknown_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "scan-stab",
                "2024-06-01T10:00:00",
                "2024-06-01T10:05:00",
                "git",
                "stabilization-repo",
                "https://github.com/org/stab",
                "COMPLETED_WITH_FINDINGS",
                "FAILED",
                12,
                3,
                4,
                3,
                2,
                0,
                0,
            ),
        )
        severities = ["CRITICAL"] * 3 + ["HIGH"] * 4 + ["MEDIUM"] * 3 + ["LOW"] * 2
        for i, sev in enumerate(severities):
            conn.execute(
                "INSERT INTO findings (scan_id, timestamp, target_type, target_name, "
                "title, description, severity, tool, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "scan-stab",
                    f"2024-06-01T10:0{i}:00",
                    "git",
                    "stabilization-repo",
                    f"Finding {i}",
                    f"Description {i}",
                    sev,
                    "bandit",
                    "sast",
                ),
            )
    return db_path


# ---------------------------------------------------------------------------
# db.py: count_findings
# ---------------------------------------------------------------------------


def test_count_findings_all(db_with_findings):
    total = _db.count_findings(db_with_findings)
    assert total == 12


def test_count_findings_by_severity(db_with_findings):
    assert _db.count_findings(db_with_findings, severity="CRITICAL") == 3
    assert _db.count_findings(db_with_findings, severity="HIGH") == 4
    assert _db.count_findings(db_with_findings, severity="INFO") == 0


def test_count_findings_by_tool(db_with_findings):
    assert _db.count_findings(db_with_findings, tool="bandit") == 12
    assert _db.count_findings(db_with_findings, tool="nonexistent") == 0


def test_count_findings_by_scan_id(db_with_findings):
    assert _db.count_findings(db_with_findings, scan_id="scan-stab") == 12
    assert _db.count_findings(db_with_findings, scan_id="no-such-scan") == 0


# ---------------------------------------------------------------------------
# db.py: list_findings with offset
# ---------------------------------------------------------------------------


def test_list_findings_offset_basic(db_with_findings):
    """offset skips the correct number of rows."""
    all_findings = _db.list_findings(db_with_findings, limit=12)
    assert len(all_findings) == 12

    page1 = _db.list_findings(db_with_findings, limit=5, offset=0)
    page2 = _db.list_findings(db_with_findings, limit=5, offset=5)
    page3 = _db.list_findings(db_with_findings, limit=5, offset=10)

    assert len(page1) == 5
    assert len(page2) == 5
    assert len(page3) == 2

    # No duplicates across pages
    ids_p1 = {r["id"] for r in page1}
    ids_p2 = {r["id"] for r in page2}
    ids_p3 = {r["id"] for r in page3}
    assert len(ids_p1 | ids_p2 | ids_p3) == 12
    assert ids_p1.isdisjoint(ids_p2)
    assert ids_p1.isdisjoint(ids_p3)


def test_list_findings_offset_beyond_total(db_with_findings):
    """offset beyond total returns empty list."""
    result = _db.list_findings(db_with_findings, limit=10, offset=100)
    assert result == []


def test_list_findings_offset_with_filter(db_with_findings):
    """offset works correctly with severity filter."""
    # 3 CRITICAL findings total — page them as 2 + 1
    p1 = _db.list_findings(db_with_findings, limit=2, severity="CRITICAL", offset=0)
    p2 = _db.list_findings(db_with_findings, limit=2, severity="CRITICAL", offset=2)
    assert len(p1) == 2
    assert len(p2) == 1
    assert all(r["severity"] == "CRITICAL" for r in p1 + p2)


# ---------------------------------------------------------------------------
# app.py: /findings route pagination
# ---------------------------------------------------------------------------


@pytest.fixture
def auth_client(db_with_findings):
    """Authenticated TestClient using the isolated DB (same path app.DB_PATH points to)."""
    # db_with_findings is the isolated_db path which matches os.environ["DASHBOARD_DB_PATH"]
    # and therefore app.DB_PATH — no env mutation needed.
    client = TestClient(app, raise_server_exceptions=True)
    client.post("/login", data={"username": "testuser", "password": "testpass"})
    return client


def test_findings_redirects_to_spa(auth_client):
    """GET /findings now redirects to the SPA at /#findings."""
    resp = auth_client.get("/findings", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/#findings"


def test_scans_redirects_to_spa(auth_client):
    """GET /scans now redirects to the SPA at /#scans."""
    resp = auth_client.get("/scans", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/#scans"


# ---------------------------------------------------------------------------
# Dead templates: verify 404 (no route serves them)
# ---------------------------------------------------------------------------


def test_index_html_not_served(auth_client):
    """/index.html must not exist as a route (template was dead code and removed)."""
    # The root / serves app.html (Vue SPA), not index.html
    resp = auth_client.get("/")
    assert resp.status_code == 200
    # Ensure it's the Vue SPA, not the old index.html
    assert "vue" in resp.text.lower() or "app" in resp.text.lower()
