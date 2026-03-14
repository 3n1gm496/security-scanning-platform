"""Unit tests for charting engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from charting import ChartingEngine
import sqlite3


def _setup_test_db():
    """Create test database with sample data."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            target_name TEXT,
            target_type TEXT,
            status TEXT,
            created_at TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            title TEXT,
            description TEXT,
            severity TEXT,
            file TEXT,
            tool TEXT,
            cve TEXT,
            timestamp TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE finding_states (
            finding_id INTEGER,
            status TEXT
        )
    """)

    # Insert test data
    for i in range(5):
        conn.execute(
            """
            INSERT INTO scans VALUES (?, ?, 'repository', 'completed', datetime('now', '-' || ? || ' days'))
        """,
            (i + 1, f"target-{i}", i),
        )

    for i in range(20):
        severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4]
        tool = ["semgrep", "bandit", "nuclei"][i % 3]
        cve = f"CVE-2024-{1000+i}" if i < 10 else None
        scan_id = (i % 5) + 1

        conn.execute(
            """
            INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-' || ? || ' days'))
        """,
            (i + 1, scan_id, f"Finding {i}", f"Desc {i}", severity, f"file{i}.py", tool, cve, i // 5),
        )

    conn.commit()
    return conn


def test_severity_distribution():
    """Test severity distribution chart data."""
    conn = _setup_test_db()
    data = ChartingEngine.severity_distribution(conn, days=30)

    assert "labels" in data
    assert "datasets" in data
    assert len(data["datasets"]) > 0
    assert all("label" in ds for ds in data["datasets"])

    conn.close()


def test_tool_effectiveness():
    """Test tool effectiveness chart data."""
    conn = _setup_test_db()
    data = ChartingEngine.tool_effectiveness(conn)

    assert "labels" in data
    assert "datasets" in data
    assert len(data["labels"]) > 0
    assert all(label in ["semgrep", "bandit", "nuclei"] for label in data["labels"])

    conn.close()


def test_target_risk_heatmap():
    """Test target risk heatmap data."""
    conn = _setup_test_db()
    data = ChartingEngine.target_risk_heatmap(conn)

    assert "targets" in data
    assert "data" in data
    assert len(data["data"]) > 0
    assert all("risk_score" in item and "target" in item for item in data["data"])

    conn.close()


def test_scan_status_trend():
    """Test scan status trend chart data."""
    conn = _setup_test_db()
    data = ChartingEngine.scan_status_trend(conn, days=30)

    assert "labels" in data
    assert "datasets" in data
    assert any("Completed" in ds["label"] for ds in data["datasets"])

    conn.close()


def test_remediation_progress():
    """Test remediation progress chart data."""
    conn = _setup_test_db()
    data = ChartingEngine.remediation_progress(conn)

    assert "labels" in data
    assert "datasets" in data
    assert len(data["labels"]) > 0

    conn.close()


def test_cve_distribution():
    """Test CVE distribution chart data."""
    conn = _setup_test_db()
    data = ChartingEngine.cve_distribution(conn)

    assert "labels" in data
    assert "datasets" in data
    assert len(data["labels"]) > 0
    assert all("CVE-" in label for label in data["labels"])

    conn.close()
