"""Tests for advanced analytics module."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from analytics import (
    calculate_risk_score,
    map_to_owasp,
    map_to_cwe,
    get_risk_distribution,
    get_compliance_summary,
    get_trend_analysis,
    get_target_risk_ranking,
    get_tool_effectiveness,
)


@pytest.fixture
def analytics_db(tmp_path, monkeypatch):
    """Create test database with sample findings for analytics."""
    db_path = str(tmp_path / "analytics_test.db")
    
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_name TEXT NOT NULL,
            tool TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            file TEXT,
            line INTEGER,
            package TEXT,
            version TEXT,
            cve TEXT,
            remediation TEXT,
            raw_reference TEXT,
            fingerprint TEXT
        )
    """)
    
    # Insert test findings with various attributes
    now = datetime.now(timezone.utc)
    findings_data = [
        # High risk findings
        ("scan1", (now - timedelta(days=1)).isoformat(), "repo", "app1", "bandit", "SQL Injection", "CRITICAL", "SQL Injection vulnerability", "desc", "app.py", 42, None, None, "CVE-2024-1234", None, None, "fp1"),
        ("scan1", (now - timedelta(days=1)).isoformat(), "repo", "app1", "semgrep", "Command Injection", "HIGH", "Command injection in subprocess", "desc", "cmd.py", 10, None, None, None, None, None, "fp2"),
        ("scan2", (now - timedelta(days=2)).isoformat(), "repo", "app2", "trivy", "Vulnerable Components", "HIGH", "Outdated dependency", "desc", None, None, "requests", "2.0.0", "CVE-2024-5678", None, None, "fp3"),
        
        # Medium risk findings
        ("scan2", (now - timedelta(days=2)).isoformat(), "repo", "app2", "bandit", "Hardcoded Password", "MEDIUM", "Hardcoded credentials", "desc", "config.py", 5, None, None, None, None, None, "fp4"),
        ("scan3", (now - timedelta(days=5)).isoformat(), "repo", "app3", "semgrep", "CSRF", "MEDIUM", "Missing CSRF token", "desc", "views.py", 100, None, None, None, None, None, "fp5"),
        
        # Low risk findings
        ("scan3", (now - timedelta(days=5)).isoformat(), "repo", "app3", "bandit", "Logging", "LOW", "Insecure logging", "desc", None, None, None, None, None, None, None, "fp6"),
        ("scan4", (now - timedelta(days=10)).isoformat(), "container", "nginx", "trivy", "Security Misconfiguration", "INFO", "Missing security header", "desc", None, None, None, None, None, None, None, "fp7"),
    ]
    
    conn.executemany(
        "INSERT INTO findings (scan_id, timestamp, target_type, target_name, tool, category, severity, title, description, file, line, package, version, cve, remediation, raw_reference, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        findings_data
    )
    
    conn.commit()
    conn.close()
    
    return db_path


def test_calculate_risk_score_critical_with_cve():
    """Test risk score calculation for critical finding with CVE."""
    finding = {
        "severity": "CRITICAL",
        "category": "SQL Injection",
        "cve": "CVE-2024-1234",
        "file": "app.py",
        "line": 42
    }
    
    score = calculate_risk_score(finding)
    
    # Base: 10.0 * 10 = 100
    # CVE: 100 * 1.2 = 120
    # Location: 120 * 1.1 = 132
    # Critical category: 132 * 1.15 = 151.8
    # Capped at 100
    assert score == 100.0


def test_calculate_risk_score_high_no_bonuses():
    """Test risk score for high severity without bonuses."""
    finding = {
        "severity": "HIGH",
        "category": "Other",
    }
    
    score = calculate_risk_score(finding)
    
    # Base: 7.5 * 10 = 75
    assert score == 75.0


def test_calculate_risk_score_medium():
    """Test risk score for medium severity."""
    finding = {
        "severity": "MEDIUM",
        "file": "test.py",
        "line": 10
    }
    
    score = calculate_risk_score(finding)
    
    # Base: 5.0 * 10 = 50
    # Location: 50 * 1.1 = 55
    assert score == pytest.approx(55.0, rel=1e-6)


def test_calculate_risk_score_unknown():
    """Test risk score for unknown severity."""
    finding = {"severity": "UNKNOWN"}
    
    score = calculate_risk_score(finding)
    assert score == 30.0  # 3.0 * 10


def test_map_to_owasp_sql_injection():
    """Test OWASP mapping for SQL injection."""
    assert map_to_owasp("SQL Injection") == "A03:2021 - Injection"
    assert map_to_owasp("sql injection vulnerability") == "A03:2021 - Injection"


def test_map_to_owasp_authentication():
    """Test OWASP mapping for authentication issues."""
    assert map_to_owasp("Broken Authentication") == "A07:2021 - Identification and Authentication Failures"
    assert map_to_owasp("authentication bypass") == "A07:2021 - Identification and Authentication Failures"


def test_map_to_owasp_unmapped():
    """Test OWASP mapping for unmapped category."""
    assert map_to_owasp("Unknown Category") is None
    assert map_to_owasp("") is None
    assert map_to_owasp(None) is None


def test_map_to_cwe_sql_injection():
    """Test CWE mapping for SQL injection."""
    assert map_to_cwe("SQL Injection") == "CWE-89"


def test_map_to_cwe_xss():
    """Test CWE mapping for XSS."""
    assert map_to_cwe("Cross-Site Scripting") == "CWE-79"
    assert map_to_cwe("XSS vulnerability") == "CWE-79"


def test_map_to_cwe_unmapped():
    """Test CWE mapping for unmapped category."""
    assert map_to_cwe("Unknown") is None
    assert map_to_cwe("") is None


def test_get_risk_distribution(analytics_db):
    """Test risk distribution calculation."""
    result = get_risk_distribution(analytics_db)
    
    assert result["total_findings"] == 7
    assert result["average_risk"] > 0
    assert result["max_risk"] <= 100.0
    assert result["high_risk_count"] > 0
    
    # Check distribution buckets
    distribution = result["distribution"]
    assert "0-25" in distribution
    assert "25-50" in distribution
    assert "50-75" in distribution
    assert "75-100" in distribution
    
    # Total counts should match
    total = sum(distribution.values())
    assert total == 7


def test_get_risk_distribution_empty_db(tmp_path):
    """Test risk distribution with no findings."""
    db_path = str(tmp_path / "empty.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY,
            severity TEXT,
            category TEXT,
            cve TEXT,
            file TEXT,
            line INTEGER
        )
    """)
    conn.close()
    
    result = get_risk_distribution(db_path)
    
    assert result["total_findings"] == 0
    assert result["average_risk"] == 0.0
    assert result["max_risk"] == 0.0
    assert result["high_risk_count"] == 0


def test_get_compliance_summary(analytics_db):
    """Test compliance summary generation."""
    result = get_compliance_summary(analytics_db)
    
    assert "owasp_top_10" in result
    assert "cwe_top" in result
    assert "unmapped_findings" in result
    assert "total_findings" in result
    
    assert result["total_findings"] == 7
    
    # Should have mapped some findings
    owasp_mapped = sum(item["count"] for item in result["owasp_top_10"])
    assert owasp_mapped > 0
    
    cwe_mapped = sum(item["count"] for item in result["cwe_top"])
    assert cwe_mapped > 0
    
    # Check structure
    if result["owasp_top_10"]:
        assert "category" in result["owasp_top_10"][0]
        assert "count" in result["owasp_top_10"][0]
    
    if result["cwe_top"]:
        assert "cwe" in result["cwe_top"][0]
        assert "count" in result["cwe_top"][0]


def test_get_trend_analysis(analytics_db):
    """Test trend analysis."""
    result = get_trend_analysis(analytics_db, days=30)
    
    assert result["period_days"] == 30
    assert result["data_points"] > 0
    assert "trend" in result
    
    # Check trend data structure
    for point in result["trend"]:
        assert "date" in point
        assert "total_findings" in point
        assert "average_risk" in point
        assert "max_risk" in point
        assert "severity_breakdown" in point
        
        breakdown = point["severity_breakdown"]
        assert "CRITICAL" in breakdown
        assert "HIGH" in breakdown
        assert "MEDIUM" in breakdown
        assert "LOW" in breakdown
        assert "INFO" in breakdown


def test_get_trend_analysis_short_period(analytics_db):
    """Test trend analysis with short period."""
    result = get_trend_analysis(analytics_db, days=7)
    
    assert result["period_days"] == 7
    assert result["data_points"] >= 0


def test_get_target_risk_ranking(analytics_db):
    """Test target risk ranking."""
    result = get_target_risk_ranking(analytics_db)
    
    assert len(result) > 0
    
    # Check structure
    for target in result:
        assert "target" in target
        assert "findings_count" in target
        assert "total_risk" in target
        assert "average_risk" in target
        assert "max_risk" in target
        
        assert target["findings_count"] > 0
        assert target["total_risk"] >= 0
        assert target["average_risk"] >= 0
    
    # Should be sorted by total_risk descending
    if len(result) > 1:
        assert result[0]["total_risk"] >= result[1]["total_risk"]


def test_get_tool_effectiveness(analytics_db):
    """Test tool effectiveness analysis."""
    result = get_tool_effectiveness(analytics_db)
    
    assert len(result) > 0
    
    # Check structure
    for tool in result:
        assert "tool" in tool
        assert "total_findings" in tool
        assert "high_risk_findings" in tool
        assert "average_risk" in tool
        assert "critical_count" in tool
        assert "high_count" in tool
        
        assert tool["total_findings"] > 0
        assert tool["high_risk_findings"] >= 0
        assert tool["average_risk"] >= 0
    
    # Should be sorted by high_risk_findings descending
    if len(result) > 1:
        assert result[0]["high_risk_findings"] >= result[1]["high_risk_findings"]


def test_risk_score_capping():
    """Test that risk scores are capped at 100."""
    finding = {
        "severity": "CRITICAL",
        "category": "SQL Injection",
        "cve": "CVE-2024-1234",
        "file": "app.py",
        "line": 42
    }
    
    score = calculate_risk_score(finding)
    assert score <= 100.0


def test_compliance_mapping_case_insensitive():
    """Test that compliance mapping is case-insensitive."""
    assert map_to_owasp("sql injection") == map_to_owasp("SQL INJECTION")
    assert map_to_cwe("csrf") == map_to_cwe("CSRF")
