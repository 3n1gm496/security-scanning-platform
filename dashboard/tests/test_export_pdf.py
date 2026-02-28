"""Tests for PDF export functionality."""

from __future__ import annotations

import pytest

from export import export_to_pdf


def test_export_to_pdf_basic():
    """Test basic PDF export with minimal findings."""
    findings = [
        {
            "id": 1,
            "severity": "HIGH",
            "title": "SQL Injection",
            "tool": "bandit",
            "category": "SQL Injection",
            "description": "Possible SQL injection vulnerability",
            "file": "app.py",
            "line": 42,
        },
        {
            "id": 2,
            "severity": "MEDIUM",
            "title": "Hardcoded Password",
            "tool": "semgrep",
            "category": "Hardcoded",
            "description": "Hardcoded credentials detected",
        }
    ]
    
    pdf_content = export_to_pdf(findings)
    
    # Check that PDF content is generated
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    
    # Check PDF magic number
    assert pdf_content[:4] == b'%PDF'


def test_export_to_pdf_with_scan_info():
    """Test PDF export with scan metadata."""
    findings = [
        {
            "severity": "CRITICAL",
            "title": "RCE",
            "tool": "bandit",
            "category": "Command Injection",
            "description": "Remote code execution",
        }
    ]
    
    scan_info = {
        "id": "scan123",
        "target_type": "repository",
        "target_name": "myapp",
        "status": "COMPLETED_WITH_FINDINGS",
        "created_at": "2024-02-28T10:00:00Z",
        "findings_count": 1
    }
    
    pdf_content = export_to_pdf(findings, scan_info)
    
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    assert pdf_content[:4] == b'%PDF'


def test_export_to_pdf_with_analytics():
    """Test PDF export with analytics data."""
    findings = [
        {
            "severity": "HIGH",
            "title": "Security Issue",
            "tool": "trivy",
            "category": "Vulnerability",
            "description": "Security vulnerability detected",
            "cve": "CVE-2024-1234",
        }
    ]
    
    analytics_data = {
        "risk_distribution": {
            "total_findings": 1,
            "average_risk": 75.5,
            "max_risk": 85.0,
            "high_risk_count": 1,
            "distribution": {"0-25": 0, "25-50": 0, "50-75": 0, "75-100": 1}
        }
    }
    
    pdf_content = export_to_pdf(findings, analytics_data=analytics_data)
    
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    assert pdf_content[:4] == b'%PDF'


def test_export_to_pdf_empty_findings():
    """Test PDF export with empty findings list."""
    findings = []
    
    pdf_content = export_to_pdf(findings)
    
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    assert pdf_content[:4] == b'%PDF'


def test_export_to_pdf_many_findings():
    """Test PDF export with many findings."""
    findings = []
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    for i in range(100):
        findings.append({
            "severity": severities[i % 5],
            "title": f"Finding {i}",
            "tool": "test-tool",
            "category": "Test Category",
            "description": f"Test description for finding {i}",
            "file": f"file{i}.py",
            "line": i * 10,
        })
    
    pdf_content = export_to_pdf(findings)
    
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    assert pdf_content[:4] == b'%PDF'


def test_export_to_pdf_all_severities():
    """Test PDF export with all severity levels."""
    findings = [
        {"severity": "CRITICAL", "title": "Critical", "tool": "t1", "category": "c1"},
        {"severity": "HIGH", "title": "High", "tool": "t2", "category": "c2"},
        {"severity": "MEDIUM", "title": "Medium", "tool": "t3", "category": "c3"},
        {"severity": "LOW", "title": "Low", "tool": "t4", "category": "c4"},
        {"severity": "INFO", "title": "Info", "tool": "t5", "category": "c5"},
    ]
    
    pdf_content = export_to_pdf(findings)
    
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    assert pdf_content[:4] == b'%PDF'


def test_export_to_pdf_long_descriptions():
    """Test PDF export with long descriptions."""
    findings = [
        {
            "severity": "HIGH",
            "title": "Long Description Finding",
            "tool": "scanner",
            "category": "Test",
            "description": "A" * 1000,  # Very long description
        }
    ]
    
    pdf_content = export_to_pdf(findings)
    
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    assert pdf_content[:4] == b'%PDF'


def test_export_to_pdf_special_characters():
    """Test PDF export with special characters in content."""
    findings = [
        {
            "severity": "MEDIUM",
            "title": "Test with <special> & characters \"quoted\"",
            "tool": "test-tool",
            "category": "Test",
            "description": "Description with <tags> & symbols \"quotes\" 'apostrophes'",
        }
    ]
    
    pdf_content = export_to_pdf(findings)
    
    assert isinstance(pdf_content, bytes)
    assert len(pdf_content) > 0
    assert pdf_content[:4] == b'%PDF'
