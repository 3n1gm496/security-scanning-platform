"""
Test per il sistema di export findings.
"""
import json

from export import export_to_json, export_to_csv, export_to_sarif, export_to_html


# Sample findings data
SAMPLE_FINDINGS = [
    {
        "id": 1,
        "scan_id": 123,
        "tool": "trivy",
        "severity": "critical",
        "category": "CVE",
        "cve_id": "CVE-2024-1234",
        "message": "Critical vulnerability in openssl",
        "description": "A critical buffer overflow vulnerability was found",
        "target": "container:myapp:latest",
        "file": "/usr/lib/openssl.so",
        "line": 42
    },
    {
        "id": 2,
        "scan_id": 123,
        "tool": "bandit",
        "severity": "high",
        "category": "B201",
        "message": "Use of insecure pickle",
        "description": "Pickle library can execute arbitrary code",
        "target": "file:app.py",
        "file": "app.py",
        "line": 15
    },
    {
        "id": 3,
        "scan_id": 123,
        "tool": "trivy",
        "severity": "medium",
        "category": "CVE",
        "cve_id": "CVE-2024-5678",
        "message": "Medium severity vulnerability",
        "target": "container:myapp:latest"
    }
]


def test_export_to_json():
    """Test JSON export."""
    result = export_to_json(SAMPLE_FINDINGS)
    
    # Parse JSON
    data = json.loads(result)
    
    assert data["version"] == "1.0"
    assert data["total_findings"] == 3
    assert len(data["findings"]) == 3
    assert data["findings"][0]["id"] == 1
    assert data["findings"][0]["severity"] == "critical"


def test_export_to_json_empty():
    """Test JSON export with empty findings."""
    result = export_to_json([])
    
    data = json.loads(result)
    assert data["total_findings"] == 0
    assert data["findings"] == []


def test_export_to_csv():
    """Test CSV export."""
    result = export_to_csv(SAMPLE_FINDINGS)
    
    lines = result.strip().split("\n")
    assert len(lines) >= 4  # Header + 3 findings
    
    # Check header contains expected fields
    header = lines[0]
    assert "id" in header
    assert "severity" in header
    assert "tool" in header
    
    # Check data rows
    assert "critical" in lines[1]
    assert "high" in lines[2]
    assert "medium" in lines[3]


def test_export_to_csv_empty():
    """Test CSV export with empty findings."""
    result = export_to_csv([])
    assert result == ""


def test_export_to_sarif():
    """Test SARIF export."""
    result = export_to_sarif(SAMPLE_FINDINGS)
    
    # Parse SARIF
    sarif = json.loads(result)
    
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) == 2  # trivy and bandit
    
    # Check first run (trivy)
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] in ["trivy", "bandit"]
    assert "results" in run
    
    # Check results
    total_results = sum(len(run["results"]) for run in sarif["runs"])
    assert total_results == 3
    
    # Check result structure
    result = run["results"][0]
    assert "ruleId" in result
    assert "level" in result
    assert "message" in result
    assert "text" in result["message"]


def test_export_to_sarif_severity_mapping():
    """Test that SARIF severity mapping is correct."""
    findings = [
        {"severity": "critical", "message": "test", "tool": "tool1"},
        {"severity": "high", "message": "test", "tool": "tool1"},
        {"severity": "medium", "message": "test", "tool": "tool1"},
        {"severity": "low", "message": "test", "tool": "tool1"},
        {"severity": "info", "message": "test", "tool": "tool1"},
    ]
    
    result = export_to_sarif(findings)
    sarif = json.loads(result)
    
    results = sarif["runs"][0]["results"]
    assert results[0]["level"] == "error"  # critical -> error
    assert results[1]["level"] == "error"  # high -> error
    assert results[2]["level"] == "warning"  # medium -> warning
    assert results[3]["level"] == "note"  # low -> note
    assert results[4]["level"] == "note"  # info -> note


def test_export_to_html():
    """Test HTML export."""
    result = export_to_html(SAMPLE_FINDINGS)
    
    # Check HTML structure
    assert "<!DOCTYPE html>" in result
    assert "<html" in result
    assert "</html>" in result
    
    # Check content
    assert "Security Scan Report" in result
    assert "critical" in result.lower()
    assert "high" in result.lower()
    assert "medium" in result.lower()
    
    # Check findings are included
    assert "Critical vulnerability in openssl" in result
    assert "Use of insecure pickle" in result
    assert "CVE-2024-1234" in result


def test_export_to_html_with_scan_info():
    """Test HTML export with scan info."""
    scan_info = {
        "scan_id": 123,
        "target": "myapp:latest",
        "initiated_at": "2024-01-01T00:00:00"
    }
    
    result = export_to_html(SAMPLE_FINDINGS, scan_info)
    
    assert "Scan ID: 123" in result
    assert "Target: myapp:latest" in result


def test_export_to_html_empty():
    """Test HTML export with empty findings."""
    result = export_to_html([])
    
    assert "<!DOCTYPE html>" in result
    assert "Total Findings" in result
    assert "Security Scan Report" in result


def test_export_to_html_severity_grouping():
    """Test that HTML groups findings by severity."""
    result = export_to_html(SAMPLE_FINDINGS)
    
    # Check summary cards
    assert ">1<" in result  # 1 critical
    assert ">1<" in result  # 1 high
    assert ">1<" in result  # 1 medium
    
    # Check sections
    assert "CRITICAL Severity (1)" in result
    assert "HIGH Severity (1)" in result
    assert "MEDIUM Severity (1)" in result
