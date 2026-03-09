"""Unit tests for remediation engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation import RemediationEngine


def test_generate_specific_cwe_template():
    finding = {
        "title": "SQL Injection (CWE-89)",
        "description": "Unsanitized input",
        "severity": "CRITICAL",
        "file": "app.py",
        "line": 10,
    }
    result = RemediationEngine.generate_remediation(finding)
    assert result["cwe"] == "CWE-89"
    assert "steps" in result and len(result["steps"]) > 0
    assert "code_example" in result
    assert "references" in result


def test_generate_generic_when_no_cwe():
    finding = {"title": "Unknown issue", "description": "No CWE", "severity": "LOW"}
    result = RemediationEngine.generate_remediation(finding)
    assert result["cwe"] is None
    assert result["title"] == "Generic Security Fix"
    assert len(result["steps"]) > 0


def test_cwe_mapping_shape():
    for _, template in RemediationEngine.CWE_REMEDIATION.items():
        assert "title" in template
        assert "steps" in template and isinstance(template["steps"], list)
        assert "code_example" in template
        assert "references" in template and isinstance(template["references"], list)


def test_priority_mapping_by_severity():
    crit = RemediationEngine.generate_remediation({"title": "x (CWE-79)", "severity": "CRITICAL"})
    low = RemediationEngine.generate_remediation({"title": "x (CWE-79)", "severity": "LOW"})
    assert "URGENT" in crit["priority"]
    assert "Low Priority" in low["priority"]
