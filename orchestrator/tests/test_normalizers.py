from orchestrator.normalizer import (
    normalize_bandit,
    normalize_nuclei,
    normalize_grype,
    normalize_zap,
    normalize_semgrep,
)
from orchestrator.models import TargetSpec

# minimal target used in tests
TARGET = TargetSpec(name="demo", type="local", path="/tmp")


def test_normalize_bandit_empty():
    data = {"results": []}
    findings = normalize_bandit("scan1", TARGET, data, "ref")
    assert findings == []


def test_normalize_bandit_simple():
    data = {
        "results": [
            {
                "filename": "app.py",
                "issue_severity": "LOW",
                "test_name": "B101",
                "issue_text": "Use of assert detected",
                "line_number": 42,
                "more_info": "https://bandit.example.com/B101",
            }
        ]
    }
    findings = normalize_bandit("scan1", TARGET, data, "ref")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "bandit"
    assert f.severity == "LOW"
    assert "assert" in f.description


def test_normalize_nuclei_empty():
    findings = normalize_nuclei("s", TARGET, [], "ref")
    assert findings == []


def test_normalize_nuclei_example():
    raw = [
        {
            "templateId": "nuclei-test",
            "severity": "high",
            "info": {"name": "Test", "description": "desc", "tags": ["xss", "injection"]},
            "matched": {"file": "test.txt", "line": 10},
        }
    ]
    findings = normalize_nuclei("s", TARGET, raw, "ref")
    assert len(findings) == 1
    assert findings[0].tool == "nuclei"
    assert findings[0].severity == "HIGH"
    # tags contain injection/xss → should map to sast
    assert findings[0].category == "sast"


def test_normalize_nuclei_credentials():
    # credentials tag should map to secret category
    raw = [
        {
            "templateId": "creds-check",
            "severity": "medium",
            "info": {
                "name": "Credentials Disclosure Check",
                "description": "Found exposed credentials",
                "tags": ["credentials", "discovery"],
            },
            "matched": {"file": "config.py"},
        }
    ]
    findings = normalize_nuclei("s", TARGET, raw, "ref")
    assert len(findings) == 1
    assert findings[0].category == "secret"
    assert findings[0].severity == "MEDIUM"


def test_normalize_nuclei_no_tags():
    # no tags → fallback to 'vulnerability'
    raw = [
        {
            "templateId": "generic-check",
            "severity": "low",
            "info": {"name": "URL Extension Inspector", "description": "Check file extensions", "tags": []},
            "matched": {"file": "index.html"},
        }
    ]
    findings = normalize_nuclei("s", TARGET, raw, "ref")
    assert len(findings) == 1
    # empty tags → vulnerability
    assert findings[0].category == "vulnerability"


def test_normalize_nuclei_matcher_name():
    """matcher-name should be appended to the title for sub-findings."""
    raw = [
        {
            "templateId": "http-missing-security-headers",
            "template-id": "http-missing-security-headers",
            "severity": "info",
            "info": {"name": "HTTP Missing Security Headers", "description": "desc", "tags": ["misconfig"]},
            "matcher-name": "strict-transport-security",
            "matched-at": "https://example.com",
        },
        {
            "templateId": "http-missing-security-headers",
            "template-id": "http-missing-security-headers",
            "severity": "info",
            "info": {"name": "HTTP Missing Security Headers", "description": "desc", "tags": ["misconfig"]},
            "matcher-name": "x-frame-options",
            "matched-at": "https://example.com",
        },
    ]
    findings = normalize_nuclei("s", TARGET, raw, "ref")
    assert len(findings) == 2
    assert findings[0].title == "HTTP Missing Security Headers: strict-transport-security"
    assert findings[1].title == "HTTP Missing Security Headers: x-frame-options"
    # Fingerprints should be different despite same templateId
    assert findings[0].fingerprint != findings[1].fingerprint


def test_normalize_grype_empty():
    findings = normalize_grype("s", TARGET, {"matches": []}, "ref")
    assert findings == []


def test_normalize_grype_example():
    raw = {
        "matches": [
            {
                "artifact": {"name": "pkg", "version": "1.0"},
                "vulnerability": {"id": "CVE-1234", "severity": "LOW", "details": "foo"},
            }
        ]
    }
    findings = normalize_grype("s", TARGET, raw, "ref")
    assert len(findings) == 1
    assert findings[0].package == "pkg"
    assert findings[0].cve == "CVE-1234"


def test_normalize_zap_empty():
    findings = normalize_zap("s", TARGET, [], "ref")
    assert findings == []


def test_normalize_zap_example():
    raw = [
        {
            "alert": "Test alert",
            "risk": "High",
            "url": "http://example.com",
            "description": "issue",
            "solution": "fix it",
        }
    ]
    findings = normalize_zap("s", TARGET, raw, "ref")
    assert len(findings) == 1
    assert findings[0].tool == "zap"
    assert findings[0].severity == "HIGH"


def test_normalize_zap_cwe():
    """ZAP alerts with cweid should populate the cve field as CWE-NNN."""
    raw = [
        {
            "alert": "SQL Injection",
            "risk": "High",
            "url": "http://example.com/login",
            "description": "sql injection",
            "solution": "parameterize queries",
            "cweid": "89",
            "pluginId": "40018",
        }
    ]
    findings = normalize_zap("s", TARGET, raw, "ref")
    assert len(findings) == 1
    assert findings[0].cve == "CWE-89"


def test_normalize_zap_no_cwe():
    """ZAP alerts without cweid or with cweid=0 should have cve=None."""
    raw = [
        {"alert": "Info", "risk": "Low", "url": "http://x.com", "cweid": "0"},
        {"alert": "Info2", "risk": "Low", "url": "http://x.com"},
    ]
    findings = normalize_zap("s", TARGET, raw, "ref")
    assert findings[0].cve is None
    assert findings[1].cve is None


# sanity check existing semgrep still works


def test_semgrep_roundtrip():
    raw = {
        "results": [
            {
                "check_id": "test",
                "path": "file.py",
                "extra": {"severity": "MEDIUM", "message": "msg"},
                "start": {"line": 1},
            }
        ]
    }
    findings = normalize_semgrep("s", TARGET, raw, "ref", base_path="/tmp")
    assert findings and findings[0].tool == "semgrep"


def test_normalize_zap_informational():
    """ZAP alerts with risk='Informational' or 'Inform' should be normalized to 'INFO'."""
    raw = [
        {"alert": "Info 1", "risk": "Informational", "url": "http://x.com"},
        {"alert": "Info 2", "risk": "Inform", "url": "http://x.com"},
    ]
    findings = normalize_zap("s", TARGET, raw, "ref")
    assert findings[0].severity == "INFO"
    assert findings[1].severity == "INFO"
