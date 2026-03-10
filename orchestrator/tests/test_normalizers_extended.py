"""Extended normalizer tests covering trivy, gitleaks, checkov, and sbom_metadata."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from orchestrator.models import TargetSpec
from orchestrator.normalizer import (
    normalize_trivy,
    normalize_gitleaks,
    normalize_checkov,
    sbom_metadata,
    _severity,
    _fingerprint,
    _rel_path,
)

TARGET_LOCAL = TargetSpec(name="myrepo", type="local", path="/tmp/repo")
TARGET_IMAGE = TargetSpec(name="myimage", type="image", path="nginx:latest")


# ---------------------------------------------------------------------------
# _severity helper
# ---------------------------------------------------------------------------

def test_severity_known_values():
    assert _severity("CRITICAL") == "CRITICAL"
    assert _severity("HIGH") == "HIGH"
    assert _severity("MEDIUM") == "MEDIUM"
    assert _severity("LOW") == "LOW"
    assert _severity("INFO") == "INFO"
    assert _severity("WARN") == "MEDIUM"
    assert _severity("WARNING") == "MEDIUM"
    assert _severity("ERROR") == "HIGH"
    assert _severity("MODERATE") == "MEDIUM"
    assert _severity("UNKNOWN") == "UNKNOWN"


def test_severity_none_returns_default():
    assert _severity(None) == "MEDIUM"
    assert _severity(None, "HIGH") == "HIGH"
    assert _severity("", "LOW") == "LOW"


def test_severity_passthrough_unknown_value():
    # Unknown values are uppercased and returned as-is
    result = _severity("EXTREME")
    assert result == "EXTREME"


# ---------------------------------------------------------------------------
# _fingerprint helper
# ---------------------------------------------------------------------------

def test_fingerprint_deterministic():
    a = _fingerprint("tool", "target", "file.py", 42, "CVE-1234")
    b = _fingerprint("tool", "target", "file.py", 42, "CVE-1234")
    assert a == b


def test_fingerprint_differs_on_change():
    a = _fingerprint("tool", "target", "file.py", 42)
    b = _fingerprint("tool", "target", "file.py", 43)
    assert a != b


def test_fingerprint_handles_none():
    # Should not raise even with None parts
    result = _fingerprint("tool", None, None)
    assert isinstance(result, str) and len(result) == 64


# ---------------------------------------------------------------------------
# _rel_path helper
# ---------------------------------------------------------------------------

def test_rel_path_with_base():
    result = _rel_path("/tmp/repo", "/tmp/repo/src/app.py")
    assert result == "src/app.py"


def test_rel_path_without_base():
    result = _rel_path(None, "/tmp/repo/src/app.py")
    assert result == "/tmp/repo/src/app.py"


def test_rel_path_none_file():
    assert _rel_path("/tmp", None) is None


def test_rel_path_outside_base():
    # File outside base → fallback to original path
    result = _rel_path("/tmp/repo", "/etc/passwd")
    assert result == "/etc/passwd"


# ---------------------------------------------------------------------------
# normalize_trivy
# ---------------------------------------------------------------------------

def test_normalize_trivy_empty():
    findings = normalize_trivy("s1", TARGET_LOCAL, {"Results": []}, "ref")
    assert findings == []


def test_normalize_trivy_no_results_key():
    findings = normalize_trivy("s1", TARGET_LOCAL, {}, "ref")
    assert findings == []


def test_normalize_trivy_vulnerabilities():
    raw = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0001",
                        "PkgName": "requests",
                        "InstalledVersion": "2.28.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH",
                        "Title": "Request smuggling",
                        "Description": "HTTP request smuggling vulnerability",
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
                    }
                ],
            }
        ]
    }
    findings = normalize_trivy("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "trivy"
    assert f.cve == "CVE-2023-0001"
    assert f.package == "requests"
    assert f.version == "2.28.0"
    assert f.remediation == "2.31.0"
    assert f.severity == "HIGH"
    assert f.category == "sca"


def test_normalize_trivy_image_target():
    """For image targets, file should be None."""
    raw = {
        "Results": [
            {
                "Target": "nginx:latest (debian 11.6)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-9999",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "Severity": "CRITICAL",
                    }
                ],
            }
        ]
    }
    findings = normalize_trivy("s1", TARGET_IMAGE, raw, "ref")
    assert len(findings) == 1
    assert findings[0].file is None
    assert findings[0].category == "container"


def test_normalize_trivy_misconfigurations():
    raw = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Image user should not be root",
                        "Description": "Running as root is dangerous",
                        "Severity": "HIGH",
                        "Resolution": "Add USER directive",
                    }
                ],
            }
        ]
    }
    findings = normalize_trivy("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "trivy"
    assert f.category == "iac"
    assert f.cve == "DS002"
    assert f.remediation == "Add USER directive"


def test_normalize_trivy_secrets():
    raw = {
        "Results": [
            {
                "Target": "config/settings.py",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Title": "AWS Access Key ID",
                        "Match": "AKIAIOSFODNN7EXAMPLE",
                        "Severity": "CRITICAL",
                        "StartLine": 10,
                    }
                ],
            }
        ]
    }
    findings = normalize_trivy("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "trivy"
    assert f.category == "secret"
    assert f.severity == "CRITICAL"
    assert f.line == 10
    assert f.cve == "aws-access-key-id"


def test_normalize_trivy_mixed_results():
    """Single result with vulns + misconfigs + secrets."""
    raw = {
        "Results": [
            {
                "Target": "app/",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-A",
                        "PkgName": "pkg",
                        "InstalledVersion": "1.0",
                        "Severity": "MEDIUM",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "MC001",
                        "Title": "Bad config",
                        "Severity": "LOW",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "generic-api-key",
                        "Severity": "HIGH",
                        "StartLine": 5,
                    }
                ],
            }
        ]
    }
    findings = normalize_trivy("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 3
    tools = {f.tool for f in findings}
    assert tools == {"trivy"}
    categories = {f.category for f in findings}
    assert "sca" in categories
    assert "iac" in categories
    assert "secret" in categories


def test_normalize_trivy_custom_category():
    raw = {
        "Results": [
            {
                "Target": "img",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-X",
                        "PkgName": "lib",
                        "InstalledVersion": "0.1",
                        "Severity": "LOW",
                    }
                ],
            }
        ]
    }
    findings = normalize_trivy("s1", TARGET_LOCAL, raw, "ref", category="custom")
    assert findings[0].category == "custom"


# ---------------------------------------------------------------------------
# normalize_gitleaks
# ---------------------------------------------------------------------------

def test_normalize_gitleaks_empty():
    findings = normalize_gitleaks("s1", TARGET_LOCAL, [], "ref")
    assert findings == []


def test_normalize_gitleaks_simple():
    raw = [
        {
            "Description": "AWS Access Key",
            "RuleID": "aws-access-key-id",
            "File": "config.py",
            "StartLine": 42,
            "Fingerprint": "abc123",
        }
    ]
    findings = normalize_gitleaks("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "gitleaks"
    assert f.category == "secret"
    assert f.severity == "HIGH"
    assert f.title == "aws-access-key-id"
    assert f.line == 42
    assert f.fingerprint == "abc123"


def test_normalize_gitleaks_no_fingerprint():
    """When no Fingerprint in raw, a computed one should be generated."""
    raw = [
        {
            "RuleID": "generic-secret",
            "File": "app.py",
            "StartLine": 1,
        }
    ]
    findings = normalize_gitleaks("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    assert findings[0].fingerprint is not None
    assert len(findings[0].fingerprint) == 64  # sha256 hex


def test_normalize_gitleaks_multiple():
    raw = [
        {"RuleID": "secret-1", "File": "a.py", "StartLine": 1, "Fingerprint": "fp1"},
        {"RuleID": "secret-2", "File": "b.py", "StartLine": 2, "Fingerprint": "fp2"},
        {"RuleID": "secret-3", "File": "c.py", "StartLine": 3, "Fingerprint": "fp3"},
    ]
    findings = normalize_gitleaks("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 3
    assert all(f.tool == "gitleaks" for f in findings)


def test_normalize_gitleaks_description_fallback():
    """When Description is missing, falls back to RuleID."""
    raw = [{"RuleID": "my-rule", "File": "x.py", "StartLine": 1}]
    findings = normalize_gitleaks("s1", TARGET_LOCAL, raw, "ref")
    assert findings[0].description == "my-rule"


def test_normalize_gitleaks_with_base_path():
    raw = [
        {
            "RuleID": "secret",
            "File": "/tmp/repo/src/config.py",
            "StartLine": 5,
            "Fingerprint": "xyz",
        }
    ]
    findings = normalize_gitleaks("s1", TARGET_LOCAL, raw, "ref", base_path="/tmp/repo")
    assert findings[0].file == "src/config.py"


# ---------------------------------------------------------------------------
# normalize_checkov
# ---------------------------------------------------------------------------

def test_normalize_checkov_empty_dict():
    raw = {"results": {"failed_checks": [], "passed_checks": []}}
    findings = normalize_checkov("s1", TARGET_LOCAL, raw, "ref")
    assert findings == []


def test_normalize_checkov_empty_list():
    findings = normalize_checkov("s1", TARGET_LOCAL, [], "ref")
    assert findings == []


def test_normalize_checkov_invalid_type():
    findings = normalize_checkov("s1", TARGET_LOCAL, "not-a-dict-or-list", "ref")
    assert findings == []


def test_normalize_checkov_single_dict():
    raw = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_2",
                    "check_name": "Ensure that HEALTHCHECK instructions have been added",
                    "file_path": "/tmp/repo/Dockerfile",
                    "file_line_range": [1, 10],
                    "severity": "LOW",
                    "guideline": "https://docs.checkov.io/...",
                }
            ]
        }
    }
    findings = normalize_checkov("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "checkov"
    assert f.category == "iac"
    assert f.cve == "CKV_DOCKER_2"
    assert f.severity == "LOW"
    assert f.line == 1


def test_normalize_checkov_list_of_dicts():
    """Checkov can return a list of framework results."""
    raw = [
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_1",
                        "check_name": "Do not admit root containers",
                        "file_path": "k8s/deploy.yaml",
                        "file_line_range": [5, 20],
                        "severity": "HIGH",
                    }
                ]
            }
        },
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_TF_1",
                        "check_name": "Ensure Terraform module sources use a commit hash",
                        "file_path": "main.tf",
                        "file_line_range": [3, 3],
                        "severity": "MEDIUM",
                    }
                ]
            }
        },
    ]
    findings = normalize_checkov("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 2
    check_ids = {f.cve for f in findings}
    assert "CKV_K8S_1" in check_ids
    assert "CKV_TF_1" in check_ids


def test_normalize_checkov_no_severity():
    """Missing severity should default to MEDIUM."""
    raw = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_X_1",
                    "check_name": "Some check",
                    "file_path": "file.tf",
                    "file_line_range": [],
                }
            ]
        }
    }
    findings = normalize_checkov("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_normalize_checkov_guideline_list():
    """Guideline as list should be joined into string."""
    raw = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_X_2",
                    "check_name": "Check with list guideline",
                    "file_path": "file.tf",
                    "file_line_range": [1, 1],
                    "guideline": ["https://example.com/1", "https://example.com/2"],
                }
            ]
        }
    }
    findings = normalize_checkov("s1", TARGET_LOCAL, raw, "ref")
    assert len(findings) == 1
    assert "https://example.com/1" in findings[0].remediation
    assert "https://example.com/2" in findings[0].remediation


# ---------------------------------------------------------------------------
# sbom_metadata
# ---------------------------------------------------------------------------

def test_sbom_metadata_basic(tmp_path):
    sbom_file = tmp_path / "sbom.json"
    sbom_data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"name": "requests", "versionInfo": "2.28.0"},
            {"name": "flask", "versionInfo": "2.3.0"},
        ],
    }
    sbom_file.write_text(json.dumps(sbom_data), encoding="utf-8")
    meta = sbom_metadata(str(sbom_file))
    assert meta["artifact_type"] == "sbom"
    assert meta["format"] == "spdx-json"
    assert meta["package_count"] == 2
    assert meta["path"] == str(sbom_file)


def test_sbom_metadata_empty_packages(tmp_path):
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}), encoding="utf-8")
    meta = sbom_metadata(str(sbom_file))
    assert meta["package_count"] == 0


def test_sbom_metadata_no_packages_key(tmp_path):
    """If 'packages' key is missing, count should be 0."""
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
    meta = sbom_metadata(str(sbom_file))
    assert meta["package_count"] == 0
