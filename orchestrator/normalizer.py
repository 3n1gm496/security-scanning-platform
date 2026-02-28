from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from orchestrator.models import Finding, TargetSpec, utc_now_iso


SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "UNKNOWN": "UNKNOWN",
}


def _severity(value: str | None, default: str = "MEDIUM") -> str:
    if not value:
        return default
    return SEVERITY_MAP.get(str(value).upper(), str(value).upper())


def _fingerprint(*parts: Any) -> str:
    normalized = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _rel_path(base_path: str | None, file_path: str | None) -> str | None:
    if not file_path:
        return None
    try:
        if base_path:
            return str(Path(file_path).resolve().relative_to(Path(base_path).resolve()))
    except Exception:
        pass
    return file_path


def normalize_semgrep(scan_id: str, target: TargetSpec, raw: dict[str, Any], raw_reference: str, base_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw.get("results", []):
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        start = item.get("start", {}) or {}
        file_path = item.get("path") or item.get("extra", {}).get("path")
        title = metadata.get("shortDescription") or item.get("check_id") or "Semgrep finding"
        description = extra.get("message") or metadata.get("message") or title
        severity = _severity(extra.get("severity") or metadata.get("severity"), "MEDIUM")
        remediation = metadata.get("fix") or metadata.get("fix_regex") or metadata.get("references")
        if isinstance(remediation, list):
            remediation = "; ".join(str(x) for x in remediation)
        finding = Finding(
            scan_id=scan_id,
            timestamp=utc_now_iso(),
            target_type=target.type,
            target_name=target.name,
            tool="semgrep",
            category="sast",
            severity=severity,
            title=title,
            description=description,
            file=_rel_path(base_path, file_path),
            line=start.get("line"),
            package=None,
            version=None,
            cve=metadata.get("cwe") or metadata.get("owasp"),
            remediation=str(remediation) if remediation else None,
            raw_reference=raw_reference,
            fingerprint=_fingerprint("semgrep", target.name, file_path, start.get("line"), item.get("check_id")),
        )
        findings.append(finding)
    return findings


def normalize_trivy(scan_id: str, target: TargetSpec, raw: dict[str, Any], raw_reference: str, base_path: str | None = None, category: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for result in raw.get("Results", []) or []:
        result_target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            finding = Finding(
                scan_id=scan_id,
                timestamp=utc_now_iso(),
                target_type=target.type,
                target_name=target.name,
                tool="trivy",
                category=category or ("container" if target.type == "image" else "sca"),
                severity=_severity(vuln.get("Severity"), "UNKNOWN"),
                title=vuln.get("Title") or vuln.get("PkgName") or vuln.get("VulnerabilityID") or "Trivy vulnerability",
                description=vuln.get("Description") or vuln.get("PrimaryURL") or "Vulnerability detected by Trivy",
                file=_rel_path(base_path, result_target) if target.type != "image" else None,
                line=None,
                package=vuln.get("PkgName"),
                version=vuln.get("InstalledVersion"),
                cve=vuln.get("VulnerabilityID"),
                remediation=vuln.get("FixedVersion"),
                raw_reference=raw_reference,
                fingerprint=_fingerprint("trivy", target.name, result_target, vuln.get("PkgName"), vuln.get("InstalledVersion"), vuln.get("VulnerabilityID")),
            )
            findings.append(finding)
        for misconfig in result.get("Misconfigurations", []) or []:
            finding = Finding(
                scan_id=scan_id,
                timestamp=utc_now_iso(),
                target_type=target.type,
                target_name=target.name,
                tool="trivy",
                category=category or "iac",
                severity=_severity(misconfig.get("Severity"), "MEDIUM"),
                title=misconfig.get("Title") or misconfig.get("ID") or "Trivy misconfiguration",
                description=misconfig.get("Description") or "Misconfiguration detected by Trivy",
                file=_rel_path(base_path, result_target),
                line=None,
                package=None,
                version=None,
                cve=misconfig.get("ID"),
                remediation=misconfig.get("Resolution"),
                raw_reference=raw_reference,
                fingerprint=_fingerprint("trivy-misconfig", target.name, result_target, misconfig.get("ID")),
            )
            findings.append(finding)
        for secret in result.get("Secrets", []) or []:
            finding = Finding(
                scan_id=scan_id,
                timestamp=utc_now_iso(),
                target_type=target.type,
                target_name=target.name,
                tool="trivy",
                category=category or "secret",
                severity=_severity(secret.get("Severity"), "HIGH"),
                title=secret.get("Title") or secret.get("RuleID") or "Potential secret",
                description=secret.get("Match") or "Potential secret detected by Trivy",
                file=_rel_path(base_path, result_target),
                line=secret.get("StartLine"),
                package=None,
                version=None,
                cve=secret.get("RuleID"),
                remediation="Rotate the secret and remove it from source control.",
                raw_reference=raw_reference,
                fingerprint=_fingerprint("trivy-secret", target.name, result_target, secret.get("RuleID"), secret.get("StartLine")),
            )
            findings.append(finding)
    return findings


def normalize_gitleaks(scan_id: str, target: TargetSpec, raw: list[dict[str, Any]], raw_reference: str, base_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw:
        description = item.get("Description") or item.get("RuleID") or "Potential secret detected"
        file_path = item.get("File")
        finding = Finding(
            scan_id=scan_id,
            timestamp=utc_now_iso(),
            target_type=target.type,
            target_name=target.name,
            tool="gitleaks",
            category="secret",
            severity="HIGH",
            title=item.get("RuleID") or "Secret detected",
            description=description,
            file=_rel_path(base_path, file_path),
            line=item.get("StartLine"),
            package=None,
            version=None,
            cve=None,
            remediation="Rotate the secret, remove it from source control, and add an ignore only if justified.",
            raw_reference=raw_reference,
            fingerprint=item.get("Fingerprint") or _fingerprint("gitleaks", target.name, file_path, item.get("StartLine"), item.get("RuleID")),
        )
        findings.append(finding)
    return findings


def normalize_checkov(scan_id: str, target: TargetSpec, raw: Any, raw_reference: str, base_path: str | None = None) -> list[Finding]:
    """
    Checkov JSON output is not fully stable: it can be either:
    - a dict containing {"results": {"failed_checks": [...]}}
    - a list of such dicts (multiple frameworks)
    This normalizer supports both.
    """
    findings: list[Finding] = []

    # Normalize raw payload into a list of result objects
    payloads: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        payloads = [raw]
    elif isinstance(raw, list):
        payloads = [x for x in raw if isinstance(x, dict)]
    else:
        return findings

    for payload in payloads:
        results = payload.get("results", {}) or {}
        failed = results.get("failed_checks", []) or []

        for item in failed:
            line_ranges = item.get("file_line_range") or []
            line = line_ranges[0] if line_ranges else None
            severity = _severity(item.get("severity"), "MEDIUM")
            description = item.get("guideline") or item.get("check_name") or item.get("check_id") or "IaC misconfiguration"

            remediation = item.get("guideline")
            if isinstance(remediation, list):
                remediation = "; ".join(str(x) for x in remediation)

            finding = Finding(
                scan_id=scan_id,
                timestamp=utc_now_iso(),
                target_type=target.type,
                target_name=target.name,
                tool="checkov",
                category="iac",
                severity=severity,
                title=item.get("check_name") or item.get("check_id") or "Checkov finding",
                description=str(description),
                file=_rel_path(base_path, item.get("file_path")),
                line=line,
                package=None,
                version=None,
                cve=item.get("check_id"),
                remediation=str(remediation) if remediation else None,
                raw_reference=raw_reference,
                fingerprint=_fingerprint("checkov", target.name, item.get("file_path"), line, item.get("check_id")),
            )
            findings.append(finding)

    return findings

def normalize_bandit(scan_id: str, target: TargetSpec, raw: dict[str, Any], raw_reference: str, base_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for issue in raw.get("results", []):
        filename = issue.get("filename")
        severity = _severity(issue.get("issue_severity"), "LOW")
        title = issue.get("test_name") or issue.get("issue_text") or "Bandit issue"
        finding = Finding(
            scan_id=scan_id,
            timestamp=utc_now_iso(),
            target_type=target.type,
            target_name=target.name,
            tool="bandit",
            category="sast",
            severity=severity,
            title=title,
            description=issue.get("issue_text") or issue.get("test_text") or "",
            file=_rel_path(base_path, filename),
            line=issue.get("line_number"),
            package=None,
            version=None,
            cve=None,
            remediation=issue.get("more_info"),
            raw_reference=raw_reference,
            fingerprint=_fingerprint("bandit", target.name, filename, issue.get("line_number"), issue.get("test_name")),
        )
        findings.append(finding)
    return findings


def _nuclei_category(info: dict[str, Any]) -> str:
    """Map nuclei template tags to discovery categories.
    
    Nuclei templates use tags to indicate the type of check; we use these
    to classify the finding into security categories.
    """
    tags = info.get("tags", [])
    if not isinstance(tags, list):
        tags = []

    # Map common nuclei tag patterns to categories
    tag_str = " ".join(str(t).lower() for t in tags)

    # Secrets / credential disclosure
    if any(t in tag_str for t in ["credential", "secret", "password", "api-key", "token"]):
        return "secret"
    # Code analysis / SAST patterns
    if any(t in tag_str for t in ["injection", "xss", "sqli", "xxe", "sast", "code-analysis"]):
        return "sast"
    # Network / service discovery
    if any(t in tag_str for t in ["network", "service", "dns", "ftp", "smtp", "ssh", "ssl"]):
        return "network"
    # Web vulnerabilities
    if any(t in tag_str for t in ["web", "http", "ssl-certificate", "cve", "vulnerability"]):
        return "web"
    # IaC / configuration
    if any(t in tag_str for t in ["config", "iac", "terraform", "kubernetes"]):
        return "iac"
    # Default to vulnerabilitydetection
    return "vulnerability"


def normalize_nuclei(scan_id: str, target: TargetSpec, raw: list[dict[str, Any]], raw_reference: str, base_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    # nuclei outputs list of JSON objects; parser may load lines into list
    for item in raw:
        severity = _severity(item.get("severity"), "MEDIUM")
        info = item.get("info", {})
        finding = Finding(
            scan_id=scan_id,
            timestamp=utc_now_iso(),
            target_type=target.type,
            target_name=target.name,
            tool="nuclei",
            category=_nuclei_category(info),
            severity=severity,
            title=info.get("name") or item.get("templateId") or "Nuclei finding",
            description=info.get("description") or "",
            file=_rel_path(base_path, item.get("matched", {}).get("file")),
            line=item.get("matched", {}).get("line"),
            package=None,
            version=None,
            cve=None,
            remediation=info.get("reference"),
            raw_reference=raw_reference,
            fingerprint=_fingerprint("nuclei", target.name, item.get("templateId"), item.get("matched", {}).get("line")),
        )
        findings.append(finding)
    return findings


def normalize_grype(scan_id: str, target: TargetSpec, raw: dict[str, Any], raw_reference: str, base_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for match in raw.get("matches", []) or []:
        # grype match structure contains vulnerability info
        pkg = match.get("artifact", {}).get("name")
        ver = match.get("artifact", {}).get("version")
        vuln = match.get("vulnerability", {})
        severity = _severity(vuln.get("severity"), "UNKNOWN")
        finding = Finding(
            scan_id=scan_id,
            timestamp=utc_now_iso(),
            target_type=target.type,
            target_name=target.name,
            tool="grype",
            category="sca",
            severity=severity,
            title=vuln.get("id") or pkg or "Grype finding",
            description=vuln.get("details") or vuln.get("description") or "",
            file=None,
            line=None,
            package=pkg,
            version=ver,
            cve=vuln.get("id"),
            remediation=vuln.get("fix") or vuln.get("link"),
            raw_reference=raw_reference,
            fingerprint=_fingerprint("grype", target.name, pkg, ver, vuln.get("id")),
        )
        findings.append(finding)
    return findings


def normalize_zap(scan_id: str, target: TargetSpec, raw: list[dict[str, Any]], raw_reference: str, base_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    # zap-cli returns a list of alerts
    for item in raw:
        severity = _severity(item.get("risk"), "MEDIUM")
        finding = Finding(
            scan_id=scan_id,
            timestamp=utc_now_iso(),
            target_type=target.type,
            target_name=target.name,
            tool="zap",
            category="dast",
            severity=severity,
            title=item.get("alert") or "ZAP alert",
            description=item.get("description") or item.get("url") or "",
            file=item.get("url"),
            line=None,
            package=None,
            version=None,
            cve=None,
            remediation=item.get("solution"),
            raw_reference=raw_reference,
            fingerprint=_fingerprint("zap", target.name, item.get("alert"), item.get("url")),
        )
        findings.append(finding)
    return findings


def sbom_metadata(raw_path: str) -> dict[str, Any]:
    path = Path(raw_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages") or payload.get("Packages") or []
    return {
        "artifact_type": "sbom",
        "format": "spdx-json",
        "package_count": len(packages),
        "path": str(path),
    }
