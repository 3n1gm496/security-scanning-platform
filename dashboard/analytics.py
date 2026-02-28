"""Advanced Analytics Module for Security Scanning Platform.

Provides risk scoring, compliance mapping (OWASP Top 10, CWE),
trend analysis, and report generation capabilities.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from typing import Any

from db import get_connection


# OWASP Top 10 2021 mapping
OWASP_TOP_10_MAPPING = {
    "SQL Injection": "A03:2021 - Injection",
    "XSS": "A03:2021 - Injection",
    "Cross-Site Scripting": "A03:2021 - Injection",
    "Command Injection": "A03:2021 - Injection",
    "Authentication": "A07:2021 - Identification and Authentication Failures",
    "Broken Authentication": "A07:2021 - Identification and Authentication Failures",
    "Session Management": "A07:2021 - Identification and Authentication Failures",
    "Sensitive Data Exposure": "A02:2021 - Cryptographic Failures",
    "Cryptographic": "A02:2021 - Cryptographic Failures",
    "XXE": "A05:2021 - Security Misconfiguration",
    "XML External Entity": "A05:2021 - Security Misconfiguration",
    "Access Control": "A01:2021 - Broken Access Control",
    "Authorization": "A01:2021 - Broken Access Control",
    "CSRF": "A01:2021 - Broken Access Control",
    "Insecure Deserialization": "A08:2021 - Software and Data Integrity Failures",
    "Security Misconfiguration": "A05:2021 - Security Misconfiguration",
    "Vulnerable Components": "A06:2021 - Vulnerable and Outdated Components",
    "Logging": "A09:2021 - Security Logging and Monitoring Failures",
    "Monitoring": "A09:2021 - Security Logging and Monitoring Failures",
    "SSRF": "A10:2021 - Server-Side Request Forgery",
    "Hardcoded": "A05:2021 - Security Misconfiguration",
}

# Common CWE mappings
CWE_MAPPING = {
    "SQL Injection": "CWE-89",
    "XSS": "CWE-79",
    "Cross-Site Scripting": "CWE-79",
    "Command Injection": "CWE-78",
    "Path Traversal": "CWE-22",
    "Authentication": "CWE-287",
    "Broken Authentication": "CWE-287",
    "Hardcoded": "CWE-798",
    "Cryptographic": "CWE-327",
    "XXE": "CWE-611",
    "CSRF": "CWE-352",
    "Access Control": "CWE-285",
    "Authorization": "CWE-285",
    "SSRF": "CWE-918",
    "Insecure Deserialization": "CWE-502",
}

# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0,
    "UNKNOWN": 3.0,
}


def calculate_risk_score(finding: dict[str, Any]) -> float:
    """Calculate risk score for a finding (0-100).
    
    Scoring factors:
    - Severity (base weight)
    - CVE presence (+20%)
    - File/line specificity (+10%)
    - Category criticality (SQL Injection, RCE, etc: +15%)
    """
    severity = finding.get("severity", "UNKNOWN").upper()
    base_score = SEVERITY_WEIGHTS.get(severity, 3.0) * 10  # Scale to 0-100
    
    # CVE bonus
    if finding.get("cve"):
        base_score *= 1.2
    
    # Location specificity bonus
    if finding.get("file") and finding.get("line"):
        base_score *= 1.1
    
    # Critical category bonus
    category = (finding.get("category") or "").lower()
    critical_categories = ["sql injection", "command injection", "rce", "authentication"]
    if any(cat in category for cat in critical_categories):
        base_score *= 1.15
    
    return min(base_score, 100.0)


def map_to_owasp(category: str) -> str | None:
    """Map finding category to OWASP Top 10 2021."""
    if not category:
        return None
    
    category_lower = category.lower()
    for keyword, owasp_cat in OWASP_TOP_10_MAPPING.items():
        if keyword.lower() in category_lower:
            return owasp_cat
    return None


def map_to_cwe(category: str) -> str | None:
    """Map finding category to CWE identifier."""
    if not category:
        return None
    
    category_lower = category.lower()
    for keyword, cwe in CWE_MAPPING.items():
        if keyword.lower() in category_lower:
            return cwe
    return None


def get_risk_distribution(db_path: str) -> dict[str, Any]:
    """Calculate risk score distribution across all findings."""
    with get_connection(db_path) as conn:
        findings = conn.execute(
            "SELECT severity, category, cve, file, line FROM findings"
        ).fetchall()
    
    risk_scores = [calculate_risk_score(dict(f)) for f in findings]
    
    if not risk_scores:
        return {
            "total_findings": 0,
            "average_risk": 0.0,
            "max_risk": 0.0,
            "high_risk_count": 0,
            "distribution": {"0-25": 0, "25-50": 0, "50-75": 0, "75-100": 0},
        }
    
    distribution = {"0-25": 0, "25-50": 0, "50-75": 0, "75-100": 0}
    high_risk_count = 0
    
    for score in risk_scores:
        if score >= 75:
            distribution["75-100"] += 1
            high_risk_count += 1
        elif score >= 50:
            distribution["50-75"] += 1
            high_risk_count += 1
        elif score >= 25:
            distribution["25-50"] += 1
        else:
            distribution["0-25"] += 1
    
    return {
        "total_findings": len(risk_scores),
        "average_risk": round(sum(risk_scores) / len(risk_scores), 2),
        "max_risk": round(max(risk_scores), 2),
        "high_risk_count": high_risk_count,
        "distribution": distribution,
    }


def get_compliance_summary(db_path: str) -> dict[str, Any]:
    """Generate OWASP Top 10 and CWE compliance summary."""
    with get_connection(db_path) as conn:
        findings = conn.execute("SELECT category, severity FROM findings").fetchall()
    
    owasp_counts: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}
    unmapped_count = 0
    
    for finding in findings:
        category = finding["category"] or ""
        
        owasp = map_to_owasp(category)
        if owasp:
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
        else:
            unmapped_count += 1
        
        cwe = map_to_cwe(category)
        if cwe:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    # Sort by count descending
    owasp_sorted = sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)
    cwe_sorted = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
    
    return {
        "owasp_top_10": [{"category": k, "count": v} for k, v in owasp_sorted],
        "cwe_top": [{"cwe": k, "count": v} for k, v in cwe_sorted[:20]],
        "unmapped_findings": unmapped_count,
        "total_findings": len(findings),
    }


def get_trend_analysis(db_path: str, days: int = 90) -> dict[str, Any]:
    """Detailed trend analysis with risk scoring over time."""
    with get_connection(db_path) as conn:
        # Get findings grouped by day
        rows = conn.execute(
            """
            SELECT 
                substr(timestamp, 1, 10) AS day,
                severity,
                category,
                cve,
                file,
                line
            FROM findings
            WHERE substr(timestamp, 1, 10) >= date('now', ?)
            ORDER BY day ASC
            """,
            (f"-{days} day",),
        ).fetchall()
    
    # Group by day
    daily_data: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        day = row["day"]
        if day not in daily_data:
            daily_data[day] = []
        daily_data[day].append(dict(row))
    
    # Calculate daily metrics
    trend_points = []
    for day in sorted(daily_data.keys()):
        findings = daily_data[day]
        risk_scores = [calculate_risk_score(f) for f in findings]
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "UNKNOWN").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        trend_points.append({
            "date": day,
            "total_findings": len(findings),
            "average_risk": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0,
            "max_risk": round(max(risk_scores), 2) if risk_scores else 0,
            "severity_breakdown": severity_counts,
        })
    
    return {
        "period_days": days,
        "data_points": len(trend_points),
        "trend": trend_points,
    }


def get_target_risk_ranking(db_path: str) -> list[dict[str, Any]]:
    """Rank targets by aggregated risk score."""
    with get_connection(db_path) as conn:
        findings = conn.execute(
            "SELECT target_name, severity, category, cve, file, line FROM findings"
        ).fetchall()
    
    # Group by target
    target_findings: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        target = f["target_name"]
        if target not in target_findings:
            target_findings[target] = []
        target_findings[target].append(dict(f))
    
    # Calculate risk for each target
    target_risks = []
    for target, finds in target_findings.items():
        risk_scores = [calculate_risk_score(f) for f in finds]
        total_risk = sum(risk_scores)
        avg_risk = total_risk / len(risk_scores) if risk_scores else 0
        
        target_risks.append({
            "target": target,
            "findings_count": len(finds),
            "total_risk": round(total_risk, 2),
            "average_risk": round(avg_risk, 2),
            "max_risk": round(max(risk_scores), 2) if risk_scores else 0,
        })
    
    # Sort by total risk descending
    target_risks.sort(key=lambda x: x["total_risk"], reverse=True)
    return target_risks


def get_tool_effectiveness(db_path: str) -> list[dict[str, Any]]:
    """Analyze tool effectiveness by findings and risk detection."""
    with get_connection(db_path) as conn:
        findings = conn.execute(
            "SELECT tool, severity, category, cve, file, line FROM findings"
        ).fetchall()
    
    # Group by tool
    tool_findings: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        tool = f["tool"]
        if tool not in tool_findings:
            tool_findings[tool] = []
        tool_findings[tool].append(dict(f))
    
    # Calculate metrics for each tool
    tool_metrics = []
    for tool, finds in tool_findings.items():
        risk_scores = [calculate_risk_score(f) for f in finds]
        high_risk_findings = sum(1 for score in risk_scores if score >= 50)
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in finds:
            sev = f.get("severity", "").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        tool_metrics.append({
            "tool": tool,
            "total_findings": len(finds),
            "high_risk_findings": high_risk_findings,
            "average_risk": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0,
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
        })
    
    # Sort by high risk findings
    tool_metrics.sort(key=lambda x: x["high_risk_findings"], reverse=True)
    return tool_metrics
