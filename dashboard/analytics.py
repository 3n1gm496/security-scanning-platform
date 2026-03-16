"""Advanced Analytics Module for Security Scanning Platform.

Provides risk scoring, compliance mapping (OWASP Top 10, CWE),
trend analysis, and report generation capabilities.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from db import get_connection

# OWASP Top 10 2021 mapping — exact category match.
# Includes both the orchestrator normalizer categories (sast, sca, iac, etc.)
# and the fine-grained categories used by nuclei/specific scanners.
OWASP_TOP_10_CATEGORY_MAPPING: dict[str, str] = {
    # A01 — Broken Access Control
    "csrf": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "path-traversal": "A01:2021 - Broken Access Control",
    "iam": "A01:2021 - Broken Access Control",
    # A02 — Cryptographic Failures
    "crypto": "A02:2021 - Cryptographic Failures",
    "encryption": "A02:2021 - Cryptographic Failures",
    "secret": "A02:2021 - Cryptographic Failures",
    # A03 — Injection (sast covers static analysis findings: injection, XSS, etc.)
    "sast": "A03:2021 - Injection",
    "sqli": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "subprocess": "A03:2021 - Injection",
    "dast": "A03:2021 - Injection",
    # A05 — Security Misconfiguration (iac findings are misconfigurations)
    "misconfig": "A05:2021 - Security Misconfiguration",
    "iac": "A05:2021 - Security Misconfiguration",
    "network": "A05:2021 - Security Misconfiguration",
    # A06 — Vulnerable and Outdated Components (sca/container/vulnerability)
    "cve": "A06:2021 - Vulnerable and Outdated Components",
    "sca": "A06:2021 - Vulnerable and Outdated Components",
    "container": "A06:2021 - Vulnerable and Outdated Components",
    "vulnerability": "A06:2021 - Vulnerable and Outdated Components",
    "web": "A06:2021 - Vulnerable and Outdated Components",
    # A08 — Software and Data Integrity Failures
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    # A09 — Security Logging and Monitoring Failures
    "logging": "A09:2021 - Security Logging and Monitoring Failures",
    # A10 — Server-Side Request Forgery
    "ssrf": "A10:2021 - Server-Side Request Forgery",
}

# Keyword-based OWASP mapping applied to the finding title when category alone
# does not produce a match.  Each tuple is (keyword, owasp_category).
OWASP_TITLE_KEYWORDS: list[tuple[str, str]] = [
    ("access control", "A01:2021 - Broken Access Control"),
    ("authorization", "A01:2021 - Broken Access Control"),
    ("traversal", "A01:2021 - Broken Access Control"),
    ("csrf", "A01:2021 - Broken Access Control"),
    ("hardcoded", "A02:2021 - Cryptographic Failures"),
    ("password", "A02:2021 - Cryptographic Failures"),
    ("private key", "A02:2021 - Cryptographic Failures"),
    ("secret", "A02:2021 - Cryptographic Failures"),
    ("crypto", "A02:2021 - Cryptographic Failures"),
    ("injection", "A03:2021 - Injection"),
    ("xss", "A03:2021 - Injection"),
    ("sql", "A03:2021 - Injection"),
    ("command", "A03:2021 - Injection"),
    ("eval(", "A03:2021 - Injection"),
    ("deserializ", "A08:2021 - Software and Data Integrity Failures"),
    ("ssrf", "A10:2021 - Server-Side Request Forgery"),
    ("misconfigur", "A05:2021 - Security Misconfiguration"),
    ("cve-", "A06:2021 - Vulnerable and Outdated Components"),
    ("vulnerable", "A06:2021 - Vulnerable and Outdated Components"),
    ("outdated", "A06:2021 - Vulnerable and Outdated Components"),
]

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


def _risk_score_sql() -> str:
    base_score = (
        "CASE UPPER(severity) "
        "WHEN 'CRITICAL' THEN 100.0 "
        "WHEN 'HIGH' THEN 75.0 "
        "WHEN 'MEDIUM' THEN 50.0 "
        "WHEN 'LOW' THEN 25.0 "
        "WHEN 'INFO' THEN 10.0 "
        "ELSE 30.0 END"
    )
    cve_multiplier = "CASE WHEN COALESCE(cve, '') <> '' THEN 1.2 ELSE 1.0 END"
    location_multiplier = "CASE WHEN COALESCE(file, '') <> '' AND line IS NOT NULL THEN 1.1 ELSE 1.0 END"
    critical_multiplier = (
        "CASE WHEN lower(COALESCE(category, '')) LIKE '%sql injection%' "
        "OR lower(COALESCE(category, '')) LIKE '%command injection%' "
        "OR lower(COALESCE(category, '')) LIKE '%rce%' "
        "OR lower(COALESCE(category, '')) LIKE '%authentication%' "
        "THEN 1.15 ELSE 1.0 END"
    )
    raw_score = f"(({base_score}) * ({cve_multiplier}) * ({location_multiplier}) * ({critical_multiplier}))"
    return f"CASE WHEN {raw_score} > 100.0 THEN 100.0 ELSE {raw_score} END"


def _owasp_case_sql() -> str:
    return """
        CASE
            WHEN lower(COALESCE(category, '')) = 'csrf' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(category, '')) = 'idor' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(category, '')) = 'path-traversal' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(category, '')) = 'iam' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(category, '')) = 'crypto' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(category, '')) = 'encryption' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(category, '')) = 'secret' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(category, '')) = 'sast' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(category, '')) = 'sqli' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(category, '')) = 'xss' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(category, '')) = 'subprocess' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(category, '')) = 'dast' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(category, '')) = 'misconfig' THEN 'A05:2021 - Security Misconfiguration'
            WHEN lower(COALESCE(category, '')) = 'iac' THEN 'A05:2021 - Security Misconfiguration'
            WHEN lower(COALESCE(category, '')) = 'network' THEN 'A05:2021 - Security Misconfiguration'
            WHEN lower(COALESCE(category, '')) = 'cve' THEN 'A06:2021 - Vulnerable and Outdated Components'
            WHEN lower(COALESCE(category, '')) = 'sca' THEN 'A06:2021 - Vulnerable and Outdated Components'
            WHEN lower(COALESCE(category, '')) = 'container' THEN 'A06:2021 - Vulnerable and Outdated Components'
            WHEN lower(COALESCE(category, '')) = 'vulnerability' THEN 'A06:2021 - Vulnerable and Outdated Components'
            WHEN lower(COALESCE(category, '')) = 'web' THEN 'A06:2021 - Vulnerable and Outdated Components'
            WHEN lower(COALESCE(category, '')) = 'deserialization'
                THEN 'A08:2021 - Software and Data Integrity Failures'
            WHEN lower(COALESCE(category, '')) = 'logging' THEN 'A09:2021 - Security Logging and Monitoring Failures'
            WHEN lower(COALESCE(category, '')) = 'ssrf' THEN 'A10:2021 - Server-Side Request Forgery'
            WHEN lower(COALESCE(title, '')) LIKE '%access control%' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(title, '')) LIKE '%authorization%' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(title, '')) LIKE '%traversal%' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(title, '')) LIKE '%csrf%' THEN 'A01:2021 - Broken Access Control'
            WHEN lower(COALESCE(title, '')) LIKE '%hardcoded%' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(title, '')) LIKE '%password%' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(title, '')) LIKE '%private key%' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(title, '')) LIKE '%secret%' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(title, '')) LIKE '%crypto%' THEN 'A02:2021 - Cryptographic Failures'
            WHEN lower(COALESCE(title, '')) LIKE '%injection%' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(title, '')) LIKE '%xss%' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(title, '')) LIKE '%sql%' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(title, '')) LIKE '%command%' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(title, '')) LIKE '%eval(%' THEN 'A03:2021 - Injection'
            WHEN lower(COALESCE(title, '')) LIKE '%deserializ%' THEN 'A08:2021 - Software and Data Integrity Failures'
            WHEN lower(COALESCE(title, '')) LIKE '%ssrf%' THEN 'A10:2021 - Server-Side Request Forgery'
            WHEN lower(COALESCE(title, '')) LIKE '%misconfigur%' THEN 'A05:2021 - Security Misconfiguration'
            WHEN lower(COALESCE(title, '')) LIKE '%cve-%' THEN 'A06:2021 - Vulnerable and Outdated Components'
            WHEN lower(COALESCE(title, '')) LIKE '%vulnerable%' THEN 'A06:2021 - Vulnerable and Outdated Components'
            WHEN lower(COALESCE(title, '')) LIKE '%outdated%' THEN 'A06:2021 - Vulnerable and Outdated Components'
            ELSE NULL
        END
    """


def _cwe_case_sql() -> str:
    return """
        CASE
            WHEN lower(COALESCE(category, '')) LIKE '%sql injection%' THEN 'CWE-89'
            WHEN lower(COALESCE(category, '')) LIKE '%xss%' THEN 'CWE-79'
            WHEN lower(COALESCE(category, '')) LIKE '%cross-site scripting%' THEN 'CWE-79'
            WHEN lower(COALESCE(category, '')) LIKE '%command injection%' THEN 'CWE-78'
            WHEN lower(COALESCE(category, '')) LIKE '%path traversal%' THEN 'CWE-22'
            WHEN lower(COALESCE(category, '')) LIKE '%authentication%' THEN 'CWE-287'
            WHEN lower(COALESCE(category, '')) LIKE '%broken authentication%' THEN 'CWE-287'
            WHEN lower(COALESCE(category, '')) LIKE '%hardcoded%' THEN 'CWE-798'
            WHEN lower(COALESCE(category, '')) LIKE '%cryptographic%' THEN 'CWE-327'
            WHEN lower(COALESCE(category, '')) LIKE '%xxe%' THEN 'CWE-611'
            WHEN lower(COALESCE(category, '')) LIKE '%csrf%' THEN 'CWE-352'
            WHEN lower(COALESCE(category, '')) LIKE '%access control%' THEN 'CWE-285'
            WHEN lower(COALESCE(category, '')) LIKE '%authorization%' THEN 'CWE-285'
            WHEN lower(COALESCE(category, '')) LIKE '%ssrf%' THEN 'CWE-918'
            WHEN lower(COALESCE(category, '')) LIKE '%insecure deserialization%' THEN 'CWE-502'
            ELSE NULL
        END
    """


def _date_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()


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


def map_to_owasp(category: str, title: str = "") -> str | None:
    """Map finding category (and optionally title) to OWASP Top 10 2021.

    First tries exact match on the category.  If that fails, scans the
    finding title for known keywords.
    """
    if category:
        result = OWASP_TOP_10_CATEGORY_MAPPING.get(category.lower())
        if result:
            return result

    # Fallback: keyword match on title
    if title:
        title_lower = title.lower()
        for keyword, owasp in OWASP_TITLE_KEYWORDS:
            if keyword in title_lower:
                return owasp

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
    risk_sql = _risk_score_sql()
    query_template = """
        SELECT
            COUNT(*) AS total_findings,
            COALESCE(AVG(__RISK_SQL__), 0.0) AS average_risk,
            COALESCE(MAX(__RISK_SQL__), 0.0) AS max_risk,
            COALESCE(SUM(CASE WHEN __RISK_SQL__ >= 50 THEN 1 ELSE 0 END), 0) AS high_risk_count,
            COALESCE(SUM(CASE WHEN __RISK_SQL__ >= 75 THEN 1 ELSE 0 END), 0) AS bucket_75_100,
            COALESCE(SUM(CASE WHEN __RISK_SQL__ >= 50 AND __RISK_SQL__ < 75 THEN 1 ELSE 0 END), 0) AS bucket_50_75,
            COALESCE(SUM(CASE WHEN __RISK_SQL__ >= 25 AND __RISK_SQL__ < 50 THEN 1 ELSE 0 END), 0) AS bucket_25_50,
            COALESCE(SUM(CASE WHEN __RISK_SQL__ < 25 THEN 1 ELSE 0 END), 0) AS bucket_0_25
        FROM findings
        """
    query = query_template.replace("__RISK_SQL__", risk_sql)
    with get_connection(db_path) as conn:
        row = conn.execute(query).fetchone()

    if not row or int(row["total_findings"]) == 0:
        return {
            "total_findings": 0,
            "average_risk": 0.0,
            "max_risk": 0.0,
            "high_risk_count": 0,
            "distribution": {"0-25": 0, "25-50": 0, "50-75": 0, "75-100": 0},
        }

    return {
        "total_findings": int(row["total_findings"]),
        "average_risk": round(float(row["average_risk"]), 2),
        "max_risk": round(float(row["max_risk"]), 2),
        "high_risk_count": int(row["high_risk_count"]),
        "distribution": {
            "0-25": int(row["bucket_0_25"]),
            "25-50": int(row["bucket_25_50"]),
            "50-75": int(row["bucket_50_75"]),
            "75-100": int(row["bucket_75_100"]),
        },
    }


def get_compliance_summary(db_path: str) -> dict[str, Any]:
    """Generate OWASP Top 10 and CWE compliance summary."""
    owasp_case = _owasp_case_sql()
    cwe_case = _cwe_case_sql()
    owasp_query_template = """
        SELECT mapped_owasp AS category, COUNT(*) AS count
        FROM (
            SELECT __OWASP_CASE__ AS mapped_owasp
            FROM findings
        ) mapped
        WHERE mapped_owasp IS NOT NULL
        GROUP BY mapped_owasp
        ORDER BY count DESC, mapped_owasp ASC
        """
    cwe_query_template = """
        SELECT mapped_cwe AS cwe, COUNT(*) AS count
        FROM (
            SELECT __CWE_CASE__ AS mapped_cwe
            FROM findings
        ) mapped
        WHERE mapped_cwe IS NOT NULL
        GROUP BY mapped_cwe
        ORDER BY count DESC, mapped_cwe ASC
        """
    totals_query_template = """
        SELECT
            COUNT(*) AS total_findings,
            COALESCE(SUM(CASE WHEN __OWASP_CASE__ IS NULL THEN 1 ELSE 0 END), 0) AS unmapped_findings
        FROM findings
        """
    owasp_query = owasp_query_template.replace("__OWASP_CASE__", owasp_case)
    cwe_query = cwe_query_template.replace("__CWE_CASE__", cwe_case)
    totals_query = totals_query_template.replace("__OWASP_CASE__", owasp_case)
    with get_connection(db_path) as conn:
        owasp_rows = conn.execute(owasp_query).fetchall()
        cwe_rows = conn.execute(cwe_query).fetchall()
        totals = conn.execute(totals_query).fetchone()

    return {
        "owasp_top_10": [{"category": row["category"], "count": row["count"]} for row in owasp_rows],
        "cwe_top": [{"cwe": row["cwe"], "count": row["count"]} for row in cwe_rows[:20]],
        "unmapped_findings": int(totals["unmapped_findings"]),
        "total_findings": int(totals["total_findings"]),
    }


def get_trend_analysis(db_path: str, days: int = 90) -> dict[str, Any]:
    """Detailed trend analysis with risk scoring over time."""
    cutoff = _date_days_ago(days)
    risk_sql = _risk_score_sql()
    query_template = """
        SELECT
            substr(timestamp, 1, 10) AS day,
            COUNT(*) AS total_findings,
            COALESCE(AVG(__RISK_SQL__), 0.0) AS average_risk,
            COALESCE(MAX(__RISK_SQL__), 0.0) AS max_risk,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 ELSE 0 END), 0) AS high_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS medium_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'LOW' THEN 1 ELSE 0 END), 0) AS low_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'INFO' THEN 1 ELSE 0 END), 0) AS info_count
        FROM findings
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY substr(timestamp, 1, 10)
        ORDER BY day ASC
        """
    query = query_template.replace("__RISK_SQL__", risk_sql)
    with get_connection(db_path) as conn:
        rows = conn.execute(query, (cutoff,)).fetchall()

    trend_points = []
    for row in rows:
        trend_points.append(
            {
                "date": row["day"],
                "total_findings": int(row["total_findings"]),
                "average_risk": round(float(row["average_risk"]), 2),
                "max_risk": round(float(row["max_risk"]), 2),
                "severity_breakdown": {
                    "CRITICAL": int(row["critical_count"]),
                    "HIGH": int(row["high_count"]),
                    "MEDIUM": int(row["medium_count"]),
                    "LOW": int(row["low_count"]),
                    "INFO": int(row["info_count"]),
                },
            }
        )

    return {
        "period_days": days,
        "data_points": len(trend_points),
        "trend": trend_points,
    }


def get_target_risk_ranking(db_path: str) -> list[dict[str, Any]]:
    """Rank targets by aggregated risk score."""
    risk_sql = _risk_score_sql()
    query_template = """
        SELECT
            target_name AS target,
            COUNT(*) AS findings_count,
            ROUND(COALESCE(SUM(__RISK_SQL__), 0.0), 2) AS total_risk,
            ROUND(COALESCE(AVG(__RISK_SQL__), 0.0), 2) AS average_risk,
            ROUND(COALESCE(MAX(__RISK_SQL__), 0.0), 2) AS max_risk
        FROM findings
        GROUP BY target_name
        ORDER BY total_risk DESC, target_name ASC
        """
    query = query_template.replace("__RISK_SQL__", risk_sql)
    with get_connection(db_path) as conn:
        rows = conn.execute(query).fetchall()
    return [dict(row) for row in rows]


def get_tool_effectiveness(db_path: str) -> list[dict[str, Any]]:
    """Analyze tool effectiveness by findings and risk detection."""
    risk_sql = _risk_score_sql()
    query_template = """
        SELECT
            tool,
            COUNT(*) AS total_findings,
            COALESCE(SUM(CASE WHEN __RISK_SQL__ >= 50 THEN 1 ELSE 0 END), 0) AS high_risk_findings,
            ROUND(COALESCE(AVG(__RISK_SQL__), 0.0), 2) AS average_risk,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 ELSE 0 END), 0) AS high_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS medium_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'LOW' THEN 1 ELSE 0 END), 0) AS low_count,
            COALESCE(SUM(CASE WHEN UPPER(severity) = 'INFO' THEN 1 ELSE 0 END), 0) AS info_count
        FROM findings
        GROUP BY tool
        ORDER BY high_risk_findings DESC, tool ASC
        """
    query = query_template.replace("__RISK_SQL__", risk_sql)
    with get_connection(db_path) as conn:
        rows = conn.execute(query).fetchall()
    return [dict(row) for row in rows]
