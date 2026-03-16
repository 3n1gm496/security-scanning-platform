#!/usr/bin/env python3
"""
Seed script for development and demo environments.

Populates the database with realistic-looking security scan data so that
the dashboard can be explored without running actual scans.

Usage:
    python3 scripts/seed_dev_data.py [--db-path /path/to/db] [--clear]

Options:
    --db-path   Path to the SQLite database file.
                Defaults to DASHBOARD_DB_PATH env var or ./data/security_scans.db
    --clear     Drop all existing data before seeding (default: append)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = os.environ.get(
    "DASHBOARD_DB_PATH",
    str(Path(__file__).parent.parent / "data" / "security_scans.db"),
)

TARGETS = [
    ("url", "api.example.com", "https://api.example.com"),
    ("url", "shop.example.com", "https://shop.example.com"),
    ("url", "admin.example.com", "https://admin.example.com"),
    ("repo", "example/backend", "https://github.com/example/backend"),
    ("repo", "example/frontend", "https://github.com/example/frontend"),
    ("container", "nginx:1.25", "docker.io/library/nginx:1.25"),
    ("container", "node:20-alpine", "docker.io/library/node:20-alpine"),
]

TOOLS = ["zap", "trivy", "semgrep", "bandit", "nuclei", "gitleaks", "checkov"]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_WEIGHTS = [0.05, 0.15, 0.30, 0.30, 0.20]

CATEGORIES = {
    "zap": ["sqli", "xss", "csrf", "ssrf", "idor", "open-redirect", "misconfig"],
    "trivy": ["cve", "misconfig", "secret", "license"],
    "semgrep": ["injection", "auth", "crypto", "path-traversal", "deserialization"],
    "bandit": ["injection", "crypto", "hardcoded-secret", "subprocess", "pickle"],
    "nuclei": ["cve", "misconfig", "exposure", "takeover", "fuzzing"],
    "gitleaks": ["secret", "api-key", "token", "password"],
    "checkov": ["misconfig", "iam", "network", "encryption", "logging"],
}

FINDING_TEMPLATES = [
    ("SQL Injection", "A SQL injection vulnerability allows attackers to manipulate database queries.", "HIGH", "sqli"),
    ("Cross-Site Scripting (XSS)", "Reflected XSS vulnerability found in user input field.", "MEDIUM", "xss"),
    ("Outdated Package with CVE", "Package contains a known vulnerability (CVE-2024-XXXX).", "HIGH", "cve"),
    ("Hardcoded Secret", "An API key or password was found hardcoded in the source code.", "CRITICAL", "secret"),
    ("Missing Security Headers", "The response is missing security headers such as CSP and HSTS.", "LOW", "misconfig"),
    ("Insecure Direct Object Reference", "IDOR vulnerability allows access to other users' data.", "HIGH", "idor"),
    ("Server-Side Request Forgery", "SSRF vulnerability allows requests to internal services.", "CRITICAL", "ssrf"),
    ("Weak Cryptography", "MD5 or SHA1 used for password hashing.", "HIGH", "crypto"),
    ("Path Traversal", "User input is used in file paths without sanitization.", "HIGH", "path-traversal"),
    ("Open Redirect", "User-controlled redirect target allows phishing attacks.", "MEDIUM", "open-redirect"),
    ("Exposed Debug Endpoint", "A debug or admin endpoint is exposed without authentication.", "MEDIUM", "exposure"),
    ("Insecure Deserialization", "Untrusted data is deserialized without validation.", "CRITICAL", "deserialization"),
    ("Privilege Escalation via IAM", "IAM role allows excessive permissions.", "HIGH", "iam"),
    ("Unencrypted Data at Rest", "Sensitive data is stored without encryption.", "MEDIUM", "encryption"),
    ("Missing Audit Logging", "Critical operations are not logged for audit purposes.", "LOW", "logging"),
    ("CSRF Token Missing", "Form submission does not include a CSRF token.", "MEDIUM", "csrf"),
    ("Leaked Token in Git History", "An access token was committed to the repository.", "CRITICAL", "token"),
    ("Container Running as Root", "Container image runs as the root user.", "MEDIUM", "misconfig"),
    ("Outdated Base Image", "The base image has known vulnerabilities.", "HIGH", "cve"),
    ("Subprocess Shell Injection", "User input is passed to a subprocess shell command.", "HIGH", "subprocess"),
]

REMEDIATION_TEMPLATES = {
    "sqli": "Use parameterised queries or prepared statements. Never concatenate user input into SQL strings.",
    "xss": "Encode all user-supplied output. Use a Content Security Policy header.",
    "cve": "Upgrade the affected package to the latest patched version.",
    "secret": "Remove the secret from the codebase immediately. Rotate the exposed credential. Use a secrets manager.",
    "misconfig": "Review and apply the recommended security configuration baseline.",
    "idor": "Implement server-side authorisation checks for every resource access.",
    "ssrf": "Validate and allowlist URLs. Block requests to internal IP ranges.",
    "crypto": "Replace MD5/SHA1 with bcrypt, Argon2, or SHA-256 for password hashing.",
    "path-traversal": "Sanitise file paths and use os.path.realpath to resolve canonical paths.",
    "open-redirect": "Validate redirect targets against an allowlist of trusted domains.",
    "exposure": "Remove or protect debug endpoints with authentication and IP allowlisting.",
    "deserialization": "Avoid deserialising untrusted data. Use safe formats like JSON.",
    "iam": "Apply the principle of least privilege. Review and restrict IAM permissions.",
    "encryption": "Enable encryption at rest using AES-256 or equivalent.",
    "logging": "Implement structured audit logging for all sensitive operations.",
    "csrf": "Add CSRF tokens to all state-changing forms and validate them server-side.",
    "token": "Revoke the exposed token immediately. Use git-filter-repo to purge history.",
    "subprocess": "Avoid shell=True in subprocess calls. Use argument lists instead.",
}

FINDING_STATES = ["open", "open", "open", "in_progress", "resolved", "false_positive"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_scan_id() -> str:
    return str(uuid.uuid4())


def _random_date(start: datetime, end: datetime) -> datetime:
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def _generate_findings(scan_id: str, target_name: str, tool: str, n: int) -> list[dict]:
    findings = []
    for _ in range(n):
        template = random.choice(FINDING_TEMPLATES)
        title, description, default_sev, category = template
        severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
        remediation = REMEDIATION_TEMPLATES.get(category, "Review and fix the issue.")
        findings.append(
            {
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target_type": "url",
                "target_name": target_name,
                "tool": tool,
                "category": category,
                "severity": severity,
                "title": title,
                "description": description,
                "file": f"src/{random.choice(['app', 'api', 'utils', 'models'])}.py" if random.random() > 0.5 else None,
                "line": random.randint(1, 500) if random.random() > 0.5 else None,
                "package": f"package-{random.randint(1, 50)}" if random.random() > 0.6 else None,
                "version": f"1.{random.randint(0, 9)}.{random.randint(0, 20)}" if random.random() > 0.6 else None,
                "cve": f"CVE-2024-{random.randint(10000, 99999)}" if category == "cve" else None,
                "remediation": remediation,
                "raw_reference": json.dumps({"source": tool, "rule": f"{tool}-{category}-001"}),
                "fingerprint": str(uuid.uuid4()),
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Main seeding logic
# ---------------------------------------------------------------------------


def seed(db_path: str, clear: bool = False) -> None:
    print(f"Seeding database: {db_path}")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Ensure schema exists
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_name TEXT NOT NULL,
            target_value TEXT NOT NULL,
            status TEXT NOT NULL,
            policy_status TEXT NOT NULL,
            findings_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0,
            info_count INTEGER NOT NULL DEFAULT 0,
            unknown_count INTEGER NOT NULL DEFAULT 0,
            raw_report_dir TEXT NOT NULL DEFAULT '',
            normalized_report_path TEXT NOT NULL DEFAULT '',
            artifacts_json TEXT NOT NULL DEFAULT '[]',
            tools_json TEXT NOT NULL DEFAULT '[]',
            error_message TEXT
        );
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
            description TEXT NOT NULL,
            file TEXT,
            line INTEGER,
            package TEXT,
            version TEXT,
            cve TEXT,
            remediation TEXT,
            raw_reference TEXT,
            fingerprint TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)
    conn.commit()

    if clear:
        print("  Clearing existing data...")
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM scans")
        conn.commit()

    # Generate 30 scans over the last 90 days
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=90)

    scans_inserted = 0
    findings_inserted = 0

    for i in range(30):
        target_type, target_name, target_value = random.choice(TARGETS)
        tool = random.choice(TOOLS)
        scan_id = _random_scan_id()
        created_at = _random_date(start_date, now)
        duration_seconds = random.randint(30, 600)
        finished_at = created_at + timedelta(seconds=duration_seconds)
        status = random.choices(["completed", "completed", "completed", "failed"], weights=[0.85, 0.85, 0.85, 0.15])[0]
        policy_status = random.choices(["pass", "fail"], weights=[0.6, 0.4])[0]

        n_findings = 0 if status == "failed" else random.randint(0, 25)
        findings = _generate_findings(scan_id, target_name, tool, n_findings)
        counts = _severity_counts(findings)

        try:
            conn.execute(
                """
                INSERT INTO scans (
                    id, created_at, finished_at, target_type, target_name,
                    target_value, status, policy_status, findings_count,
                    critical_count, high_count, medium_count, low_count,
                    info_count, unknown_count, raw_report_dir,
                    normalized_report_path, artifacts_json, tools_json, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    created_at.isoformat(),
                    finished_at.isoformat(),
                    target_type,
                    target_name,
                    target_value,
                    status,
                    policy_status,
                    n_findings,
                    counts["CRITICAL"],
                    counts["HIGH"],
                    counts["MEDIUM"],
                    counts["LOW"],
                    counts["INFO"],
                    counts["UNKNOWN"],
                    f"/data/reports/{scan_id}/raw",
                    f"/data/reports/{scan_id}/normalized.json",
                    json.dumps([]),
                    json.dumps([tool]),
                    "Scan failed due to network timeout." if status == "failed" else None,
                ),
            )
            scans_inserted += 1
        except sqlite3.IntegrityError:
            continue  # Skip duplicate scan IDs

        for finding in findings:
            conn.execute(
                """
                INSERT INTO findings (
                    scan_id, timestamp, target_type, target_name, tool,
                    category, severity, title, description, file, line,
                    package, version, cve, remediation, raw_reference, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding["scan_id"],
                    finding["timestamp"],
                    finding["target_type"],
                    finding["target_name"],
                    finding["tool"],
                    finding["category"],
                    finding["severity"],
                    finding["title"],
                    finding["description"],
                    finding["file"],
                    finding["line"],
                    finding["package"],
                    finding["version"],
                    finding["cve"],
                    finding["remediation"],
                    finding["raw_reference"],
                    finding["fingerprint"],
                ),
            )
            findings_inserted += 1

    conn.commit()
    conn.close()

    print(f"  Inserted {scans_inserted} scans and {findings_inserted} findings.")
    print("Done. You can now start the dashboard with: ./scripts/ops.sh up")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the development database with demo data.")
    parser.add_argument(
        "--db-path",
        default=DEFAULT_DB_PATH,
        help=f"Path to the SQLite database (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all existing data before seeding",
    )
    args = parser.parse_args()
    seed(args.db_path, args.clear)
