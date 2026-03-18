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
                "cwe": "CWE-22" if category == "path-traversal" else ("CWE-89" if category == "sqli" else None),
                "remediation": remediation,
                "raw_reference": json.dumps({"source": tool, "rule": f"{tool}-{category}-001"}),
                "fingerprint": str(uuid.uuid4()),
            }
        )
    return findings


def _ensure_schema(conn: sqlite3.Connection) -> None:
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
            cwe TEXT,
            remediation TEXT,
            raw_reference TEXT,
            fingerprint TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)
    finding_columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    if "cwe" not in finding_columns:
        conn.execute("ALTER TABLE findings ADD COLUMN cwe TEXT")
    conn.commit()


def _insert_scan(conn: sqlite3.Connection, scan: dict, findings: list[dict]) -> None:
    counts = _severity_counts(findings)
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
            scan["id"],
            scan["created_at"],
            scan["finished_at"],
            scan["target_type"],
            scan["target_name"],
            scan["target_value"],
            scan["status"],
            scan["policy_status"],
            len(findings),
            counts["CRITICAL"],
            counts["HIGH"],
            counts["MEDIUM"],
            counts["LOW"],
            counts["INFO"],
            counts["UNKNOWN"],
            scan.get("raw_report_dir", f"/data/reports/{scan['id']}/raw"),
            scan.get("normalized_report_path", f"/data/reports/{scan['id']}/normalized.json"),
            json.dumps(scan.get("artifacts", [])),
            json.dumps(scan.get("tools", [])),
            scan.get("error_message"),
        ),
    )
    for finding in findings:
        conn.execute(
            """
            INSERT INTO findings (
                scan_id, timestamp, target_type, target_name, tool,
                category, severity, title, description, file, line,
                package, version, cve, cwe, remediation, raw_reference, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                finding.get("cwe"),
                finding["remediation"],
                finding["raw_reference"],
                finding["fingerprint"],
            ),
        )


def _seed_edge(conn: sqlite3.Connection) -> tuple[int, int]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    scan_defs = [
        {
            "id": "edge-compare-diff-a",
            "created_at": (now - timedelta(days=3, hours=2)).isoformat(),
            "finished_at": (now - timedelta(days=3, hours=1, minutes=54)).isoformat(),
            "target_type": "git",
            "target_name": "edge-compare.example.internal/platform/api",
            "target_value": "https://github.com/example/edge-compare-api",
            "status": "COMPLETED_WITH_FINDINGS",
            "policy_status": "BLOCK",
            "tools": ["semgrep"],
        },
        {
            "id": "edge-compare-diff-b",
            "created_at": (now - timedelta(days=2, hours=2)).isoformat(),
            "finished_at": (now - timedelta(days=2, hours=1, minutes=55)).isoformat(),
            "target_type": "git",
            "target_name": "edge-compare.example.internal/platform/api",
            "target_value": "https://github.com/example/edge-compare-api",
            "status": "COMPLETED_WITH_FINDINGS",
            "policy_status": "BLOCK",
            "tools": ["semgrep"],
        },
        {
            "id": "edge-compare-match-a",
            "created_at": (now - timedelta(days=5, hours=3)).isoformat(),
            "finished_at": (now - timedelta(days=5, hours=2, minutes=52)).isoformat(),
            "target_type": "url",
            "target_name": "https://identical-edge.example.internal/service",
            "target_value": "https://identical-edge.example.internal/service",
            "status": "COMPLETED_WITH_FINDINGS",
            "policy_status": "PASS",
            "tools": ["semgrep"],
        },
        {
            "id": "edge-compare-match-b",
            "created_at": (now - timedelta(days=1, hours=4)).isoformat(),
            "finished_at": (now - timedelta(days=1, hours=3, minutes=54)).isoformat(),
            "target_type": "url",
            "target_name": "https://identical-edge.example.internal/service",
            "target_value": "https://identical-edge.example.internal/service",
            "status": "COMPLETED_WITH_FINDINGS",
            "policy_status": "PASS",
            "tools": ["semgrep"],
        },
        {
            "id": "edge-long-target",
            "created_at": (now - timedelta(hours=16)).isoformat(),
            "finished_at": (now - timedelta(hours=15, minutes=50)).isoformat(),
            "target_type": "repo",
            "target_name": "observatory-for-legislative-systems-and-governance/ultra-long-target-with-multiple-segments-and-deeply-nested-components",
            "target_value": "https://github.com/example/observatory-for-legislative-systems-and-governance",
            "status": "COMPLETED_WITH_FINDINGS",
            "policy_status": "BLOCK",
            "tools": ["semgrep"],
        },
        {
            "id": "edge-clean-target",
            "created_at": (now - timedelta(hours=10)).isoformat(),
            "finished_at": (now - timedelta(hours=9, minutes=57)).isoformat(),
            "target_type": "image",
            "target_name": "registry.internal/clean-service:2026.03",
            "target_value": "registry.internal/clean-service:2026.03",
            "status": "COMPLETED_CLEAN",
            "policy_status": "PASS",
            "tools": ["semgrep"],
        },
        {
            "id": "edge-partial-failed",
            "created_at": (now - timedelta(hours=7)).isoformat(),
            "finished_at": (now - timedelta(hours=6, minutes=51)).isoformat(),
            "target_type": "url",
            "target_name": "https://partial-edge.example.internal",
            "target_value": "https://partial-edge.example.internal",
            "status": "PARTIAL_FAILED",
            "policy_status": "UNKNOWN",
            "tools": ["semgrep"],
            "error_message": "One scanner timed out while collecting evidence.",
        },
        {
            "id": "edge-running-target",
            "created_at": (now - timedelta(minutes=25)).isoformat(),
            "finished_at": (now - timedelta(minutes=20)).isoformat(),
            "target_type": "url",
            "target_name": "https://running-edge.example.internal",
            "target_value": "https://running-edge.example.internal",
            "status": "RUNNING",
            "policy_status": "UNKNOWN",
            "tools": ["semgrep"],
        },
    ]

    findings_by_scan = {
        "edge-compare-diff-a": [
            {
                "scan_id": "edge-compare-diff-a",
                "timestamp": (now - timedelta(days=3, hours=2)).isoformat(),
                "target_type": "git",
                "target_name": "edge-compare.example.internal/platform/api",
                "tool": "semgrep",
                "category": "custom",
                "severity": "HIGH",
                "title": "Baseline credential exposure in deployment pipeline",
                "description": "A reusable secret was detected in pipeline configuration.",
                "file": "pipelines/deploy.yml",
                "line": 18,
                "package": None,
                "version": None,
                "cve": None,
                "cwe": "CWE-798",
                "remediation": "Rotate the credential and move it into managed secret storage.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-secret"}),
                "fingerprint": "edge-compare-common-1",
            },
        ],
        "edge-compare-diff-b": [
            {
                "scan_id": "edge-compare-diff-b",
                "timestamp": (now - timedelta(days=2, hours=2)).isoformat(),
                "target_type": "git",
                "target_name": "edge-compare.example.internal/platform/api",
                "tool": "semgrep",
                "category": "custom",
                "severity": "HIGH",
                "title": "Baseline credential exposure in deployment pipeline",
                "description": "A reusable secret was detected in pipeline configuration.",
                "file": "pipelines/deploy.yml",
                "line": 18,
                "package": None,
                "version": None,
                "cve": None,
                "cwe": "CWE-798",
                "remediation": "Rotate the credential and move it into managed secret storage.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-secret"}),
                "fingerprint": "edge-compare-common-1",
            },
            {
                "scan_id": "edge-compare-diff-b",
                "timestamp": (now - timedelta(days=2, hours=2, minutes=1)).isoformat(),
                "target_type": "git",
                "target_name": "edge-compare.example.internal/platform/api",
                "tool": "semgrep",
                "category": "custom",
                "severity": "CRITICAL",
                "title": "New privilege bypass introduced after baseline deployment",
                "description": "An authorization guard regressed between consecutive runs.",
                "file": "services/authz/policy_enforcement_gateway.py",
                "line": 241,
                "package": None,
                "version": None,
                "cve": None,
                "cwe": "CWE-285",
                "remediation": "Restore explicit authorization checks for the affected route family.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-authz"}),
                "fingerprint": "edge-compare-new-1",
            },
        ],
        "edge-compare-match-a": [
            {
                "scan_id": "edge-compare-match-a",
                "timestamp": (now - timedelta(days=5, hours=3)).isoformat(),
                "target_type": "url",
                "target_name": "https://identical-edge.example.internal/service",
                "tool": "semgrep",
                "category": "custom",
                "severity": "MEDIUM",
                "title": "Persistent path canonicalization gap in upload endpoint",
                "description": "Uploaded archive paths are normalized late in the request lifecycle.",
                "file": "src/http/upload_gateway.py",
                "line": 91,
                "package": None,
                "version": None,
                "cve": None,
                "cwe": "CWE-22",
                "remediation": "Normalize and validate archive member paths before extraction.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-upload"}),
                "fingerprint": "edge-compare-match-1",
            }
        ],
        "edge-compare-match-b": [
            {
                "scan_id": "edge-compare-match-b",
                "timestamp": (now - timedelta(days=1, hours=4)).isoformat(),
                "target_type": "url",
                "target_name": "https://identical-edge.example.internal/service",
                "tool": "semgrep",
                "category": "custom",
                "severity": "MEDIUM",
                "title": "Persistent path canonicalization gap in upload endpoint",
                "description": "Uploaded archive paths are normalized late in the request lifecycle.",
                "file": "src/http/upload_gateway.py",
                "line": 91,
                "package": None,
                "version": None,
                "cve": None,
                "cwe": "CWE-22",
                "remediation": "Normalize and validate archive member paths before extraction.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-upload"}),
                "fingerprint": "edge-compare-match-1",
            }
        ],
        "edge-long-target": [
            {
                "scan_id": "edge-long-target",
                "timestamp": (now - timedelta(hours=16)).isoformat(),
                "target_type": "repo",
                "target_name": "observatory-for-legislative-systems-and-governance/ultra-long-target-with-multiple-segments-and-deeply-nested-components",
                "tool": "semgrep",
                "category": "custom",
                "severity": "HIGH",
                "title": "Overly permissive request forwarding path allows user-controlled upstream selection inside the legislative-observatory aggregation pipeline for mirrored content synchronization",
                "description": "The forwarding path accepts user-controlled upstream fragments when syncing mirrored content across aggregation workers.",
                "file": "src/platform/ingestion/mirrors/legislative_observatory/upstream_forwarding_controller_with_really_long_module_name.py",
                "line": 347,
                "package": None,
                "version": None,
                "cve": "CVE-2099-12345",
                "cwe": None,
                "remediation": "Constrain upstream selection to an allowlist and fail closed when the target cannot be matched.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-forwarding"}),
                "fingerprint": "edge-long-finding-1",
            },
            {
                "scan_id": "edge-long-target",
                "timestamp": (now - timedelta(hours=15, minutes=56)).isoformat(),
                "target_type": "repo",
                "target_name": "observatory-for-legislative-systems-and-governance/ultra-long-target-with-multiple-segments-and-deeply-nested-components",
                "tool": "semgrep",
                "category": "custom",
                "severity": "LOW",
                "title": "Audit annotation is missing for one mirrored-content retry path",
                "description": "One retry branch omits the operator audit annotation.",
                "file": "src/platform/ingestion/mirrors/retry_annotations.py",
                "line": 58,
                "package": None,
                "version": None,
                "cve": None,
                "cwe": "CWE-778",
                "remediation": "Emit the same audit annotation before the retry is queued.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-audit"}),
                "fingerprint": "edge-long-finding-2",
            },
        ],
        "edge-partial-failed": [
            {
                "scan_id": "edge-partial-failed",
                "timestamp": (now - timedelta(hours=7)).isoformat(),
                "target_type": "url",
                "target_name": "https://partial-edge.example.internal",
                "tool": "semgrep",
                "category": "custom",
                "severity": "MEDIUM",
                "title": "Residual operator note remains exposed in the partial run",
                "description": "The partial run still surfaces a medium-severity configuration issue.",
                "file": "src/config/runtime_flags.py",
                "line": 12,
                "package": None,
                "version": None,
                "cve": None,
                "cwe": "CWE-16",
                "remediation": "Remove operator-only notes from externally reachable responses.",
                "raw_reference": json.dumps({"source": "semgrep", "rule": "edge-config"}),
                "fingerprint": "edge-partial-finding-1",
            }
        ],
    }

    scans_inserted = 0
    findings_inserted = 0
    for scan in scan_defs:
        findings = findings_by_scan.get(scan["id"], [])
        _insert_scan(conn, scan, findings)
        scans_inserted += 1
        findings_inserted += len(findings)

    return scans_inserted, findings_inserted


# ---------------------------------------------------------------------------
# Main seeding logic
# ---------------------------------------------------------------------------


def seed(db_path: str, clear: bool = False, mode: str = "normal") -> None:
    print(f"Seeding database: {db_path}")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    _ensure_schema(conn)

    if clear:
        print("  Clearing existing data...")
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM scans")
        conn.commit()

    if mode == "edge":
        scans_inserted, findings_inserted = _seed_edge(conn)
        conn.commit()
        conn.close()
        print(f"  Inserted {scans_inserted} scans and {findings_inserted} findings.")
        print("Done. You can now start the dashboard with: ./scripts/ops.sh up")
        return

    # Generate 30 scans over the last 90 days
    random.seed(42)
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
            _insert_scan(
                conn,
                {
                    "id": scan_id,
                    "created_at": created_at.isoformat(),
                    "finished_at": finished_at.isoformat(),
                    "target_type": target_type,
                    "target_name": target_name,
                    "target_value": target_value,
                    "status": status,
                    "policy_status": policy_status,
                    "tools": [tool],
                    "error_message": "Scan failed due to network timeout." if status == "failed" else None,
                },
                findings,
            )
            scans_inserted += 1
        except sqlite3.IntegrityError:
            continue  # Skip duplicate scan IDs
        findings_inserted += len(findings)

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
    parser.add_argument(
        "--mode",
        choices=["normal", "edge"],
        default="normal",
        help="Seed mode: normal demo data or edge-case validation data",
    )
    args = parser.parse_args()
    seed(args.db_path, args.clear, args.mode)
