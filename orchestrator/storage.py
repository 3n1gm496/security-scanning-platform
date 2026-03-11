from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from orchestrator.db_adapter import adapt_schema, get_connection
from orchestrator.models import Finding, ScanResult

LOGGER = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


SCHEMA_SQL = """
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
    raw_report_dir TEXT NOT NULL,
    normalized_report_path TEXT NOT NULL,
    artifacts_json TEXT NOT NULL,
    tools_json TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_target_name ON findings(target_name);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    description TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL
);
"""

# ---------------------------------------------------------------------------
# Versioned migrations applied on top of SCHEMA_SQL (baseline = v0).
# Each entry: (version: int, description: str, sql: str)
# sql may be an empty string for marker-only entries.
# ---------------------------------------------------------------------------
_MIGRATIONS: list[tuple[int, str, str]] = [
    # v1 – baseline marker: all tables above were created by SCHEMA_SQL.
    # Future column additions / index changes go here as new entries.
    (1, "baseline marker", ""),
]


def run_migrations(db_path: str) -> None:
    """Apply any schema migrations not yet recorded in schema_migrations."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").fetchone()
        current_version: int = int(row["v"]) if row else 0

    pending = [(v, d, s) for v, d, s in _MIGRATIONS if v > current_version]
    if not pending:
        return

    for version, description, sql in pending:
        with get_connection(db_path) as conn:
            if sql.strip():
                adapted = adapt_schema(sql)
                conn.executescript(adapted)
            conn.execute(
                "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                (version, description, _utc_now()),
            )
        LOGGER.info("Applied schema migration v%s: %s", version, description)


def connect(db_path: str):
    """Return a connection wrapper (backward-compatible alias)."""
    return get_connection(db_path)


def init_db(db_path: str) -> None:
    adapted = adapt_schema(SCHEMA_SQL)
    with get_connection(db_path) as conn:
        conn.executescript(adapted)
        conn.commit()
    run_migrations(db_path)
    LOGGER.info("Database initialised at %s", db_path)


def _to_text(value):
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def save_scan_result(db_path: str, result: ScanResult) -> None:
    counts = result.severity_counts()
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scans (
                id, created_at, finished_at, target_type, target_name, target_value,
                status, policy_status, findings_count, critical_count, high_count,
                medium_count, low_count, info_count, unknown_count, raw_report_dir,
                normalized_report_path, artifacts_json, tools_json, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                finished_at             = excluded.finished_at,
                status                  = excluded.status,
                policy_status           = excluded.policy_status,
                findings_count          = excluded.findings_count,
                critical_count          = excluded.critical_count,
                high_count              = excluded.high_count,
                medium_count            = excluded.medium_count,
                low_count               = excluded.low_count,
                info_count              = excluded.info_count,
                unknown_count           = excluded.unknown_count,
                raw_report_dir          = excluded.raw_report_dir,
                normalized_report_path  = excluded.normalized_report_path,
                artifacts_json          = excluded.artifacts_json,
                tools_json              = excluded.tools_json,
                error_message           = excluded.error_message
            """,
            (
                result.scan_id,
                result.started_at,
                result.finished_at,
                result.target_type,
                result.target_name,
                result.target_value,
                result.status,
                result.policy_status,
                len(result.findings),
                counts.get("CRITICAL", 0),
                counts.get("HIGH", 0),
                counts.get("MEDIUM", 0),
                counts.get("LOW", 0),
                counts.get("INFO", 0),
                counts.get("UNKNOWN", 0),
                result.raw_report_dir,
                result.normalized_report_path,
                json.dumps(result.artifacts, ensure_ascii=False),
                json.dumps([tool.to_dict() for tool in result.tools], ensure_ascii=False),
                result.error_message,
            ),
        )
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (result.scan_id,))
        conn.executemany(
            """
            INSERT INTO findings (
                scan_id, timestamp, target_type, target_name, tool, category, severity,
                title, description, file, line, package, version, cve, remediation,
                raw_reference, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    finding.scan_id,
                    finding.timestamp,
                    finding.target_type,
                    finding.target_name,
                    finding.tool,
                    finding.category,
                    finding.severity,
                    _to_text(finding.title),
                    _to_text(finding.description),
                    _to_text(finding.file),
                    finding.line,
                    _to_text(finding.package),
                    _to_text(finding.version),
                    _to_text(finding.cve),
                    _to_text(finding.remediation),
                    _to_text(finding.raw_reference),
                    _to_text(finding.fingerprint),
                )
                for finding in result.findings
            ],
        )
        conn.commit()
    LOGGER.info("Persisted scan %s with %s findings", result.scan_id, len(result.findings))


def write_json_file(path: str | Path, payload: dict | list) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
