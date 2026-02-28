from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

from orchestrator.models import Finding, ScanResult

LOGGER = logging.getLogger(__name__)


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
"""


def connect(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    LOGGER.info("SQLite initialized at %s", db_path)

def _to_sqlite_text(value):
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)

def save_scan_result(db_path: str, result: ScanResult) -> None:
    counts = result.severity_counts()
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (
                id, created_at, finished_at, target_type, target_name, target_value,
                status, policy_status, findings_count, critical_count, high_count,
                medium_count, low_count, info_count, unknown_count, raw_report_dir,
                normalized_report_path, artifacts_json, tools_json, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    _to_sqlite_text(finding.title),
                    _to_sqlite_text(finding.description),
                    _to_sqlite_text(finding.file),
                    finding.line,
                    _to_sqlite_text(finding.package),
                    _to_sqlite_text(finding.version),
                    _to_sqlite_text(finding.cve),
                    _to_sqlite_text(finding.remediation),
                    _to_sqlite_text(finding.raw_reference),
                    _to_sqlite_text(finding.fingerprint),
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
