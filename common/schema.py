"""
Single source of truth for the database schema used by both orchestrator and dashboard.

Both components import SCHEMA_SQL and MIGRATIONS from this module so that
table definitions, indexes, and migration history stay in sync.
"""

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
    raw_report_dir TEXT NOT NULL DEFAULT '',
    normalized_report_path TEXT NOT NULL DEFAULT '',
    artifacts_json TEXT NOT NULL DEFAULT '{}',
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
MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "baseline marker", ""),
    (
        2,
        "add composite indexes for analytics query performance",
        """
CREATE INDEX IF NOT EXISTS idx_findings_severity_tool
    ON findings(severity, tool);
CREATE INDEX IF NOT EXISTS idx_findings_target_severity
    ON findings(target_name, severity);
""",
    ),
]
