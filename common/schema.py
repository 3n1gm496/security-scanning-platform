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
    # NOTE: The following dashboard-specific tables are created by their
    # respective init_*_tables() functions (idempotent, using IF NOT EXISTS):
    #   - finding_states, finding_comments, finding_attachments  (finding_management.py)
    #   - notification_preferences                                (notifications.py)
    #   - api_keys, users, audit_log                              (rbac.py)
    #   - webhooks, webhook_deliveries                            (webhooks.py)
    # Migration v3 below consolidates them into the migration chain.
    (
        3,
        "consolidate dashboard tables into schema migrations",
        """
-- RBAC tables
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    expires_at TEXT,
    is_active INTEGER DEFAULT 1,
    created_by TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user_id TEXT,
    api_key_prefix TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    result TEXT,
    ip_address TEXT
);

-- Webhook tables
CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT,
    events TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    last_triggered_at TEXT,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    consecutive_failures INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    error TEXT,
    delivered_at TEXT NOT NULL,
    duration_ms INTEGER,
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
);

-- Finding management tables
CREATE TABLE IF NOT EXISTS finding_states (
    finding_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'new',
    assigned_to TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    resolution_notes TEXT,
    false_positive_reason TEXT,
    risk_acceptance_justification TEXT,
    risk_acceptance_expires_at TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    user TEXT NOT NULL,
    comment TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_states_status ON finding_states(status);
CREATE INDEX IF NOT EXISTS idx_finding_states_assigned ON finding_states(assigned_to);
CREATE INDEX IF NOT EXISTS idx_finding_comments_finding ON finding_comments(finding_id);

-- Notification preferences
CREATE TABLE IF NOT EXISTS notification_preferences (
    id INTEGER PRIMARY KEY,
    user_email TEXT UNIQUE,
    critical_alerts BOOLEAN DEFAULT 1,
    high_alerts BOOLEAN DEFAULT 1,
    scan_summaries BOOLEAN DEFAULT 1,
    weekly_digest BOOLEAN DEFAULT 0,
    preferred_channel TEXT DEFAULT 'email',
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
""",
    ),
    (
        4,
        "add fingerprint index for finding deduplication",
        """
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan_fingerprint
    ON findings(scan_id, fingerprint);
""",
    ),
    (
        5,
        "add git_sha column to scans for incremental scanning",
        """
ALTER TABLE scans ADD COLUMN git_sha TEXT;
CREATE INDEX IF NOT EXISTS idx_scans_target_name ON scans(target_name);
""",
    ),
    (
        6,
        "add tenant_id column for multi-tenant isolation",
        """
ALTER TABLE scans ADD COLUMN tenant_id TEXT DEFAULT 'default';
ALTER TABLE findings ADD COLUMN tenant_id TEXT DEFAULT 'default';
ALTER TABLE api_keys ADD COLUMN tenant_id TEXT DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
""",
    ),
]
