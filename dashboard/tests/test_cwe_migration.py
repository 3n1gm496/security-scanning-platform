"""Tests for explicit CWE migration/backfill behavior."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

import db as _db


def _create_legacy_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE findings (
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
            tenant_id TEXT DEFAULT 'default',
            remediation TEXT,
            raw_reference TEXT,
            fingerprint TEXT
        );
        CREATE TABLE scans (
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
            error_message TEXT,
            git_sha TEXT,
            tenant_id TEXT DEFAULT 'default'
        );
        CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );
        INSERT INTO schema_migrations (version, description, applied_at) VALUES
            (1, 'baseline marker', '2026-03-17T00:00:00+00:00'),
            (2, 'add composite indexes for analytics query performance', '2026-03-17T00:00:00+00:00'),
            (3, 'consolidate dashboard tables into schema migrations', '2026-03-17T00:00:00+00:00'),
            (4, 'add fingerprint index for finding deduplication', '2026-03-17T00:00:00+00:00'),
            (5, 'add git_sha column to scans for incremental scanning', '2026-03-17T00:00:00+00:00'),
            (6, 'add tenant_id column for multi-tenant isolation', '2026-03-17T00:00:00+00:00');
        """)
    conn.execute(
        """
        INSERT INTO findings (
            scan_id, timestamp, target_type, target_name, tool, category, severity,
            title, description, cve, fingerprint
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "scan-1",
            "2026-03-17T00:00:00+00:00",
            "local",
            "demo",
            "semgrep",
            "sast",
            "HIGH",
            "legacy cwe",
            "desc",
            '["CWE-79", "CWE-89"]',
            "fp-1",
        ),
    )
    conn.commit()
    conn.close()


def test_init_db_backfills_legacy_cwe_values(tmp_path):
    db_path = tmp_path / "legacy.db"
    _create_legacy_schema(str(db_path))

    _db.init_db(str(db_path))

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT cve, cwe FROM findings WHERE fingerprint = ?", ("fp-1",)).fetchone()
    conn.close()

    assert row["cve"] is None
    assert row["cwe"] == "CWE-79,CWE-89"
