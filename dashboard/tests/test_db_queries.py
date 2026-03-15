"""Focused tests for db.py query behavior."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

import db as _db


@pytest.fixture
def query_db(tmp_path):
    db_path = str(tmp_path / "queries.db")
    _db.init_db(db_path)

    with _db.get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scans (
                id, created_at, finished_at, target_type, target_name, target_value,
                status, policy_status, findings_count, critical_count, high_count,
                medium_count, low_count, info_count, unknown_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-1",
                "2026-03-01T10:00:00+00:00",
                "2026-03-01T10:01:00+00:00",
                "git",
                "repo-a",
                "https://example.com/repo-a.git",
                "COMPLETED_WITH_FINDINGS",
                "PASS",
                4,
                1,
                1,
                1,
                1,
                0,
                0,
            ),
        )
        conn.execute(
            """
            INSERT INTO scans (
                id, created_at, finished_at, target_type, target_name, target_value,
                status, policy_status, findings_count, critical_count, high_count,
                medium_count, low_count, info_count, unknown_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-2",
                "2026-03-02T10:00:00+00:00",
                "2026-03-02T10:01:00+00:00",
                "git",
                "repo-b",
                "https://example.com/repo-b.git",
                "COMPLETED_WITH_FINDINGS",
                "PASS",
                2,
                1,
                0,
                1,
                0,
                0,
                0,
            ),
        )
        conn.executemany(
            """
            INSERT INTO findings (
                scan_id, timestamp, target_type, target_name, tool, category, severity,
                title, description, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("scan-1", "2026-03-01T10:00:04+00:00", "git", "repo-a", "bandit", "misc", "LOW", "Low", "d", "fp-low"),
                ("scan-1", "2026-03-01T10:00:03+00:00", "git", "repo-a", "bandit", "misc", "MEDIUM", "Medium", "d", "fp-med"),
                ("scan-1", "2026-03-01T10:00:02+00:00", "git", "repo-a", "bandit", "misc", "HIGH", "High", "d", "fp-high"),
                ("scan-1", "2026-03-01T10:00:01+00:00", "git", "repo-a", "bandit", "misc", "CRITICAL", "Critical", "d", "fp-crit"),
                ("scan-1", "2026-03-01T10:00:05+00:00", "git", "repo-a", "semgrep", "xss", "HIGH", "Shared older", "d", "fp-shared"),
                ("scan-2", "2026-03-02T10:00:05+00:00", "git", "repo-b", "semgrep", "xss", "CRITICAL", "Shared newer", "d", "fp-shared"),
            ],
        )

    return db_path


def test_list_findings_uses_severity_rank_with_same_timestamp(query_db):
    """Severity ordering should be risk-based, not alphabetical."""
    with _db.get_connection(query_db) as conn:
        conn.execute("UPDATE findings SET timestamp = ? WHERE fingerprint IN (?, ?, ?, ?)", ("2026-03-03T00:00:00+00:00", "fp-low", "fp-med", "fp-high", "fp-crit"))

    rows = _db.list_findings(query_db, limit=4)
    severities = [row["severity"] for row in rows[:4]]
    assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_deduplicated_findings_reapplies_outer_filters(query_db):
    """Dedup results must not leak newer findings from other targets."""
    rows = _db.deduplicated_findings(query_db, target_name="repo-a")
    assert rows
    assert all(row["target_name"] == "repo-a" for row in rows)
    assert all(not (row["fingerprint"] == "fp-shared" and row["target_name"] == "repo-b") for row in rows)
