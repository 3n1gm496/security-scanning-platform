"""Unit tests for pagination system."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import sqlite3

from pagination import FindingsPaginator, PaginationCursor, ScansPaginator


def test_pagination_cursor_encode_decode():
    """Test cursor encoding/decoding."""
    cursor = PaginationCursor("test_table")
    encoded = cursor.encode_cursor({"id": 42})
    decoded = cursor.decode_cursor(encoded)
    assert decoded == "42"


def test_findings_paginator_basic():
    """Test findings pagination basic functionality."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                title TEXT,
                description TEXT,
                severity TEXT,
                file TEXT,
                line INTEGER,
                tool TEXT,
                cve TEXT,
                cwe TEXT,
                fingerprint TEXT,
                timestamp TEXT,
                target_name TEXT
            )
        """)

    for i in range(25):
        conn.execute(
            """
            INSERT INTO findings VALUES (?, 1, ?, ?, ?, ?, NULL, 'semgrep', NULL, NULL, ?, datetime('now'), NULL)
        """,
            (i, f"Finding {i}", f"Desc {i}", ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4], f"file{i}.py", f"fp{i}"),
        )

    conn.commit()

    paginator = FindingsPaginator(per_page=10)
    result = paginator.paginate(conn)

    assert len(result["items"]) == 10
    assert result["pagination"]["has_next"] is True
    assert result["pagination"]["count"] == 10
    conn.close()


def _make_scans_db(n: int = 15):
    """Helper: create an in-memory scans DB with the full schema."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            target_name TEXT,
            target_type TEXT,
            status TEXT,
            policy_status TEXT,
            created_at TEXT,
            finished_at TEXT,
            findings_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            error_message TEXT
        )
    """)

    for i in range(15):
        conn.execute(
            """
            INSERT INTO scans (id, target_name, target_type, status, policy_status, created_at, finished_at,
                               findings_count, critical_count, high_count, medium_count, low_count)
            VALUES (?, ?, 'repository', 'completed', 'PASSED', datetime('now'), datetime('now'), 3, 0, 1, 2, 0)
        """,
            (i, f"target-{i}"),
        )
    conn.commit()
    return conn


def test_scans_paginator_basic():
    """Test scans pagination returns correct page size and has_next."""
    conn = _make_scans_db(15)
    paginator = ScansPaginator(per_page=5)
    result = paginator.paginate(conn)
    assert len(result["items"]) == 5
    assert result["pagination"]["has_next"] is True
    # Verify new fields are present
    item = result["items"][0]
    assert "policy_status" in item
    assert "critical_count" in item
    assert "high_count" in item
    conn.close()


def _make_full_scans_db(rows: list[tuple]) -> sqlite3.Connection:
    """Helper: create an in-memory scans DB matching the production schema."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            target_name TEXT,
            target_type TEXT,
            status TEXT,
            policy_status TEXT NOT NULL DEFAULT 'UNKNOWN',
            created_at TEXT,
            finished_at TEXT,
            findings_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0,
            error_message TEXT
        )
    """)
    for row in rows:
        conn.execute(
            (
                "INSERT INTO scans (id, target_name, target_type, status, policy_status, created_at) "
                "VALUES (?, ?, ?, ?, ?, datetime('now'))"
            ),
            row,
        )
    conn.commit()
    return conn


def test_scans_paginator_policy_filter():
    """Test scans pagination with policy_status filter."""
    pass_rows = [(i, f"pass-{i}", "repository", "COMPLETED_CLEAN", "PASS") for i in range(5)]
    block_rows = [(i, f"block-{i}", "repository", "COMPLETED_WITH_FINDINGS", "BLOCK") for i in range(5, 8)]
    conn = _make_full_scans_db(pass_rows + block_rows)
    paginator = ScansPaginator(per_page=20)
    pass_result = paginator.paginate(conn, policy_filter="PASS")
    assert len(pass_result["items"]) == 5
    assert all(item["policy_status"] == "PASS" for item in pass_result["items"])
    block_result = paginator.paginate(conn, policy_filter="BLOCK")
    assert len(block_result["items"]) == 3
    conn.close()


def test_scans_paginator_total_count_not_affected_by_cursor():
    """total_count must reflect filters only, not the current page cursor."""
    conn = _make_scans_db(15)
    paginator = ScansPaginator(per_page=5)
    first_page = paginator.paginate(conn, sort_by="id", sort_order="ASC")
    second_page = paginator.paginate(
        conn,
        sort_by="id",
        sort_order="ASC",
        cursor=first_page["pagination"]["next_cursor"],
    )

    assert first_page["pagination"]["total_count"] == 15
    assert second_page["pagination"]["total_count"] == 15
    conn.close()


def test_pagination_cursor_invalid():
    """Test cursor validation."""
    cursor = PaginationCursor("test")
    result = cursor.decode_cursor("invalid!!!!")
    assert result == ""


def test_findings_paginator_with_status_filter():
    """Test findings pagination with a status filter."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    # Create findings table
    conn.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY, scan_id INTEGER, title TEXT, description TEXT,
            severity TEXT, file TEXT, line INTEGER, tool TEXT, cve TEXT, cwe TEXT,
            fingerprint TEXT, timestamp TEXT, target_name TEXT
        )
        """)

    # Create finding_states table
    conn.execute("""
        CREATE TABLE finding_states (
            id INTEGER PRIMARY KEY, finding_id INTEGER, status TEXT, user TEXT,
            comment TEXT, created_at TEXT
        )
    """)

    # Insert findings
    for i in range(10):
        conn.execute(
            "INSERT INTO findings (id, title, severity) VALUES (?, ?, ?)",
            (i + 1, f"Finding {i + 1}", "HIGH"),
        )

    # Set status for some findings
    conn.execute("INSERT INTO finding_states (finding_id, status) VALUES (?, ?)", (2, "resolved"))
    conn.execute("INSERT INTO finding_states (finding_id, status) VALUES (?, ?)", (4, "in_progress"))
    conn.execute("INSERT INTO finding_states (finding_id, status) VALUES (?, ?)", (5, "resolved"))
    conn.commit()

    paginator = FindingsPaginator(per_page=10)

    # Test filter for 'open' status (default)
    open_result = paginator.paginate(conn, status_filter="open")
    assert len(open_result["items"]) == 7
    assert all(f["triage_status"] == "open" for f in open_result["items"])

    # Test filter for 'resolved' status
    resolved_result = paginator.paginate(conn, status_filter="resolved")
    assert len(resolved_result["items"]) == 2
    assert all(f["triage_status"] == "resolved" for f in resolved_result["items"])
    assert {f["id"] for f in resolved_result["items"]} == {2, 5}

    # Test filter for 'in_progress' status
    progress_result = paginator.paginate(conn, status_filter="in_progress")
    assert len(progress_result["items"]) == 1
    assert progress_result["items"][0]["id"] == 4

    conn.close()
