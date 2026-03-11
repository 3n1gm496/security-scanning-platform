"""Unit tests for pagination system."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pagination import FindingsPaginator, ScansPaginator, PaginationCursor
import sqlite3


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
            fingerprint TEXT,
            timestamp TEXT,
            target_name TEXT
        )
    """)

    for i in range(25):
        conn.execute(
            """
            INSERT INTO findings VALUES (?, 1, ?, ?, ?, ?, NULL, 'semgrep', NULL, ?, datetime('now'), NULL)
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


def test_scans_paginator_basic():
    """Test scans pagination."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            target_name TEXT,
            target_type TEXT,
            status TEXT,
            created_at TEXT
        )
    """)

    conn.execute("CREATE TABLE findings (id INTEGER, scan_id INTEGER)")

    for i in range(15):
        conn.execute(
            """
            INSERT INTO scans VALUES (?, ?, 'repository', 'completed', datetime('now'))
        """,
            (i, f"target-{i}"),
        )

    conn.commit()

    paginator = ScansPaginator(per_page=5)
    result = paginator.paginate(conn)

    assert len(result["items"]) == 5
    assert result["pagination"]["has_next"] is True
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
            severity TEXT, file TEXT, line INTEGER, tool TEXT, cve TEXT,
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
            (i + 1, f"Finding {i+1}", "HIGH"),
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
