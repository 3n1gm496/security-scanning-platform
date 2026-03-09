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
            file_path TEXT,
            line_number INTEGER,
            tool TEXT,
            cve_id TEXT,
            fingerprint TEXT,
            created_at TEXT
        )
    """)
    
    for i in range(25):
        conn.execute("""
            INSERT INTO findings VALUES (?, 1, ?, ?, ?, ?, NULL, 'semgrep', NULL, ?, datetime('now'))
        """, (i, f"Finding {i}", f"Desc {i}", ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4], f"file{i}.py", f"fp{i}"))
    
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
        conn.execute("""
            INSERT INTO scans VALUES (?, ?, 'repository', 'completed', datetime('now'))
        """, (i, f"target-{i}"))
    
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
