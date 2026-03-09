"""
Finding Management System - Track finding lifecycle and remediation status.
"""

import os
import sqlite3
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

DASHBOARD_DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")


class FindingStatus(str, Enum):
    """Finding lifecycle status."""

    NEW = "new"
    ACKNOWLEDGED = "acknow

ledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"


def init_finding_management_tables():
    """Initialize finding management tables."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    # Finding states table
    cursor.execute("""
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
        )
    """)

    # Finding comments table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS finding_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            user TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        )
    """)

    # Finding attachments table (for screenshots, logs, etc.)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS finding_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        )
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_finding_states_status ON finding_states(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_finding_states_assigned ON finding_states(assigned_to)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_finding_comments_finding ON finding_comments(finding_id)")

    conn.commit()
    conn.close()


def get_finding_state(finding_id: int) -> Optional[dict]:
    """Get finding state."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    row = cursor.execute("SELECT * FROM finding_states WHERE finding_id = ?", (finding_id,)).fetchone()
    conn.close()

    return dict(row) if row else None


def update_finding_status(
    finding_id: int,
    status: FindingStatus,
    user: str,
    notes: Optional[str] = None,
    assigned_to: Optional[str] = None,
) -> dict:
    """Update finding status."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    # Check if state exists
    existing = cursor.execute("SELECT 1 FROM finding_states WHERE finding_id = ?", (finding_id,)).fetchone()

    if existing:
        # Update existing
        cursor.execute(
            """
            UPDATE finding_states
            SET status = ?, updated_at = ?, resolution_notes = ?,
                assigned_to = ?, resolved_at = ?
            WHERE finding_id = ?
        """,
            (
                status.value,
                now,
                notes,
                assigned_to,
                now if status == FindingStatus.RESOLVED else None,
                finding_id,
            ),
        )
    else:
        # Insert new
        cursor.execute(
            """
            INSERT INTO finding_states (finding_id, status, assigned_to, created_at, updated_at, resolution_notes, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                finding_id,
                status.value,
                assigned_to,
                now,
                now,
                notes,
                now if status == FindingStatus.RESOLVED else None,
            ),
        )

    conn.commit()
    conn.close()

    return {"finding_id": finding_id, "status": status.value, "updated_at": now}


def assign_finding(finding_id: int, assigned_to: str, assigned_by: str) -> dict:
    """Assign finding to a user."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    # Check if state exists
    existing = cursor.execute("SELECT 1 FROM finding_states WHERE finding_id = ?", (finding_id,)).fetchone()

    if existing:
        cursor.execute(
            """
            UPDATE finding_states
            SET assigned_to = ?, updated_at = ?
            WHERE finding_id = ?
        """,
            (assigned_to, now, finding_id),
        )
    else:
        cursor.execute(
            """
            INSERT INTO finding_states (finding_id, status, assigned_to, created_at, updated_at)
            VALUES (?, 'new', ?, ?, ?)
        """,
            (finding_id, assigned_to, now, now),
        )

    conn.commit()

    # Add comment
    add_finding_comment(finding_id, assigned_by, f"Assigned to {assigned_to}")

    conn.close()

    return {"finding_id": finding_id, "assigned_to": assigned_to, "updated_at": now}


def mark_false_positive(finding_id: int, reason: str, user: str) -> dict:
    """Mark finding as false positive."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        """
        INSERT OR REPLACE INTO finding_states (finding_id, status, false_positive_reason, created_at, updated_at)
        VALUES (?, 'false_positive', ?, COALESCE((SELECT created_at FROM finding_states WHERE finding_id = ?), ?), ?)
    """,
        (finding_id, reason, finding_id, now, now),
    )

    conn.commit()

    # Add comment
    add_finding_comment(finding_id, user, f"Marked as false positive: {reason}")

    conn.close()

    return {"finding_id": finding_id, "status": "false_positive", "reason": reason}


def accept_risk(finding_id: int, justification: str, expires_at: str, user: str) -> dict:
    """Accept risk for finding with expiration."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        """
        INSERT OR REPLACE INTO finding_states 
        (finding_id, status, risk_acceptance_justification, risk_acceptance_expires_at, created_at, updated_at)
        VALUES (?, 'risk_accepted', ?, ?, COALESCE((SELECT created_at FROM finding_states WHERE finding_id = ?), ?), ?)
    """,
        (finding_id, justification, expires_at, finding_id, now, now),
    )

    conn.commit()

    # Add comment
    add_finding_comment(finding_id, user, f"Risk accepted until {expires_at}: {justification}")

    conn.close()

    return {
        "finding_id": finding_id,
        "status": "risk_accepted",
        "justification": justification,
        "expires_at": expires_at,
    }


def add_finding_comment(finding_id: int, user: str, comment: str) -> int:
    """Add comment to finding."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        """
        INSERT INTO finding_comments (finding_id, user, comment, created_at)
        VALUES (?, ?, ?, ?)
    """,
        (finding_id, user, comment, now),
    )

    comment_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return comment_id


def get_finding_comments(finding_id: int) -> list[dict]:
    """Get all comments for a finding."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    rows = cursor.execute(
        """
        SELECT * FROM finding_comments
        WHERE finding_id = ?
        ORDER BY created_at DESC
    """,
        (finding_id,),
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def bulk_update_status(finding_ids: list[int], status: FindingStatus, user: str) -> dict:
    """Bulk update status for multiple findings."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()
    updated_count = 0

    for finding_id in finding_ids:
        try:
            cursor.execute(
                """
                INSERT OR REPLACE INTO finding_states (finding_id, status, created_at, updated_at)
                VALUES (?, ?, COALESCE((SELECT created_at FROM finding_states WHERE finding_id = ?), ?), ?)
            """,
                (finding_id, status.value, finding_id, now, now),
            )
            updated_count += 1
        except Exception:
            continue

    conn.commit()
    conn.close()

    return {"updated_count": updated_count, "status": status.value, "finding_ids": finding_ids}


def get_findings_by_status(status: Optional[str] = None, limit: int = 100) -> list[dict]:
    """Get findings filtered by status."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    conn.row_factory = sqlite3.Row

    if status:
        query = """
            SELECT f.*, fs.status, fs.assigned_to, fs.updated_at as state_updated_at
            FROM findings f
            LEFT JOIN finding_states fs ON f.id = fs.finding_id
            WHERE fs.status = ?
            ORDER BY f.timestamp DESC
            LIMIT ?
        """
        rows = conn.execute(query, (status, limit)).fetchall()
    else:
        query = """
            SELECT f.*, COALESCE(fs.status, 'new') as status, fs.assigned_to, fs.updated_at as state_updated_at
            FROM findings f
            LEFT JOIN finding_states fs ON f.id = fs.finding_id
            ORDER BY f.timestamp DESC
            LIMIT ?
        """
        rows = conn.execute(query, (limit,)).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_finding_stats_by_status() -> dict:
    """Get statistics of findings grouped by status."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()

    # Count findings by status
    rows = cursor.execute("""
        SELECT 
            COALESCE(fs.status, 'new') as status,
            COUNT(*) as count
        FROM findings f
        LEFT JOIN finding_states fs ON f.id = fs.finding_id
        GROUP BY status
    """).fetchall()

    conn.close()

    stats = {row[0]: row[1] for row in rows}

    return stats
