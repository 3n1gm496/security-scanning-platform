"""
Finding Management System - Track finding lifecycle and remediation status.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from db import get_connection
from db_adapter import adapt_schema, is_postgres

logger = logging.getLogger(__name__)

DASHBOARD_DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")


class FindingStatus(str, Enum):
    """Finding lifecycle status."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"


def init_finding_management_tables():
    """Initialize finding management tables."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        conn.execute(adapt_schema("""
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
        """))

        conn.execute(adapt_schema("""
            CREATE TABLE IF NOT EXISTS finding_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                user TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
            )
        """))

        conn.execute(adapt_schema("""
            CREATE TABLE IF NOT EXISTS finding_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
            )
        """))

        conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_states_status ON finding_states(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_states_assigned ON finding_states(assigned_to)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_comments_finding ON finding_comments(finding_id)")


def get_finding_state(finding_id: int) -> Optional[dict]:
    """Get finding state."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        row = conn.execute("SELECT * FROM finding_states WHERE finding_id = ?", (finding_id,)).fetchone()
    return dict(row) if row else None


def _upsert_finding_state(
    finding_id: int,
    *,
    status: str,
    created_at: str,
    updated_at: str,
    assigned_to: Optional[str] = None,
    resolved_at: Optional[str] = None,
    resolution_notes: Optional[str] = None,
    false_positive_reason: Optional[str] = None,
    risk_acceptance_justification: Optional[str] = None,
    risk_acceptance_expires_at: Optional[str] = None,
) -> None:
    """Atomically insert/update finding state to avoid SELECT-then-INSERT races."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO finding_states (
                finding_id,
                status,
                assigned_to,
                created_at,
                updated_at,
                resolved_at,
                resolution_notes,
                false_positive_reason,
                risk_acceptance_justification,
                risk_acceptance_expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                status = excluded.status,
                assigned_to = COALESCE(excluded.assigned_to, finding_states.assigned_to),
                updated_at = excluded.updated_at,
                resolved_at = excluded.resolved_at,
                resolution_notes = COALESCE(excluded.resolution_notes, finding_states.resolution_notes),
                false_positive_reason = COALESCE(
                    excluded.false_positive_reason,
                    finding_states.false_positive_reason
                ),
                risk_acceptance_justification = COALESCE(
                    excluded.risk_acceptance_justification,
                    finding_states.risk_acceptance_justification
                ),
                risk_acceptance_expires_at = COALESCE(
                    excluded.risk_acceptance_expires_at,
                    finding_states.risk_acceptance_expires_at
                )
            """,
            (
                finding_id,
                status,
                assigned_to,
                created_at,
                updated_at,
                resolved_at,
                resolution_notes,
                false_positive_reason,
                risk_acceptance_justification,
                risk_acceptance_expires_at,
            ),
        )


def update_finding_status(
    finding_id: int,
    status: FindingStatus,
    user: str,
    notes: Optional[str] = None,
    assigned_to: Optional[str] = None,
) -> dict:
    """Update finding status."""
    now = datetime.now(timezone.utc).isoformat()

    resolved_at = now if status == FindingStatus.RESOLVED else None
    _upsert_finding_state(
        finding_id,
        status=status.value,
        assigned_to=assigned_to,
        created_at=now,
        updated_at=now,
        resolution_notes=notes,
        resolved_at=resolved_at,
    )

    return {"finding_id": finding_id, "status": status.value, "updated_at": now}


def assign_finding(finding_id: int, assigned_to: str, assigned_by: str) -> dict:
    """Assign finding to a user."""
    now = datetime.now(timezone.utc).isoformat()

    _upsert_finding_state(
        finding_id,
        status=FindingStatus.NEW.value,
        assigned_to=assigned_to,
        created_at=now,
        updated_at=now,
    )

    # Add comment (uses its own connection)
    add_finding_comment(finding_id, assigned_by, f"Assigned to {assigned_to}")

    return {"finding_id": finding_id, "assigned_to": assigned_to, "updated_at": now}


def mark_false_positive(finding_id: int, reason: str, user: str) -> dict:
    """Mark finding as false positive."""
    now = datetime.now(timezone.utc).isoformat()

    _upsert_finding_state(
        finding_id,
        status=FindingStatus.FALSE_POSITIVE.value,
        created_at=now,
        updated_at=now,
        false_positive_reason=reason,
    )

    add_finding_comment(finding_id, user, f"Marked as false positive: {reason}")

    return {"finding_id": finding_id, "status": "false_positive", "reason": reason}


def accept_risk(finding_id: int, justification: str, expires_at: str, user: str) -> dict:
    """Accept risk for finding with expiration."""
    now = datetime.now(timezone.utc).isoformat()

    _upsert_finding_state(
        finding_id,
        status=FindingStatus.RISK_ACCEPTED.value,
        created_at=now,
        updated_at=now,
        risk_acceptance_justification=justification,
        risk_acceptance_expires_at=expires_at,
    )

    add_finding_comment(finding_id, user, f"Risk accepted until {expires_at}: {justification}")

    return {
        "finding_id": finding_id,
        "status": "risk_accepted",
        "justification": justification,
        "expires_at": expires_at,
    }


def add_finding_comment(finding_id: int, user: str, comment: str) -> int:
    """Add comment to finding."""
    now = datetime.now(timezone.utc).isoformat()

    sql = "INSERT INTO finding_comments (finding_id, user, comment, created_at) VALUES (?, ?, ?, ?)"
    if is_postgres():
        sql += " RETURNING id"

    with get_connection(DASHBOARD_DB_PATH) as conn:
        cursor = conn.execute(sql, (finding_id, user, comment, now))
        return cursor.fetchone()[0] if is_postgres() else cursor.lastrowid


def get_finding_comments(finding_id: int) -> list[dict]:
    """Get all comments for a finding."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT * FROM finding_comments
            WHERE finding_id = ?
            ORDER BY created_at DESC
            """,
            (finding_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def bulk_update_status(finding_ids: list[int], status: FindingStatus, user: str) -> dict:
    """Bulk update status for multiple findings."""
    now = datetime.now(timezone.utc).isoformat()
    updated_count = 0
    failures: list[dict[str, str | int]] = []

    for finding_id in finding_ids:
        try:
            _upsert_finding_state(
                finding_id,
                status=status.value,
                created_at=now,
                updated_at=now,
                resolved_at=now if status == FindingStatus.RESOLVED else None,
            )
            updated_count += 1
        except Exception as exc:
            logger.warning("Failed to update finding %d status", finding_id, exc_info=True)
            failures.append({"finding_id": finding_id, "error": str(exc)})

    result = {
        "updated_count": updated_count,
        "status": status.value,
        "finding_ids": finding_ids,
        "failed_ids": [item["finding_id"] for item in failures],
        "failures": failures,
    }
    if failures:
        result["partial_success"] = True
    return result


def get_findings_by_status(status: Optional[str] = None, limit: int = 100) -> list[dict]:
    """Get findings filtered by status."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        if status:
            if status == "new":
                # 'new' is the implicit default for findings with no explicit state
                query = """
                    SELECT f.*, COALESCE(fs.status, 'new') as status,
                           fs.assigned_to, fs.updated_at as state_updated_at
                    FROM findings f
                    LEFT JOIN finding_states fs ON f.id = fs.finding_id
                    WHERE COALESCE(fs.status, 'new') = ?
                    ORDER BY f.timestamp DESC
                    LIMIT ?
                """
            else:
                query = """
                    SELECT f.*, fs.status, fs.assigned_to,
                           fs.updated_at as state_updated_at
                    FROM findings f
                    LEFT JOIN finding_states fs ON f.id = fs.finding_id
                    WHERE fs.status = ?
                    ORDER BY f.timestamp DESC
                    LIMIT ?
                """
            rows = conn.execute(query, (status, limit)).fetchall()
        else:
            query = """
                SELECT f.*, COALESCE(fs.status, 'new') as status, fs.assigned_to,
                       fs.updated_at as state_updated_at
                FROM findings f
                LEFT JOIN finding_states fs ON f.id = fs.finding_id
                ORDER BY f.timestamp DESC
                LIMIT ?
            """
            rows = conn.execute(query, (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_finding_stats_by_status() -> dict:
    """Get statistics of findings grouped by status."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        rows = conn.execute("""
            SELECT
                COALESCE(fs.status, 'new') as status,
                COUNT(*) as count
            FROM findings f
            LEFT JOIN finding_states fs ON f.id = fs.finding_id
            GROUP BY status
        """).fetchall()
    return {row["status"]: row["count"] for row in rows}


def get_expired_risk_acceptances() -> list[dict]:
    """Return findings with expired risk acceptance that need re-evaluation."""
    now = datetime.now(timezone.utc).isoformat()
    with get_connection(DASHBOARD_DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT f.id, f.title, f.severity, f.tool, f.target_name,
                   fs.risk_acceptance_justification, fs.risk_acceptance_expires_at
            FROM findings f
            JOIN finding_states fs ON f.id = fs.finding_id
            WHERE fs.status = 'risk_accepted'
              AND fs.risk_acceptance_expires_at IS NOT NULL
              AND fs.risk_acceptance_expires_at < ?
            ORDER BY f.severity DESC, fs.risk_acceptance_expires_at ASC
            """,
            (now,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_triage_summary() -> dict:
    """Return a comprehensive triage summary for the dashboard."""
    stats = get_finding_stats_by_status()
    expired = get_expired_risk_acceptances()
    overdue_cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

    with get_connection(DASHBOARD_DB_PATH) as conn:
        overdue_rows = conn.execute(
            """
            SELECT f.severity, COUNT(*) as count
            FROM findings f
            LEFT JOIN finding_states fs ON f.id = fs.finding_id
            WHERE COALESCE(fs.status, 'new') = 'new'
              AND f.timestamp < ?
            GROUP BY f.severity
            """,
            (overdue_cutoff,),
        ).fetchall()
    overdue_by_severity = {row["severity"]: row["count"] for row in overdue_rows}

    return {
        "status_counts": stats,
        "total_findings": sum(stats.values()),
        "open_findings": stats.get("new", 0) + stats.get("acknowledged", 0) + stats.get("in_progress", 0),
        "resolved_findings": stats.get("resolved", 0),
        "suppressed_findings": stats.get("false_positive", 0) + stats.get("risk_accepted", 0),
        "expired_risk_acceptances": len(expired),
        "expired_details": expired[:20],
        "overdue_by_severity": overdue_by_severity,
    }
