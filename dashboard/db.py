from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Make common package importable when running from the dashboard directory
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from db_adapter import adapt_schema, get_connection, is_postgres
from logging_config import get_logger
from runtime_config import DASHBOARD_DB_PATH

from common.schema import MIGRATIONS as _MIGRATIONS
from common.schema import SCHEMA_SQL
from common.schema import split_identifier_and_cwe

LOGGER = get_logger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _date_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()


def _normalize_finding_status(status: str | None) -> str | None:
    """Normalize legacy aliases to canonical finding triage statuses."""
    if status is None:
        return None
    normalized = str(status).strip().lower()
    if not normalized:
        return None
    return "new" if normalized == "open" else normalized


def _severity_order_sql(column: str = "severity") -> str:
    return (
        f"CASE UPPER({column}) "
        "WHEN 'CRITICAL' THEN 5 "
        "WHEN 'HIGH' THEN 4 "
        "WHEN 'MEDIUM' THEN 3 "
        "WHEN 'LOW' THEN 2 "
        "WHEN 'INFO' THEN 1 "
        "ELSE 0 END"
    )


_ADD_COLUMN_RE = re.compile(
    r"^\s*ALTER\s+TABLE\s+(?P<table>[A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+COLUMN\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?(?P<column>[A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


def _split_sql_statements(sql: str) -> list[str]:
    """Split SQL script statements on semicolons outside quoted strings."""
    statements: list[str] = []
    current: list[str] = []
    in_quote = False
    quote_char = None
    idx = 0

    while idx < len(sql):
        ch = sql[idx]
        current.append(ch)
        if in_quote:
            if ch == quote_char:
                next_ch = sql[idx + 1] if idx + 1 < len(sql) else None
                if next_ch == quote_char:
                    current.append(next_ch)
                    idx += 1
                else:
                    in_quote = False
        elif ch in ("'", '"'):
            in_quote = True
            quote_char = ch
        elif ch == ";":
            statement = "".join(current[:-1]).strip()
            if statement:
                statements.append(statement)
            current = []
        idx += 1

    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def _column_exists(conn, table: str, column: str) -> bool:
    if is_postgres():
        row = conn.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = ?
              AND column_name = ?
            """,
            (table, column),
        ).fetchone()
        return row is not None
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def _execute_migration_script(conn, sql: str) -> None:
    """Execute migration SQL, skipping ADD COLUMN statements that are already satisfied."""
    for statement in _split_sql_statements(adapt_schema(sql)):
        match = _ADD_COLUMN_RE.match(statement)
        if match and _column_exists(conn, match.group("table"), match.group("column")):
            continue
        conn.execute(statement)


def _backfill_cwe_column(conn) -> None:
    """Migrate legacy CWE values out of the overloaded cve field."""
    try:
        rows = conn.execute("SELECT id, cve, cwe FROM findings").fetchall()
    except Exception:
        return

    updates = []
    for row in rows:
        new_cve, new_cwe = split_identifier_and_cwe(row["cve"], row["cwe"])
        if new_cve != row["cve"] or new_cwe != row["cwe"]:
            updates.append((new_cve, new_cwe, row["id"]))

    if updates:
        conn.executemany("UPDATE findings SET cve = ?, cwe = ? WHERE id = ?", updates)


# Re-export get_connection so existing callers (app.py etc.) continue to work
__all__ = ["get_connection", "init_db"]

_DB_PATH = os.environ.get("DASHBOARD_DB_PATH", DASHBOARD_DB_PATH)


def _conn(db_path: str | None = None, *, read_only: bool = False):
    return get_connection(db_path or _DB_PATH, read_only=read_only)


def fetch_kpis(db_path: str) -> dict[str, Any]:
    cutoff = _date_days_ago(7)
    with _conn(db_path, read_only=True) as conn:
        total_scans = conn.execute("SELECT COUNT(*) AS value FROM scans").fetchone()["value"]
        total_findings = conn.execute("SELECT COUNT(*) AS value FROM findings").fetchone()["value"]
        critical_findings = conn.execute(
            "SELECT COUNT(*) AS value FROM findings WHERE severity = 'CRITICAL'"
        ).fetchone()["value"]
        high_findings = conn.execute("SELECT COUNT(*) AS value FROM findings WHERE severity = 'HIGH'").fetchone()[
            "value"
        ]
        distinct_targets = conn.execute("SELECT COUNT(DISTINCT target_name) AS value FROM scans").fetchone()["value"]
        last_7d_scans = conn.execute(
            "SELECT COUNT(*) AS value FROM scans WHERE substr(created_at, 1, 10) >= ?",
            (cutoff,),
        ).fetchone()["value"]
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "active_targets": distinct_targets,
        "open_targets": distinct_targets,
        "last_7d_scans": last_7d_scans,
    }


def list_scans(
    db_path: str,
    limit: int = 100,
    target: str | None = None,
    status: str | None = None,
    policy_status: str | None = None,
    search: str | None = None,
    target_partial: bool = False,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM scans WHERE 1=1"
    params: list[Any] = []
    if search:
        search_param = f"%{search}%"
        query += " AND (CAST(id AS TEXT) LIKE ? OR target_name LIKE ? OR error_message LIKE ?)"
        params.extend([search_param] * 3)
    if target:
        if target_partial:
            query += " AND target_name LIKE ?"
            params.append(f"%{target}%")
        else:
            query += " AND target_name = ?"
            params.append(target)
    if status:
        query += " AND status = ?"
        params.append(status)
    if policy_status:
        query += " AND policy_status = ?"
        params.append(policy_status.upper())
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def _findings_where_clause(
    severity: str | None,
    tool: str | None,
    target: str | None,
    scan_id: str | None,
    category: str | None,
    search: str | None = None,
    status: str | None = None,
    target_partial: bool = False,
) -> tuple[str, list[Any]]:
    """Build the shared WHERE clause and params for findings queries."""
    clause = "WHERE 1=1"
    params: list[Any] = []
    if search:
        search_param = f"%{search}%"
        clause += " AND (title LIKE ? OR description LIKE ? OR file LIKE ? OR cve LIKE ? OR cwe LIKE ?)"
        params.extend([search_param] * 5)
    if severity:
        clause += " AND severity = ?"
        params.append(severity)
    if tool:
        clause += " AND tool = ?"
        params.append(tool)
    if target:
        if target_partial:
            clause += " AND target_name LIKE ?"
            params.append(f"%{target}%")
        else:
            clause += " AND target_name = ?"
            params.append(target)
    if scan_id:
        clause += " AND scan_id = ?"
        params.append(scan_id)
    if category:
        clause += " AND category = ?"
        params.append(category)
    normalized_status = _normalize_finding_status(status)
    if normalized_status is not None:
        clause += " AND COALESCE((SELECT status FROM finding_states WHERE finding_id = findings.id), 'new') = ?"
        params.append(normalized_status)
    return clause, params


def count_findings(
    db_path: str,
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    category: str | None = None,
    search: str | None = None,
    status: str | None = None,
    target_partial: bool = False,
) -> int:
    clause, params = _findings_where_clause(
        severity,
        tool,
        target,
        scan_id,
        category,
        search=search,
        status=status,
        target_partial=target_partial,
    )
    with _conn(db_path, read_only=True) as conn:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM findings {clause}", params).fetchone()  # nosec B608
    return int(row["n"])


def list_findings(
    db_path: str,
    limit: int = 500,
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    category: str | None = None,
    search: str | None = None,
    status: str | None = None,
    target_partial: bool = False,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clause, params = _findings_where_clause(
        severity,
        tool,
        target,
        scan_id,
        category,
        search=search,
        status=status,
        target_partial=target_partial,
    )
    query = (
        f"SELECT * FROM findings {clause} "  # nosec
        f"ORDER BY timestamp DESC, {_severity_order_sql()} DESC, severity DESC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def severity_breakdown(db_path: str) -> dict[str, int]:
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS total FROM findings GROUP BY severity ORDER BY total DESC"
        ).fetchall()
    return {row["severity"]: row["total"] for row in rows}


def tool_breakdown(db_path: str) -> dict[str, int]:
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(
            "SELECT COALESCE(NULLIF(tool, ''), 'unknown') AS tool, COUNT(*) AS total "
            "FROM findings GROUP BY COALESCE(NULLIF(tool, ''), 'unknown') ORDER BY total DESC"
        ).fetchall()
    return {row["tool"]: row["total"] for row in rows}


def target_breakdown(db_path: str) -> dict[str, int]:
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(
            "SELECT COALESCE(NULLIF(target_name, ''), 'Unknown target') AS target_name, COUNT(*) AS total "
            "FROM findings GROUP BY COALESCE(NULLIF(target_name, ''), 'Unknown target') "
            "ORDER BY total DESC LIMIT 20"
        ).fetchall()
    return {row["target_name"]: row["total"] for row in rows}


def scans_trend(db_path: str, days: int = 30) -> list[dict[str, Any]]:
    cutoff = _date_days_ago(days)
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(
            """
            SELECT substr(created_at, 1, 10) AS day,
                   COUNT(*) AS scans,
                   SUM(findings_count) AS findings
            FROM scans
            WHERE substr(created_at, 1, 10) >= ?
            GROUP BY substr(created_at, 1, 10)
            ORDER BY day ASC
            """,
            (cutoff,),
        ).fetchall()
    return [dict(row) for row in rows]


def distinct_targets(db_path: str) -> list[str]:
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(
            "SELECT DISTINCT COALESCE(NULLIF(target_name, ''), 'Unknown target') AS target_name "
            "FROM scans ORDER BY target_name ASC"
        ).fetchall()
    return [row["target_name"] for row in rows]


def distinct_tools(db_path: str) -> list[str]:
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(
            "SELECT DISTINCT COALESCE(NULLIF(tool, ''), 'unknown') AS tool FROM findings ORDER BY tool ASC"
        ).fetchall()
    return [row["tool"] for row in rows]


def recent_failed_scans(db_path: str, limit: int = 20) -> list[dict[str, Any]]:
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE status != 'COMPLETED_CLEAN'" " ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def parse_artifacts(scan: dict[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(scan.get("artifacts_json") or "{}")
    except json.JSONDecodeError:
        return {}


def cache_hit_stats(db_path: str, limit_scans: int = 200) -> dict[str, Any]:
    query = "SELECT tools_json FROM scans ORDER BY created_at DESC LIMIT ?"
    total_runs = 0
    cached_runs = 0
    by_tool: dict[str, dict[str, int]] = {}

    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(query, (limit_scans,)).fetchall()

    for row in rows:
        tools_json = row["tools_json"] if "tools_json" in row.keys() else "[]"
        try:
            tools = json.loads(tools_json or "[]")
        except json.JSONDecodeError:
            tools = []

        if not isinstance(tools, list):
            continue

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = str(tool.get("tool", "unknown"))
            hit = bool(tool.get("cache_hit", False))

            total_runs += 1
            if hit:
                cached_runs += 1

            if tool_name not in by_tool:
                by_tool[tool_name] = {"total": 0, "cached": 0}
            by_tool[tool_name]["total"] += 1
            if hit:
                by_tool[tool_name]["cached"] += 1

    overall_pct = round((cached_runs / total_runs) * 100, 2) if total_runs else 0.0

    by_tool_payload = []
    for tool_name, counters in by_tool.items():
        total = counters["total"]
        cached = counters["cached"]
        pct = round((cached / total) * 100, 2) if total else 0.0
        by_tool_payload.append(
            {
                "tool": tool_name,
                "cached": cached,
                "total": total,
                "cache_hit_pct": pct,
            }
        )

    by_tool_payload.sort(key=lambda item: item["cache_hit_pct"], reverse=True)

    return {
        "overall_cache_hit_pct": overall_pct,
        "cached_runs": cached_runs,
        "total_runs": total_runs,
        "by_tool": by_tool_payload,
    }


def cache_hit_trend(db_path: str, days: int = 14) -> list[dict[str, Any]]:
    cutoff = _date_days_ago(days)
    query = """
        SELECT substr(created_at, 1, 10) AS day, tools_json
        FROM scans
        WHERE substr(created_at, 1, 10) >= ?
        ORDER BY day ASC
    """

    day_totals: dict[str, dict[str, int]] = {}

    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(query, (cutoff,)).fetchall()

    for row in rows:
        day = str(row["day"])
        if day not in day_totals:
            day_totals[day] = {"total": 0, "cached": 0}

        try:
            tools = json.loads(row["tools_json"] or "[]")
        except json.JSONDecodeError:
            tools = []

        if not isinstance(tools, list):
            continue

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            day_totals[day]["total"] += 1
            if bool(tool.get("cache_hit", False)):
                day_totals[day]["cached"] += 1

    payload = []
    for day in sorted(day_totals.keys()):
        total = day_totals[day]["total"]
        cached = day_totals[day]["cached"]
        payload.append(
            {
                "day": day,
                "tool_runs": total,
                "cached_runs": cached,
                "cache_hit_pct": round((cached / total) * 100, 2) if total else 0.0,
            }
        )

    return payload


# SCHEMA_SQL and _MIGRATIONS are imported from common.schema (single source of truth)


def _run_migrations(db_path: str) -> None:
    """Apply any schema migrations not yet recorded in schema_migrations."""
    with _conn(db_path) as conn:
        row = conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").fetchone()
        current_version: int = int(row["v"]) if row else 0

    pending = [(v, d, s) for v, d, s in _MIGRATIONS if v > current_version]
    if not pending:
        return

    for version, description, sql in pending:
        with _conn(db_path) as conn:
            if sql.strip():
                try:
                    _execute_migration_script(conn, sql)
                except Exception as exc:
                    message = str(exc).lower()
                    ignorable = (
                        "duplicate column" in message or "already exists" in message or ("duplicate_object" in message)
                    )
                    if not ignorable:
                        raise
            if version >= 7:
                _backfill_cwe_column(conn)
            conn.execute(
                "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                (version, description, _utc_now()),
            )
        LOGGER.info("db.migration_applied", version=version, description=description)


def init_db(db_path: str):
    """Initialise the database schema if it does not exist."""
    with _conn(db_path) as conn:
        conn.executescript(adapt_schema(SCHEMA_SQL))
    _run_migrations(db_path)


def deduplicated_findings(
    db_path: str,
    target_name: str | None = None,
    severity: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Return findings deduplicated by fingerprint, keeping latest occurrence.

    When the same finding (same fingerprint) appears across multiple scans,
    only the most recent instance is returned.  This is useful for showing
    the current security posture without duplicate noise.
    """
    query = """
        SELECT f.*
        FROM findings f
        INNER JOIN (
            SELECT fingerprint, MAX(timestamp) AS latest_ts
            FROM findings
            WHERE fingerprint IS NOT NULL AND fingerprint != ''
    """
    params: list[Any] = []
    if target_name:
        query += " AND target_name = ?"
        params.append(target_name)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += """
            GROUP BY fingerprint
        ) dedup ON f.fingerprint = dedup.fingerprint AND f.timestamp = dedup.latest_ts
        WHERE 1=1
    """
    if target_name:
        query += " AND f.target_name = ?"
        params.append(target_name)
    if severity:
        query += " AND f.severity = ?"
        params.append(severity)
    query += f"""
        ORDER BY f.timestamp DESC, {_severity_order_sql('f.severity')} DESC, f.severity DESC
        LIMIT ?
    """
    params.append(limit)
    with _conn(db_path, read_only=True) as conn:
        rows = conn.execute(query, params).fetchall()  # nosec B608
    return [dict(row) for row in rows]
