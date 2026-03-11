from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from db_adapter import get_connection

LOGGER = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

# Re-export get_connection so existing callers (app.py etc.) continue to work
__all__ = ["get_connection", "init_db"]

_DB_PATH = os.environ.get("DASHBOARD_DB_PATH", "/data/security_scans.db")


def _conn(db_path: str | None = None):
    return get_connection(db_path or _DB_PATH)


def fetch_kpis(db_path: str) -> dict[str, Any]:
    with _conn(db_path) as conn:
        total_scans = conn.execute("SELECT COUNT(*) AS value FROM scans").fetchone()["value"]
        total_findings = conn.execute("SELECT COUNT(*) AS value FROM findings").fetchone()["value"]
        critical_findings = conn.execute(
            "SELECT COUNT(*) AS value FROM findings WHERE severity = 'CRITICAL'"
        ).fetchone()["value"]
        high_findings = conn.execute("SELECT COUNT(*) AS value FROM findings WHERE severity = 'HIGH'").fetchone()[
            "value"
        ]
        open_targets = conn.execute("SELECT COUNT(DISTINCT target_name) AS value FROM scans").fetchone()["value"]
        last_7d_scans = conn.execute(
            "SELECT COUNT(*) AS value FROM scans" " WHERE substr(created_at, 1, 10) >= date('now', '-7 day')"
        ).fetchone()["value"]
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "open_targets": open_targets,
        "last_7d_scans": last_7d_scans,
    }


def list_scans(
    db_path: str,
    limit: int = 100,
    target: str | None = None,
    status: str | None = None,
    policy_status: str | None = None,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM scans WHERE 1=1"
    params: list[Any] = []
    if target:
        query += " AND target_name = ?"
        params.append(target)
    if status:
        query += " AND status = ?"
        params.append(status)
    if policy_status:
        query += " AND policy_status = ?"
        params.append(policy_status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _conn(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def list_findings(
    db_path: str,
    limit: int = 500,
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    category: str | None = None,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM findings WHERE 1=1"
    params: list[Any] = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if tool:
        query += " AND tool = ?"
        params.append(tool)
    if target:
        query += " AND target_name = ?"
        params.append(target)
    if scan_id:
        query += " AND scan_id = ?"
        params.append(scan_id)
    if category:
        query += " AND category = ?"
        params.append(category)
    query += " ORDER BY timestamp DESC, severity DESC LIMIT ?"
    params.append(limit)
    with _conn(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def severity_breakdown(db_path: str) -> dict[str, int]:
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS total FROM findings GROUP BY severity ORDER BY total DESC"
        ).fetchall()
    return {row["severity"]: row["total"] for row in rows}


def tool_breakdown(db_path: str) -> dict[str, int]:
    with _conn(db_path) as conn:
        rows = conn.execute("SELECT tool, COUNT(*) AS total FROM findings GROUP BY tool ORDER BY total DESC").fetchall()
    return {row["tool"]: row["total"] for row in rows}


def target_breakdown(db_path: str) -> dict[str, int]:
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT target_name, COUNT(*) AS total FROM findings" " GROUP BY target_name ORDER BY total DESC LIMIT 20"
        ).fetchall()
    return {row["target_name"]: row["total"] for row in rows}


def scans_trend(db_path: str, days: int = 30) -> list[dict[str, Any]]:
    with _conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT substr(created_at, 1, 10) AS day,
                   COUNT(*) AS scans,
                   SUM(findings_count) AS findings
            FROM scans
            WHERE substr(created_at, 1, 10) >= date('now', ?)
            GROUP BY substr(created_at, 1, 10)
            ORDER BY day ASC
            """,
            (f"-{days} day",),
        ).fetchall()
    return [dict(row) for row in rows]


def distinct_targets(db_path: str) -> list[str]:
    with _conn(db_path) as conn:
        rows = conn.execute("SELECT DISTINCT target_name FROM scans ORDER BY target_name ASC").fetchall()
    return [row["target_name"] for row in rows]


def distinct_tools(db_path: str) -> list[str]:
    with _conn(db_path) as conn:
        rows = conn.execute("SELECT DISTINCT tool FROM findings ORDER BY tool ASC").fetchall()
    return [row["tool"] for row in rows]


def recent_failed_scans(db_path: str, limit: int = 20) -> list[dict[str, Any]]:
    with _conn(db_path) as conn:
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

    with _conn(db_path) as conn:
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
    query = """
        SELECT substr(created_at, 1, 10) AS day, tools_json
        FROM scans
        WHERE substr(created_at, 1, 10) >= date('now', ?)
        ORDER BY day ASC
    """

    day_totals: dict[str, dict[str, int]] = {}

    with _conn(db_path) as conn:
        rows = conn.execute(query, (f"-{days} day",)).fetchall()

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
# Versioned migrations (shared version numbering with orchestrator/storage.py)
# ---------------------------------------------------------------------------
_MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "baseline marker", ""),
]


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
                conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                (version, description, _utc_now()),
            )
        LOGGER.info("Applied schema migration v%s: %s", version, description)


def init_db(db_path: str):
    """Inizializza lo schema del database se non esiste."""
    with _conn(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
    _run_migrations(db_path)
