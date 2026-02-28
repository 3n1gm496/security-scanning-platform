from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def get_connection(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_kpis(db_path: str) -> dict[str, Any]:
    with get_connection(db_path) as conn:
        total_scans = conn.execute("SELECT COUNT(*) AS value FROM scans").fetchone()["value"]
        total_findings = conn.execute("SELECT COUNT(*) AS value FROM findings").fetchone()["value"]
        critical_findings = conn.execute("SELECT COUNT(*) AS value FROM findings WHERE severity = 'CRITICAL'").fetchone()["value"]
        high_findings = conn.execute("SELECT COUNT(*) AS value FROM findings WHERE severity = 'HIGH'").fetchone()["value"]
        open_targets = conn.execute("SELECT COUNT(DISTINCT target_name) AS value FROM scans").fetchone()["value"]
        last_7d_scans = conn.execute(
            "SELECT COUNT(*) AS value FROM scans WHERE substr(created_at, 1, 10) >= date('now', '-7 day')"
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
    with get_connection(db_path) as conn:
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
    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def severity_breakdown(db_path: str) -> dict[str, int]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS total FROM findings GROUP BY severity ORDER BY total DESC"
        ).fetchall()
    return {row["severity"]: row["total"] for row in rows}


def tool_breakdown(db_path: str) -> dict[str, int]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT tool, COUNT(*) AS total FROM findings GROUP BY tool ORDER BY total DESC"
        ).fetchall()
    return {row["tool"]: row["total"] for row in rows}


def target_breakdown(db_path: str) -> dict[str, int]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT target_name, COUNT(*) AS total FROM findings GROUP BY target_name ORDER BY total DESC LIMIT 20"
        ).fetchall()
    return {row["target_name"]: row["total"] for row in rows}


def scans_trend(db_path: str, days: int = 30) -> list[dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS scans, SUM(findings_count) AS findings
            FROM scans
            WHERE substr(created_at, 1, 10) >= date('now', ?)
            GROUP BY substr(created_at, 1, 10)
            ORDER BY day ASC
            """,
            (f"-{days} day",),
        ).fetchall()
    return [dict(row) for row in rows]


def distinct_targets(db_path: str) -> list[str]:
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT DISTINCT target_name FROM scans ORDER BY target_name ASC").fetchall()
    return [row["target_name"] for row in rows]


def distinct_tools(db_path: str) -> list[str]:
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT DISTINCT tool FROM findings ORDER BY tool ASC").fetchall()
    return [row["tool"] for row in rows]


def recent_failed_scans(db_path: str, limit: int = 20) -> list[dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE status != 'COMPLETED_CLEAN' ORDER BY created_at DESC LIMIT ?",
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

    with get_connection(db_path) as conn:
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
