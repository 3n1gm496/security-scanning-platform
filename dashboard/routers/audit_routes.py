"""Audit log routes: /api/audit and /api/audit/export."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from auth import require_auth, require_permission, AuthContext
from db import get_connection
from rbac import Permission

from routers._shared import DB_PATH

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/audit", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def get_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    action: str | None = Query(None),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Return recent audit log entries (admin only).

    Query parameters:
    - limit: Number of entries to return (1-1000, default 100)
    - action: Filter by action type (e.g. api_key.create, webhook.delete)
    """
    query = "SELECT * FROM audit_log"
    params: list = []
    if action:
        query += " WHERE action = ?"
        params.append(action)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection(DB_PATH) as conn:
        rows = conn.execute(query, params).fetchall()
    return {"items": [dict(r) for r in rows], "count": len(rows)}


@router.get("/audit/export", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def export_audit_log(
    format: str = Query("csv", pattern="^(csv|json)$"),
    limit: int = Query(5000, ge=1, le=50000),
    action: str | None = Query(None),
    auth: AuthContext = Depends(require_auth),
) -> Response:
    """Export audit log as CSV or JSON (admin only)."""
    query = "SELECT * FROM audit_log"
    params: list = []
    if action:
        query += " WHERE action = ?"
        params.append(action)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection(DB_PATH) as conn:
        rows = [dict(r) for r in conn.execute(query, params).fetchall()]

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if format == "json":
        content = json.dumps(rows, indent=2, default=str)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="audit_{ts}.json"'},
        )

    # CSV export
    buf = io.StringIO()
    if rows:
        fieldnames = list(rows[0].keys())
        w = csv.DictWriter(buf, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit_{ts}.csv"'},
    )
