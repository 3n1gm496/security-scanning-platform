"""Audit log routes: /api/audit and /api/audit/export."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from auth import AuthContext, require_auth, require_permission
from db import get_connection
from db_adapter import is_postgres
from export import _sanitize_csv_value
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from logging_config import get_logger
from rbac import Permission, log_audit, purge_audit_log
from routers._shared import DB_PATH

router = APIRouter(prefix="/api", tags=["audit"])
LOGGER = get_logger(__name__)


@router.get("/audit", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
async def get_audit_log(
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
async def export_audit_log(
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
            w.writerow({key: _sanitize_csv_value(value) for key, value in row.items()})
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit_{ts}.csv"'},
    )


@router.post("/audit/purge", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
async def purge_audit(
    retention_days: int = Query(90, ge=1, le=3650),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Purge audit log entries older than retention_days (admin only).

    Also cleans up old webhook delivery records.
    Default retention is 90 days.
    """
    audit_deleted = purge_audit_log(retention_days)

    # Also purge old webhook delivery records
    webhook_deleted = 0
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        with get_connection(DB_PATH) as conn:
            if is_postgres():
                cursor = conn.execute(
                    "DELETE FROM webhook_deliveries WHERE delivered_at < ?",
                    (cutoff.isoformat(),),
                )
            else:
                cursor = conn.execute(
                    "DELETE FROM webhook_deliveries WHERE delivered_at < ?",
                    (cutoff.date().isoformat(),),
                )
            webhook_deleted = cursor.rowcount
    except Exception:
        LOGGER.warning("audit.webhook_delivery_purge_failed", retention_days=retention_days, exc_info=True)

    log_audit(
        action="audit.purge",
        user_id=auth.user_id,
        api_key_prefix=auth.api_key_prefix,
        resource=f"retention_days:{retention_days}",
        result=f"audit:{audit_deleted},webhooks:{webhook_deleted}",
    )

    return {
        "audit_entries_deleted": audit_deleted,
        "webhook_deliveries_deleted": webhook_deleted,
        "retention_days": retention_days,
    }
