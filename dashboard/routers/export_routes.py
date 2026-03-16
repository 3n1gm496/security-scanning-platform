"""Export routes: GET /api/export/findings."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from analytics import get_compliance_summary, get_risk_distribution
from auth import AuthContext, require_auth, require_permission
from db import count_findings, list_findings
from export import _sanitize_csv_row, export_to_csv, export_to_html, export_to_json, export_to_pdf, export_to_sarif
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from rbac import Permission
from routers._shared import DB_PATH
from starlette import status

router = APIRouter(prefix="/api", tags=["export"])


@router.get("/export/findings", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
async def export_findings_endpoint(
    format: str = Query(..., pattern="^(json|csv|sarif|html|pdf)$"),
    limit: int = Query(1000, ge=1, le=50000),
    severity: str | None = None,
    tool: str | None = None,
    status: str | None = None,
    target: str | None = None,
    search: str | None = None,
    scan_id: str | None = None,
    include_analytics: bool = Query(False),
    auth: AuthContext = Depends(require_auth),
) -> Response:
    """
    Export findings in multiple formats.
    Supported formats: json, csv, sarif, html, pdf
    """
    # Fetch findings and total count (to signal truncation to the client)
    total = count_findings(
        DB_PATH,
        severity=severity,
        tool=tool,
        target=target,
        scan_id=scan_id,
        search=search,
        status=status,
        target_partial=True,
    )
    findings = list_findings(
        DB_PATH,
        limit=limit,
        severity=severity,
        tool=tool,
        target=target,
        scan_id=scan_id,
        search=search,
        status=status,
        target_partial=True,
    )

    # Get scan info if scan_id provided
    scan_info = {}
    if scan_id:
        from db import get_connection

        with get_connection(DB_PATH) as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row:
                scan_info = dict(row)

    # Export based on format
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if format == "json":
        content = export_to_json(findings)
        media_type = "application/json"
        filename = f"findings_{ts}.json"

    elif format == "csv":
        # Stream CSV in batches for large exports to limit memory usage
        if total > 1000:
            filename = f"findings_{ts}.csv"
            batch_size = 1000
            fieldnames = []
            header_written = False

            def _csv_stream():
                nonlocal fieldnames, header_written
                for offset in range(0, limit, batch_size):
                    batch = list_findings(
                        DB_PATH,
                        limit=min(batch_size, limit - offset),
                        severity=severity,
                        tool=tool,
                        status=status,
                        target=target,
                        search=search,
                        scan_id=scan_id,
                        target_partial=True,
                        offset=offset,
                    )
                    if not batch:
                        break
                    if not header_written:
                        fieldnames = sorted(batch[0].keys())
                        buf = io.StringIO()
                        w = csv.DictWriter(buf, fieldnames=fieldnames)
                        w.writeheader()
                        yield buf.getvalue()
                        header_written = True
                    buf = io.StringIO()
                    w = csv.DictWriter(buf, fieldnames=fieldnames)
                    for row in batch:
                        w.writerow(_sanitize_csv_row(row))
                    yield buf.getvalue()

            return StreamingResponse(
                _csv_stream(),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "X-Total-Count": str(total),
                },
            )

        content = export_to_csv(findings)
        media_type = "text/csv"
        filename = f"findings_{ts}.csv"

    elif format == "sarif":
        content = export_to_sarif(findings)
        media_type = "application/json"
        filename = f"findings_{ts}.sarif"

    elif format == "html":
        content = export_to_html(findings, scan_info)
        media_type = "text/html"
        filename = f"findings_{ts}.html"

    elif format == "pdf":
        # Gather analytics data if requested
        analytics_data = {}
        if include_analytics:
            analytics_data = {
                "risk_distribution": get_risk_distribution(DB_PATH),
                "compliance": get_compliance_summary(DB_PATH),
            }

        content = export_to_pdf(findings, scan_info, analytics_data)
        media_type = "application/pdf"
        filename = f"findings_{ts}.pdf"

    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid format")

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Total-Count": str(total),
        "X-Exported-Count": str(len(findings)),
    }
    return Response(content=content, media_type=media_type, headers=headers)
