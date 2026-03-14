"""Export routes: GET /api/export/findings."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from starlette import status

from auth import require_auth, require_permission, AuthContext
from db import count_findings, list_findings, list_scans
from rbac import Permission
from export import export_to_json, export_to_csv, export_to_sarif, export_to_html, export_to_pdf, _sanitize_csv_row
from analytics import get_risk_distribution, get_compliance_summary

from routers._shared import DB_PATH

router = APIRouter(prefix="/api", tags=["export"])


@router.get("/export/findings", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def export_findings_endpoint(
    format: str = Query(..., pattern="^(json|csv|sarif|html|pdf)$"),
    limit: int = Query(1000, ge=1, le=50000),
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    include_analytics: bool = Query(False),
    auth: AuthContext = Depends(require_auth),
) -> Response:
    """
    Export findings in multiple formats.
    Supported formats: json, csv, sarif, html, pdf
    """
    # Fetch findings and total count (to signal truncation to the client)
    total = count_findings(DB_PATH, severity=severity, tool=tool, target=target, scan_id=scan_id)
    findings = list_findings(DB_PATH, limit=limit, severity=severity, tool=tool, target=target, scan_id=scan_id)

    # Get scan info if scan_id provided
    scan_info = {}
    if scan_id:
        # Search across all scans (not just the most recent one) to find the matching scan
        scans = list_scans(DB_PATH, limit=10000)
        for scan in scans:
            if scan.get("id") == scan_id:
                scan_info = scan
                break

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

            def _csv_stream():
                header_written = False
                for offset in range(0, limit, batch_size):
                    batch = list_findings(
                        DB_PATH,
                        limit=min(batch_size, limit - offset),
                        severity=severity,
                        tool=tool,
                        target=target,
                        scan_id=scan_id,
                        offset=offset,
                    )
                    if not batch:
                        break
                    if not header_written:
                        all_fields = sorted({k for row in batch for k in row})
                        buf = io.StringIO()
                        w = csv.DictWriter(buf, fieldnames=all_fields)
                        w.writeheader()
                        yield buf.getvalue()
                        header_written = True
                    else:
                        all_fields = sorted({k for row in batch for k in row})
                    buf = io.StringIO()
                    w = csv.DictWriter(buf, fieldnames=all_fields)
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
