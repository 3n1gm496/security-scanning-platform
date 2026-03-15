"""Finding routes: list, paginate, detail, state management, badge."""

from __future__ import annotations

from logging_config import get_logger

from fastapi import APIRouter, Depends, Form, HTTPException, Query
from fastapi.responses import Response
from starlette import status

from auth import require_auth, require_permission, AuthContext
from db import get_connection, list_findings
from rbac import Permission
from finding_management import (
    FindingStatus,
    update_finding_status,
    assign_finding,
    mark_false_positive,
    accept_risk,
    add_finding_comment,
    get_finding_comments,
    bulk_update_status,
    get_finding_state,
    get_triage_summary,
)
from pagination import FindingsPaginator
from remediation import RemediationEngine

from routers._shared import DB_PATH

LOGGER = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["findings"])


@router.get("/findings")
def api_findings(
    limit: int = Query(500, ge=1, le=5000),
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    category: str | None = None,
    search: str | None = None,
    auth: AuthContext = Depends(require_auth),
) -> list[dict]:
    if search:
        # Full-text search across title, description, file
        query = """
            SELECT * FROM findings
            WHERE (title LIKE ? OR description LIKE ? OR file LIKE ? OR cve LIKE ?)
        """
        params = [f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"]

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

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with get_connection(DB_PATH) as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # Original logic
    return list_findings(
        DB_PATH,
        limit=limit,
        severity=severity,
        tool=tool,
        target=target,
        scan_id=scan_id,
        category=category,
    )


@router.get("/findings/status-counts")
def api_findings_status_counts(auth: AuthContext = Depends(require_auth)) -> dict:
    """Return finding counts grouped by triage status in a single query."""
    with get_connection(DB_PATH) as conn:
        rows = conn.execute("""
            SELECT COALESCE(fs.status, 'new') AS status, COUNT(*) AS count
            FROM findings f
            LEFT JOIN finding_states fs ON fs.finding_id = f.id
            GROUP BY COALESCE(fs.status, 'new')
        """).fetchall()
    return {row["status"]: row["count"] for row in rows}


@router.get("/findings/paginated")
def paginate_findings(
    search: str = Query(""),
    severity: str = Query(""),
    tool: str = Query(""),
    target: str = Query(""),
    scan_id: str | None = Query(None),
    status: str | None = Query(None),
    cursor: str | None = Query(None),
    per_page: int = Query(50, ge=1, le=1000),
    sort_by: str = Query("id"),
    sort_order: str = Query("ASC"),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get paginated findings with cursor-based pagination.

    Query Parameters:
    - search: Full-text search across title, description, file_path, cve_id
    - severity: Comma-separated list of severities (CRITICAL,HIGH,MEDIUM,LOW)
    - tool: Comma-separated list of tools (semgrep,bandit,nuclei,etc)
    - target: Filter by target name (partial match)
    - scan_id: Filter by specific scan ID
    - status: Filter by triage status (open, in_progress, resolved, false_positive, accepted_risk)
    - cursor: Pagination cursor from previous response
    - per_page: Items per page (1-1000, default 50)
    - sort_by: Column to sort by (default: id)
    - sort_order: ASC or DESC (default: ASC)
    """
    with get_connection(DB_PATH) as conn:
        paginator = FindingsPaginator(per_page=per_page)
        severity_list = [s.strip() for s in severity.split(",")] if severity else []
        tool_list = [t.strip() for t in tool.split(",")] if tool else []

        return paginator.paginate(
            conn,
            search=search,
            severity_filter=severity_list if severity_list else None,
            tool_filter=tool_list if tool_list else None,
            scan_id=scan_id,
            status_filter=status if status else None,
            target_filter=target if target else None,
            cursor=cursor,
            sort_by=sort_by,
            sort_order=sort_order,
        )


@router.get("/findings/triage-summary")
def api_triage_summary(auth: AuthContext = Depends(require_auth)) -> dict:
    """Comprehensive triage summary: status counts, expired risk, overdue findings."""
    return get_triage_summary()


@router.get("/findings/{finding_id}")
def api_get_finding(
    finding_id: int,
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get a single finding by ID with enriched remediation data."""
    with get_connection(DB_PATH) as conn:
        finding = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding_dict = dict(finding)
    try:
        remediation = RemediationEngine.generate_remediation(finding_dict)
        finding_dict["remediation_guide"] = remediation
    except Exception as _rem_err:
        LOGGER.warning("remediation.guide_failed", finding_id=finding_id, error=str(_rem_err))
        finding_dict["remediation_guide"] = {}
    return finding_dict


@router.get("/findings/{finding_id}/state")
def api_get_finding_state(finding_id: int, auth: AuthContext = Depends(require_auth)) -> dict:
    """Get finding management state."""
    state = get_finding_state(finding_id)
    if not state:
        return {"finding_id": finding_id, "status": "new", "assigned_to": None}
    return state


@router.patch(
    "/findings/{finding_id}/status",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_update_finding_status(
    finding_id: int,
    status_value: str = Form(...),
    notes: str | None = Form(None),
    assigned_to: str | None = Form(None),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Update finding status."""
    try:
        finding_status = FindingStatus(status_value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status_value}")

    result = update_finding_status(
        finding_id,
        finding_status,
        user=auth.api_key_prefix or "unknown",
        notes=notes,
        assigned_to=assigned_to,
    )

    return result


@router.post(
    "/findings/{finding_id}/assign",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_assign_finding(
    finding_id: int,
    assigned_to: str = Form(...),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Assign finding to a user."""
    result = assign_finding(finding_id, assigned_to, assigned_by=auth.api_key_prefix or "unknown")
    return result


@router.post(
    "/findings/{finding_id}/false-positive",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_mark_false_positive(
    finding_id: int,
    reason: str = Form(...),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Mark finding as false positive."""
    result = mark_false_positive(finding_id, reason, user=auth.api_key_prefix or "unknown")
    return result


@router.post(
    "/findings/{finding_id}/accept-risk",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_accept_risk(
    finding_id: int,
    justification: str = Form(...),
    expires_at: str = Form(...),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Accept risk for finding with expiration date."""
    result = accept_risk(finding_id, justification, expires_at, user=auth.api_key_prefix or "unknown")
    return result


@router.post(
    "/findings/{finding_id}/comment",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_add_finding_comment(
    finding_id: int,
    comment: str = Form(...),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Add comment to finding."""
    comment_id = add_finding_comment(finding_id, user=auth.api_key_prefix or "unknown", comment=comment)
    return {"comment_id": comment_id, "finding_id": finding_id}


@router.get("/findings/{finding_id}/comments")
def api_get_finding_comments(finding_id: int, auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """Get all comments for a finding."""
    return get_finding_comments(finding_id)


@router.post(
    "/findings/bulk/update-status",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_bulk_update_status(
    finding_ids: list[int],
    status_value: str = Query(..., alias="status"),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Bulk update status for multiple findings."""
    try:
        finding_status = FindingStatus(status_value)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid status: {status_value}")

    result = bulk_update_status(finding_ids, finding_status, user=auth.api_key_prefix or "unknown")
    return result


@router.get("/badge/{target_name}.svg")
def generate_badge(target_name: str, auth: AuthContext = Depends(require_auth)) -> Response:
    """Generate SVG badge for scan status."""
    # Get latest scan for target
    with get_connection(DB_PATH) as conn:
        scan = conn.execute(
            "SELECT status, policy_status, findings_count, critical_count,"
            " high_count FROM scans WHERE target_name = ? ORDER BY created_at DESC LIMIT 1",
            (target_name,),
        ).fetchone()

    if not scan:
        # No scans found
        svg = """<svg xmlns="http://www.w3.org/2000/svg" width="140" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a"><rect width="140" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h60v20H0z"/>
    <path fill="#9f9f9f" d="M60 0h80v20H60z"/>
    <path fill="url(#b)" d="M0 0h140v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="30" y="15" fill="#010101" fill-opacity=".3">security</text>
    <text x="30" y="14">security</text>
    <text x="99" y="15" fill="#010101" fill-opacity=".3">unknown</text>
    <text x="99" y="14">unknown</text>
  </g>
</svg>"""
        return Response(content=svg, media_type="image/svg+xml")

    scan_dict = dict(scan)
    status_val = scan_dict.get("status", "")
    policy_status = scan_dict.get("policy_status", "")
    critical_count = scan_dict.get("critical_count", 0)
    high_count = scan_dict.get("high_count", 0)

    # Determine badge color and message
    if policy_status == "BLOCK" or critical_count > 0:
        color = "#e05d44"  # Red
        message = f"{critical_count} critical"
    elif high_count > 0:
        color = "#fe7d37"  # Orange
        message = f"{high_count} high"
    elif status_val == "COMPLETED_CLEAN":
        color = "#97ca00"  # Green
        message = "passing"
    else:
        color = "#dfb317"  # Yellow
        message = "warnings"

    # Generate SVG
    message_width = len(message) * 6 + 10
    total_width = 60 + message_width

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a"><rect width="{total_width}" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h60v20H0z"/>
    <path fill="{color}" d="M60 0h{message_width}v20H60z"/>
    <path fill="url(#b)" d="M0 0h{total_width}v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="30" y="15" fill="#010101" fill-opacity=".3">security</text>
    <text x="30" y="14">security</text>
    <text x="{60 + message_width // 2}" y="15" fill="#010101" fill-opacity=".3">{message}</text>
    <text x="{60 + message_width // 2}" y="14">{message}</text>
  </g>
</svg>"""

    return Response(content=svg, media_type="image/svg+xml")
