"""Scan-related routes: trigger, list, compare, paginate, detail."""

from __future__ import annotations

import json
import os
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Query
from starlette import status

from auth import require_auth, require_permission, AuthContext
from db import get_connection, list_scans
from rbac import Permission
from pagination import ScansPaginator
from scan_runner import run_scan

from routers._shared import DB_PATH, scan_executor

router = APIRouter(prefix="/api", tags=["scans"])


@router.get("/scans")
def api_scans(
    limit: int = 100,
    target: str | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    policy_status: str | None = None,
    auth: AuthContext = Depends(require_auth),
) -> list[dict]:
    return list_scans(
        DB_PATH,
        limit=limit,
        target=target,
        status=status_value,
        policy_status=policy_status,
    )


@router.post("/scan/trigger", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def trigger_scan(
    target_type: str = Form(...),
    target: str = Form(...),
    name: str = Form(...),
    async_mode: bool = Form(False),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Trigger a new security scan (admin/operator only).

    Args:
        target_type: 'local', 'git', 'image', or 'url'
        target: path, git URL, image reference, or web URL to scan
        name: display name for the target
        async_mode: if true, return immediately with job_id; if false, wait for completion
    """
    # Validate inputs
    _VALID_TARGET_TYPES = {"local", "git", "image", "url"}
    if target_type not in _VALID_TARGET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"target_type must be one of: {', '.join(sorted(_VALID_TARGET_TYPES))}",
        )

    if not target or not name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target and name are required")

    root_dir = Path(__file__).parent.parent.parent.absolute()

    # URL format validation: ensure the target starts with http:// or https://.
    if target_type == "url":
        if not (target.startswith("http://") or target.startswith("https://")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL target must start with http:// or https://",
            )

    # Path traversal protection: for local targets, ensure the resolved path
    # stays within the allowed workspace directory (/data/workspaces).
    if target_type == "local":
        allowed_base = Path(os.getenv("WORKSPACE_DIR", str(root_dir / "data" / "workspaces"))).resolve()
        try:
            resolved_target = Path(target).resolve()
        except (OSError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid target path: {exc}",
            ) from exc
        try:
            resolved_target.relative_to(allowed_base)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Local target must be inside the workspace directory " f"({allowed_base}). Got: {resolved_target}"
                ),
            )

    # Pre-assign scan ID and start time so we can return them immediately
    # (including in async mode, before the worker thread begins).
    scan_id = str(_uuid.uuid4())
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    if async_mode:
        # Submit to bounded thread pool to prevent unbounded thread growth.
        # If the pool is at capacity, submit() still queues the task internally
        # (ThreadPoolExecutor uses an unbounded internal queue by default).
        scan_executor.submit(run_scan, target_type, target, name, str(root_dir), scan_id, started_at)
        return {
            "status": "queued",
            "scan_id": scan_id,
            "message": "Scan queued and running in background",
            "target_name": name,
        }
    else:
        # Wait for scan to complete
        return run_scan(target_type, target, name, str(root_dir), scan_id, started_at)


@router.get("/scans/compare")
def compare_scans(
    scan_id_1: str,
    scan_id_2: str,
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Compare two scans and show diff (new, resolved, unchanged findings)."""

    with get_connection(DB_PATH) as conn:
        # Get findings for both scans
        findings_1 = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id_1,)).fetchall()
        findings_2 = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id_2,)).fetchall()

        # Get scan metadata
        scan_1 = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id_1,)).fetchone()
        scan_2 = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id_2,)).fetchone()

    if not scan_1 or not scan_2:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both scans not found")

    # Convert to dicts
    findings_1_list = [dict(f) for f in findings_1]
    findings_2_list = [dict(f) for f in findings_2]

    # Build fingerprint sets
    fingerprints_1 = {f["fingerprint"]: f for f in findings_1_list if f.get("fingerprint")}
    fingerprints_2 = {f["fingerprint"]: f for f in findings_2_list if f.get("fingerprint")}

    # Calculate diff
    new_fingerprints = set(fingerprints_2.keys()) - set(fingerprints_1.keys())
    resolved_fingerprints = set(fingerprints_1.keys()) - set(fingerprints_2.keys())
    unchanged_fingerprints = set(fingerprints_1.keys()) & set(fingerprints_2.keys())

    new_findings = [fingerprints_2[fp] for fp in new_fingerprints]
    resolved_findings = [fingerprints_1[fp] for fp in resolved_fingerprints]
    unchanged_findings = [fingerprints_2[fp] for fp in unchanged_fingerprints]

    # Count by severity
    def count_by_severity(findings_list):
        counts = {}
        for f in findings_list:
            sev = f.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    return {
        "scan_1": {
            "id": scan_id_1,
            "target_name": dict(scan_1).get("target_name"),
            "created_at": dict(scan_1).get("created_at"),
            "findings_count": len(findings_1_list),
        },
        "scan_2": {
            "id": scan_id_2,
            "target_name": dict(scan_2).get("target_name"),
            "created_at": dict(scan_2).get("created_at"),
            "findings_count": len(findings_2_list),
        },
        "diff": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged_findings),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "new_by_severity": count_by_severity(new_findings),
            "resolved_by_severity": count_by_severity(resolved_findings),
        },
    }


@router.get("/scans/paginated")
def paginate_scans(
    target: str = Query(""),
    status: str = Query(""),
    policy: str = Query(""),
    cursor: str | None = Query(None),
    per_page: int = Query(20, ge=1, le=200),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("DESC"),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get paginated scans with cursor-based pagination.

    Query Parameters:
    - target: Filter by target name (partial match)
    - status: Filter by status (exact match: completed, failed, running)
    - policy: Filter by policy_status (exact match: PASS, BLOCK, UNKNOWN)
    - cursor: Pagination cursor from previous response
    - per_page: Items per page (1-200, default 20)
    - sort_by: Column to sort by (default: created_at)
    - sort_order: ASC or DESC (default: DESC)
    """
    with get_connection(DB_PATH) as conn:
        paginator = ScansPaginator(per_page=per_page)
        return paginator.paginate(
            conn,
            target_filter=target,
            status_filter=status,
            policy_filter=policy,
            cursor=cursor,
            sort_by=sort_by,
            sort_order=sort_order,
        )


@router.get("/scans/{scan_id}")
def api_get_scan(
    scan_id: int,
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get a single scan by ID with its findings summary and per-tool execution results."""
    with get_connection(DB_PATH) as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        scan_dict = dict(scan)
        rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        ).fetchall()
        scan_dict["severity_breakdown"] = {r["severity"]: r["count"] for r in rows}
        rows = conn.execute(
            "SELECT tool, COUNT(*) as count FROM findings WHERE scan_id = ? GROUP BY tool",
            (scan_id,),
        ).fetchall()
        scan_dict["tool_breakdown"] = {r["tool"]: r["count"] for r in rows}
        # Deserialize per-tool execution results from tools_json
        raw_tools = scan_dict.get("tools_json")
        if raw_tools:
            try:
                scan_dict["tool_results"] = json.loads(raw_tools)
            except (json.JSONDecodeError, TypeError):
                scan_dict["tool_results"] = []
        else:
            scan_dict["tool_results"] = []
    return scan_dict
