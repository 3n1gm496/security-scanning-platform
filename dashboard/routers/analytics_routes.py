"""Analytics and charting routes: /api/analytics/* and /api/chart/*."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from starlette import status

from auth import require_auth, require_permission, AuthContext
from db import get_connection, severity_breakdown
from rbac import Permission
from analytics import (
    calculate_risk_score,
    get_risk_distribution,
    get_compliance_summary,
    get_trend_analysis,
    get_target_risk_ranking,
    get_tool_effectiveness,
)
from remediation import RemediationEngine
from charting import ChartingEngine

from routers._shared import DB_PATH, cached

router = APIRouter(prefix="/api", tags=["analytics"])


# ── Analytics endpoints ───────────────────────────────────────────────────


@router.get("/analytics/risk-distribution", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_risk_distribution(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get risk score distribution across all findings."""
    return cached("risk_distribution", lambda: get_risk_distribution(DB_PATH))


@router.get("/analytics/compliance", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_compliance(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get OWASP Top 10 and CWE compliance mapping."""
    return cached("compliance", lambda: get_compliance_summary(DB_PATH))


@router.get("/analytics/trends", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_trends(days: int = Query(90, ge=7, le=365), auth: AuthContext = Depends(require_auth)) -> dict:
    """Get detailed trend analysis with risk scoring over time."""
    return cached(f"trends_{days}", lambda: get_trend_analysis(DB_PATH, days=days))


@router.get("/analytics/target-risk", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_target_risk(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """Get targets ranked by aggregated risk score."""
    return cached("target_risk", lambda: get_target_risk_ranking(DB_PATH))


@router.get("/analytics/tool-effectiveness", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_tool_effectiveness(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """Analyze tool effectiveness by findings and risk detection."""
    return cached("tool_effectiveness", lambda: get_tool_effectiveness(DB_PATH))


@router.get("/analytics/finding-risk/{finding_id}", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_finding_risk(finding_id: int, auth: AuthContext = Depends(require_auth)) -> dict:
    """Calculate risk score for a specific finding."""

    # Find specific finding
    with get_connection(DB_PATH) as conn:
        finding = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    finding_dict = dict(finding)
    risk_score = calculate_risk_score(finding_dict)

    return {
        "finding_id": finding_id,
        "risk_score": round(risk_score, 2),
        "severity": finding_dict.get("severity"),
        "category": finding_dict.get("category"),
        "has_cve": bool(finding_dict.get("cve")),
        "has_location": bool(finding_dict.get("file") and finding_dict.get("line")),
    }


@router.get("/remediation/{finding_id}", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def get_remediation_guidance(finding_id: int, auth: AuthContext = Depends(require_auth)) -> dict:
    """Get comprehensive remediation guidance for a finding."""

    # Find specific finding
    with get_connection(DB_PATH) as conn:
        finding = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    finding_dict = dict(finding)
    remediation = RemediationEngine.generate_remediation(finding_dict)

    return {
        "finding_id": finding_id,
        "finding_title": finding_dict.get("title"),
        "severity": finding_dict.get("severity"),
        "remediation": remediation,
    }


# ── Charting endpoints ────────────────────────────────────────────────────


@router.get("/chart/severity-distribution")
def chart_severity_distribution(
    days: int = Query(30, ge=1, le=365),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get findings severity distribution over time for stacked bar chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.severity_distribution(conn, days=days)


@router.get("/chart/tool-effectiveness")
def chart_tool_effectiveness(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get findings count by tool for bar chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.tool_effectiveness(conn)


@router.get("/chart/target-risk-heatmap")
def chart_target_risk(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get risk scores by target for heatmap visualization."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.target_risk_heatmap(conn)


@router.get("/chart/scan-trend")
def chart_scan_trend(
    days: int = Query(90, ge=7, le=365),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get scan completion trend over time for line chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.scan_status_trend(conn, days=days)


@router.get("/chart/remediation-progress")
def chart_remediation_progress(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get findings remediation progress for pie chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.remediation_progress(conn)


@router.get("/chart/severity-breakdown")
def chart_severity_breakdown(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get findings count grouped by severity for the dashboard bar chart.

    Returns ``{labels: [...], values: [...]}`` for consistency with other
    chart endpoints.  The frontend ``parseSev()`` helper accepts both this
    format and the raw ``{CRITICAL: N, ...}`` dict, but a uniform shape
    avoids confusion.
    """
    raw = severity_breakdown(DB_PATH)
    labels = list(raw.keys())
    values = list(raw.values())
    return {"labels": labels, "values": values}


@router.get("/chart/cve-distribution")
def chart_cve_distribution(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get top CVEs found for bar chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.cve_distribution(conn)
