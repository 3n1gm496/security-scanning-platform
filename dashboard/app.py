from __future__ import annotations

import os
import secrets
import time
import csv
import io
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from db import (
    cache_hit_stats,
    cache_hit_trend,
    distinct_targets,
    distinct_tools,
    fetch_kpis,
    list_findings,
    list_scans,
    parse_artifacts,
    recent_failed_scans,
    scans_trend,
    severity_breakdown,
    target_breakdown,
    tool_breakdown,
)
from monitoring import router as monitoring_router
from rbac import (
    Role,
    Permission,
    init_rbac_tables,
    create_api_key,
    list_api_keys,
    revoke_api_key,
    create_default_admin_key,
)
from auth import require_auth, require_permission, AuthContext
from webhooks import (
    init_webhook_tables,
    create_webhook,
    list_webhooks,
    delete_webhook,
    toggle_webhook,
    WebhookEvent,
)
from export import (
    export_to_json,
    export_to_csv,
    export_to_sarif,
    export_to_html,
    export_to_pdf,
)
from analytics import (
    calculate_risk_score,
    get_risk_distribution,
    get_compliance_summary,
    get_trend_analysis,
    get_target_risk_ranking,
    get_tool_effectiveness,
)

APP_TITLE = "Security Scanning Dashboard"
DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")
USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
PASSWORD = os.getenv("DASHBOARD_PASSWORD", "change-me")
# chiave segreta per sessione (usa .env o variabile ambiente sicura)
SESSION_SECRET = os.getenv("DASHBOARD_SESSION_SECRET", "please-change-this")
RATE_LIMIT_REQUESTS = int(os.getenv("DASHBOARD_RATE_LIMIT_REQUESTS", "180"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DASHBOARD_RATE_LIMIT_WINDOW_SECONDS", "60"))

app = FastAPI(title=APP_TITLE)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# Initialize RBAC tables
init_rbac_tables()
init_webhook_tables()
default_key = create_default_admin_key()
if default_key:
    print(f"\n{'='*80}")
    print(f"DEFAULT ADMIN API KEY: {default_key}")
    print(f"Store this key securely! It will not be shown again.")
    print(f"{'='*80}\n")

# Add monitoring endpoints
app.include_router(monitoring_router, prefix="/api")

_RATE_LIMIT_EXCLUDED_PATHS = {"/api/health", "/api/ready", "/api/metrics"}
_request_timestamps: dict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = Lock()


def _client_key(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return "unknown"


def _is_rate_limited(client_id: str, now: float) -> bool:
    with _rate_limit_lock:
        bucket = _request_timestamps[client_id]
        threshold = now - RATE_LIMIT_WINDOW_SECONDS
        while bucket and bucket[0] < threshold:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_REQUESTS:
            return True
        bucket.append(now)
    return False


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.url.path.startswith("/api") and request.url.path not in _RATE_LIMIT_EXCLUDED_PATHS:
        now = time.monotonic()
        client_id = _client_key(request)
        if _is_rate_limited(client_id, now):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Retry later."},
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


# ---------------------------------------------------------------------------
# Autenticazione basata su sessione (login form)
# ---------------------------------------------------------------------------

def get_current_user(request: Request) -> str:
    """Dependency che restituisce l'utente autenticato.
    - per pagine HTML non-autenticate effettua redirect a /login
    - per chiamate API restituisce 401
    """
    user = request.session.get("user")
    if not user:
        if request.url.path.startswith("/api"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        else:
            raise HTTPException(
                status_code=status.HTTP_302_FOUND,
                headers={"Location": "/login"},
            )
    return user


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    """Mostra il form di login. Se già autenticato, reindirizza all'overview."""
    if request.session.get("user"):
        return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/"})
    return templates.TemplateResponse(request, "login.html", {"error": error})


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    # confronta in modo sicuro con le credenziali memorizzate
    if not (secrets.compare_digest(username or "", USERNAME) and secrets.compare_digest(password or "", PASSWORD)):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Credenziali non valide"},
            status_code=401,
        )
    # setta la sessione e reindirizza
    request.session["user"] = username
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/"})


@app.get("/logout")
def logout(request: Request) -> HTMLResponse:
    request.session.clear()
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})


@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: str = Depends(get_current_user)) -> HTMLResponse:
    context = {
        "user": user,
        "kpis": fetch_kpis(DB_PATH),
        "cache_stats": cache_hit_stats(DB_PATH),
        "cache_trend": cache_hit_trend(DB_PATH, 14),
        "severity_breakdown": severity_breakdown(DB_PATH),
        "tool_breakdown": tool_breakdown(DB_PATH),
        "target_breakdown": target_breakdown(DB_PATH),
        "trend": scans_trend(DB_PATH, 14),
        "recent_scans": recent_failed_scans(DB_PATH, 10),
    }
    return templates.TemplateResponse(request, "index.html", context)


@app.get("/scans", response_class=HTMLResponse)
def scans_page(
    request: Request,
    target: str | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    policy_status: str | None = None,
    user: str = Depends(get_current_user),
) -> HTMLResponse:
    scans = list_scans(DB_PATH, 200, target=target, status=status_value, policy_status=policy_status)
    for scan in scans:
        scan["artifacts"] = parse_artifacts(scan)
    return templates.TemplateResponse(
        request,
        "scans.html",
        {
            "user": user,
            "scans": scans,
            "targets": distinct_targets(DB_PATH),
            "selected_target": target,
            "selected_status": status_value,
            "selected_policy_status": policy_status,
        },
    )


@app.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    category: str | None = None,
    user: str = Depends(get_current_user),
) -> HTMLResponse:
    findings = list_findings(
        DB_PATH,
        500,
        severity=severity,
        tool=tool,
        target=target,
        scan_id=scan_id,
        category=category,
    )
    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "user": user,
            "findings": findings,
            "tools": distinct_tools(DB_PATH),
            "targets": distinct_targets(DB_PATH),
            "selected_severity": severity,
            "selected_tool": tool,
            "selected_target": target,
            "selected_scan_id": scan_id,
            "selected_category": category,
        },
    )


@app.get("/api/kpi")
def api_kpi(user: str = Depends(get_current_user)) -> dict:
    return fetch_kpis(DB_PATH)


@app.get("/api/trends")
def api_trends(days: int = 30, user: str = Depends(get_current_user)) -> list[dict]:
    return scans_trend(DB_PATH, days)


@app.get("/api/cache-hits")
def api_cache_hits(user: str = Depends(get_current_user)) -> dict:
    return cache_hit_stats(DB_PATH)


@app.get("/api/cache-hit-trend")
def api_cache_hit_trend(days: int = 14, user: str = Depends(get_current_user)) -> list[dict]:
    return cache_hit_trend(DB_PATH, days)


@app.get("/api/cache-hit-trend.csv")
def api_cache_hit_trend_csv(days: int = 14, user: str = Depends(get_current_user)) -> Response:
    rows = cache_hit_trend(DB_PATH, days)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["day", "tool_runs", "cached_runs", "cache_hit_pct"])
    for row in rows:
        writer.writerow(
            [
                row.get("day", ""),
                row.get("tool_runs", 0),
                row.get("cached_runs", 0),
                row.get("cache_hit_pct", 0.0),
            ]
        )

    content = output.getvalue()
    output.close()

    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="cache-hit-trend.csv"'},
    )


@app.get("/api/scans")
def api_scans(
    limit: int = 100,
    target: str | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    policy_status: str | None = None,
    user: str = Depends(get_current_user),
) -> list[dict]:
    return list_scans(
        DB_PATH,
        limit=limit,
        target=target,
        status=status_value,
        policy_status=policy_status,
    )


@app.get("/api/findings")
def api_findings(
    limit: int = 500,
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: str | None = None,
    category: str | None = None,
    user: str = Depends(get_current_user),
) -> list[dict]:
    return list_findings(
        DB_PATH,
        limit=limit,
        severity=severity,
        tool=tool,
        target=target,
        scan_id=scan_id,
        category=category,
    )


# ──────────────────────────────────────────────────────────────────────────────
# API Key Management Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/keys", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def get_api_keys(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """List all API keys (admin/operator only)."""
    return list_api_keys()


@app.post("/api/keys", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def create_new_api_key(
    name: str = Form(...),
    role: str = Form(...),
    expires_days: int | None = Form(None),
    auth: AuthContext = Depends(require_auth)
) -> dict:
    """Create a new API key (admin/operator only)."""
    try:
        role_enum = Role(role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role: {role}"
        )
    
    full_key, prefix = create_api_key(
        name=name,
        role=role_enum,
        expires_days=expires_days,
        created_by=auth.api_key_prefix or auth.user_id
    )
    
    return {
        "key": full_key,
        "prefix": prefix,
        "role": role,
        "name": name,
        "warning": "Store this key securely! It will not be shown again."
    }


@app.delete("/api/keys/{key_prefix}", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def delete_api_key(
    key_prefix: str,
    auth: AuthContext = Depends(require_auth)
) -> dict:
    """Revoke an API key (admin/operator only)."""
    success = revoke_api_key(key_prefix)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    return {"status": "revoked", "key_prefix": key_prefix}


# ──────────────────────────────────────────────────────────────────────────────
# Webhook Management Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/webhooks", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def get_webhooks(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """List all webhooks (admin/operator only)."""
    return list_webhooks()


@app.post("/api/webhooks", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def create_new_webhook(
    name: str = Form(...),
    url: str = Form(...),
    events: str = Form(...),  # Comma-separated event types
    secret: str | None = Form(None),
    auth: AuthContext = Depends(require_auth)
) -> dict:
    """Create a new webhook (admin/operator only)."""
    # Parse events
    event_list = []
    for event_str in events.split(","):
        event_str = event_str.strip()
        try:
            event_list.append(WebhookEvent(event_str))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event type: {event_str}"
            )
    
    webhook_id = create_webhook(name, url, event_list, secret)
    
    return {
        "id": webhook_id,
        "name": name,
        "url": url,
        "events": events
    }


@app.delete("/api/webhooks/{webhook_id}", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def delete_webhook_endpoint(
    webhook_id: int,
    auth: AuthContext = Depends(require_auth)
) -> dict:
    """Delete a webhook (admin/operator only)."""
    success = delete_webhook(webhook_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found"
        )
    
    return {"status": "deleted", "id": webhook_id}


@app.patch("/api/webhooks/{webhook_id}", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def toggle_webhook_endpoint(
    webhook_id: int,
    is_active: bool = Form(...),
    auth: AuthContext = Depends(require_auth)
) -> dict:
    """Enable or disable a webhook (admin/operator only)."""
    success = toggle_webhook(webhook_id, is_active)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found"
        )
    
    return {"status": "updated", "id": webhook_id, "is_active": is_active}


# ──────────────────────────────────────────────────────────────────────────────
# Export Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/export/findings", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def export_findings_endpoint(
    format: str = Query(..., pattern="^(json|csv|sarif|html|pdf)$"),
    limit: int = Query(1000, ge=1, le=10000),
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    scan_id: int | None = None,
    include_analytics: bool = Query(False),
    auth: AuthContext = Depends(require_auth)
) -> Response:
    """
    Export findings in multiple formats.
    Supported formats: json, csv, sarif, html, pdf
    """
    # Fetch findings
    findings = list_findings(
        DB_PATH,
        limit=limit,
        severity=severity,
        tool=tool,
        target=target,
        scan_id=scan_id
    )
    
    # Get scan info if scan_id provided
    scan_info = {}
    if scan_id:
        scans = list_scans(DB_PATH, limit=1)
        for scan in scans:
            if scan.get("id") == str(scan_id):
                scan_info = scan
                break
    
    # Export based on format
    if format == "json":
        content = export_to_json(findings)
        media_type = "application/json"
        filename = f"findings_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    
    elif format == "csv":
        content = export_to_csv(findings)
        media_type = "text/csv"
        filename = f"findings_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    
    elif format == "sarif":
        content = export_to_sarif(findings)
        media_type = "application/json"
        filename = f"findings_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.sarif"
    
    elif format == "html":
        content = export_to_html(findings, scan_info)
        media_type = "text/html"
        filename = f"findings_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
    
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
        filename = f"findings_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid format"
        )
    
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ──────────────────────────────────────────────────────────────────────────────
# Advanced Analytics Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/analytics/risk-distribution", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_risk_distribution(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get risk score distribution across all findings."""
    return get_risk_distribution(DB_PATH)


@app.get("/api/analytics/compliance", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_compliance(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get OWASP Top 10 and CWE compliance mapping."""
    return get_compliance_summary(DB_PATH)


@app.get("/api/analytics/trends", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_trends(
    days: int = Query(90, ge=7, le=365),
    auth: AuthContext = Depends(require_auth)
) -> dict:
    """Get detailed trend analysis with risk scoring over time."""
    return get_trend_analysis(DB_PATH, days=days)


@app.get("/api/analytics/target-risk", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_target_risk(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """Get targets ranked by aggregated risk score."""
    return get_target_risk_ranking(DB_PATH)


@app.get("/api/analytics/tool-effectiveness", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_tool_effectiveness(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """Analyze tool effectiveness by findings and risk detection."""
    return get_tool_effectiveness(DB_PATH)


@app.get("/api/analytics/finding-risk/{finding_id}", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
def analytics_finding_risk(
    finding_id: int,
    auth: AuthContext = Depends(require_auth)
) -> dict:
    """Calculate risk score for a specific finding."""
    findings = list_findings(DB_PATH, limit=1, scan_id=None)
    
    # Find specific finding
    with get_connection(DB_PATH) as conn:
        finding = conn.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,)
        ).fetchone()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )
    
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
