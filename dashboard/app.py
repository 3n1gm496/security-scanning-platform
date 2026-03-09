from __future__ import annotations

import os
import secrets
import time
import csv
import io
import subprocess
import json
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock, Thread
from datetime import datetime, timezone

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
    get_connection,
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
from remediation import RemediationEngine, enrich_finding_with_remediation
from finding_management import (
    init_finding_management_tables,
    FindingStatus,
    update_finding_status,
    assign_finding,
    mark_false_positive,
    accept_risk,
    add_finding_comment,
    get_finding_comments,
    bulk_update_status,
    get_findings_by_status,
    get_finding_stats_by_status,
    get_finding_state,
)
from pagination import FindingsPaginator, ScansPaginator
from charting import ChartingEngine
from notifications import EmailNotificationEngine, NotificationPreferencesManager
from metrics import get_metrics

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
init_finding_management_tables()
default_key = create_default_admin_key()
if default_key:
    print(f"\n{'=' * 80}")
    print(f"DEFAULT ADMIN API KEY: {default_key}")
    print("Store this key securely! It will not be shown again.")
    print(f"{'=' * 80}\n")

# Add monitoring endpoints
app.include_router(monitoring_router, prefix="/api")

_RATE_LIMIT_EXCLUDED_PATHS = {"/api/health", "/api/ready", "/api/metrics", "/metrics"}
_request_timestamps: dict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = Lock()

notification_engine = EmailNotificationEngine()


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
    search: str | None = None,
    user: str = Depends(get_current_user),
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
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Create a new API key (admin/operator only)."""
    try:
        role_enum = Role(role)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role: {role}")

    full_key, prefix = create_api_key(
        name=name, role=role_enum, expires_days=expires_days, created_by=auth.api_key_prefix or auth.user_id
    )

    return {
        "key": full_key,
        "prefix": prefix,
        "role": role,
        "name": name,
        "warning": "Store this key securely! It will not be shown again.",
    }


@app.delete("/api/keys/{key_prefix}", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def delete_api_key(key_prefix: str, auth: AuthContext = Depends(require_auth)) -> dict:
    """Revoke an API key (admin/operator only)."""
    success = revoke_api_key(key_prefix)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

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
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Create a new webhook (admin/operator only)."""
    # Parse events
    event_list = []
    for event_str in events.split(","):
        event_str = event_str.strip()
        try:
            event_list.append(WebhookEvent(event_str))
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid event type: {event_str}")

    webhook_id = create_webhook(name, url, event_list, secret)

    return {"id": webhook_id, "name": name, "url": url, "events": events}


@app.delete("/api/webhooks/{webhook_id}", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def delete_webhook_endpoint(webhook_id: int, auth: AuthContext = Depends(require_auth)) -> dict:
    """Delete a webhook (admin/operator only)."""
    success = delete_webhook(webhook_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    return {"status": "deleted", "id": webhook_id}


@app.patch("/api/webhooks/{webhook_id}", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def toggle_webhook_endpoint(
    webhook_id: int, is_active: bool = Form(...), auth: AuthContext = Depends(require_auth)
) -> dict:
    """Enable or disable a webhook (admin/operator only)."""
    success = toggle_webhook(webhook_id, is_active)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

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
    auth: AuthContext = Depends(require_auth),
) -> Response:
    """
    Export findings in multiple formats.
    Supported formats: json, csv, sarif, html, pdf
    """
    # Fetch findings
    findings = list_findings(DB_PATH, limit=limit, severity=severity, tool=tool, target=target, scan_id=scan_id)

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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid format")

    return Response(
        content=content, media_type=media_type, headers={"Content-Disposition": f"attachment; filename={filename}"}
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
def analytics_trends(days: int = Query(90, ge=7, le=365), auth: AuthContext = Depends(require_auth)) -> dict:
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


@app.get(
    "/api/analytics/finding-risk/{finding_id}", dependencies=[Depends(require_permission(Permission.FINDING_READ))]
)
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


@app.get("/api/remediation/{finding_id}", dependencies=[Depends(require_permission(Permission.FINDING_READ))])
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


# ──────────────────────────────────────────────────────────────────────────────
# Scan Trigger Endpoints
# ──────────────────────────────────────────────────────────────────────────────


def run_scan_async(target_type: str, target: str, name: str, root_dir: str) -> dict:
    """Execute orchestrator scan and save results to database."""
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{root_dir}:{env.get('PYTHONPATH', '')}"
        env["ORCH_DB_PATH"] = f"{root_dir}/data/security_scans.db"
        env["REPORTS_DIR"] = f"{root_dir}/data/reports"
        env["WORKSPACE_DIR"] = f"{root_dir}/data/workspaces"
        env["ORCH_CACHE_DIR"] = f"{root_dir}/data/cache"
        env["DASHBOARD_DB_PATH"] = f"{root_dir}/data/security_scans.db"

        # Build orchestrator command
        cmd = [
            "python3",
            "-m",
            "orchestrator.main",
            "--target-type",
            target_type,
            "--target",
            target,
            "--target-name",
            name,
            "--settings",
            f"{root_dir}/config/settings.yaml",
        ]

        result = subprocess.run(cmd, cwd=root_dir, capture_output=True, text=True, env=env, timeout=300)

        # Parse JSON output
        try:
            output_json = json.loads(result.stdout)
            return {"status": "completed", "output": output_json, "returncode": result.returncode}
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "Failed to parse orchestrator output",
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out after 5 minutes"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/scan/trigger", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
def trigger_scan(
    target_type: str = Form(...),
    target: str = Form(...),
    name: str = Form(...),
    async_mode: bool = Form(False),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Trigger a new security scan (admin/operator only).

    Args:
        target_type: 'local', 'git', or 'image'
        target: path, URL, or image reference
        name: display name for the target
        async_mode: if true, return immediately with job_id; if false, wait for completion
    """
    # Validate inputs
    if target_type not in ["local", "git", "image"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_type must be 'local', 'git', or 'image'",
        )

    if not target or not name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target and name are required")

    root_dir = Path(__file__).parent.parent.absolute()

    if async_mode:
        # Launch scan in background and return immediately
        thread = Thread(target=run_scan_async, args=(target_type, target, name, str(root_dir)), daemon=True)
        thread.start()
        return {"status": "queued", "message": "Scan queued and running in background", "target_name": name}
    else:
        # Wait for scan to complete
        result = run_


# ──────────────────────────────────────────────────────────────────────────────
# Finding Management Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/findings/stats-by-status")
def api_finding_stats_by_status(user: str = Depends(get_current_user)) -> dict:
    """Get finding statistics grouped by status."""
    return get_finding_stats_by_status()


@app.get("/api/findings/by-status")
def api_findings_by_status(
    status: str | None = None,
    limit: int = Query(100, le=1000),
    user: str = Depends(get_current_user),
) -> list[dict]:
    """Get findings filtered by management status."""
    return get_findings_by_status(status, limit)


@app.get("/api/findings/{finding_id}/state")
def api_get_finding_state(finding_id: int, user: str = Depends(get_current_user)) -> dict:
    """Get finding management state."""
    state = get_finding_state(finding_id)
    if not state:
        return {"finding_id": finding_id, "status": "new", "assigned_to": None}
    return state


@app.patch(
    "/api/findings/{finding_id}/status",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_update_finding_status(
    finding_id: int,
    status: str = Form(...),
    notes: str | None = Form(None),
    assigned_to: str | None = Form(None),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Update finding status."""
    try:
        finding_status = FindingStatus(status)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid status: {status}")

    result = update_finding_status(
        finding_id,
        finding_status,
        user=auth.api_key_prefix or "unknown",
        notes=notes,
        assigned_to=assigned_to,
    )

    return result


@app.post(
    "/api/findings/{finding_id}/assign",
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


@app.post(
    "/api/findings/{finding_id}/false-positive",
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


@app.post(
    "/api/findings/{finding_id}/accept-risk",
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


@app.post(
    "/api/findings/{finding_id}/comment",
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


@app.get("/api/findings/{finding_id}/comments")
def api_get_finding_comments(finding_id: int, user: str = Depends(get_current_user)) -> list[dict]:
    """Get all comments for a finding."""
    return get_finding_comments(finding_id)


@app.post(
    "/api/findings/bulk/update-status",
    dependencies=[Depends(require_permission(Permission.FINDING_WRITE))],
)
def api_bulk_update_status(
    finding_ids: list[int],
    status: str,
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Bulk update status for multiple findings."""
    try:
        finding_status = FindingStatus(status)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid status: {status}")

    result = bulk_update_status(finding_ids, finding_status, user=auth.api_key_prefix or "unknown")
    return result


# ──────────────────────────────────────────────────────────────────────────────
# CI/CD Integration Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/badge/{target_name}.svg")
def generate_badge(target_name: str) -> Response:
    """Generate SVG badge for scan status."""
    # Get latest scan for target
    with get_connection(DB_PATH) as conn:
        scan = conn.execute(
            "SELECT status, policy_status, findings_count, critical_count, high_count FROM scans WHERE target_name = ? ORDER BY created_at DESC LIMIT 1",
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
    <text x="{60 + message_width//2}" y="15" fill="#010101" fill-opacity=".3">{message}</text>
    <text x="{60 + message_width//2}" y="14">{message}</text>
  </g>
</svg>"""
    
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/api/scans/compare")
def compare_scans(
    scan_id_1: str,
    scan_id_2: str,
    user: str = Depends(get_current_user),
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




# Pagination endpoints
@app.get("/api/findings/paginated")
def paginate_findings(
    search: str = Query(""),
    severity: str = Query(""),
    tool: str = Query(""),
    scan_id: int | None = Query(None),
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
    - scan_id: Filter by specific scan ID
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
            cursor=cursor,
            sort_by=sort_by,
            sort_order=sort_order,
        )


@app.get("/api/scans/paginated")
def paginate_scans(
    target: str = Query(""),
    status: str = Query(""),
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
            cursor=cursor,
            sort_by=sort_by,
            sort_order=sort_order,
        )


# Charting endpoints
@app.get("/api/chart/severity-distribution")
def chart_severity_distribution(
    days: int = Query(30, ge=1, le=365),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get findings severity distribution over time for stacked bar chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.severity_distribution(conn, days=days)


@app.get("/api/chart/tool-effectiveness")
def chart_tool_effectiveness(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get findings count by tool for bar chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.tool_effectiveness(conn)


@app.get("/api/chart/target-risk-heatmap")
def chart_target_risk(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get risk scores by target for heatmap visualization."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.target_risk_heatmap(conn)


@app.get("/api/chart/scan-trend")
def chart_scan_trend(
    days: int = Query(90, ge=7, le=365),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Get scan completion trend over time for line chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.scan_status_trend(conn, days=days)


@app.get("/api/chart/remediation-progress")
def chart_remediation_progress(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get findings remediation progress for pie chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.remediation_progress(conn)


@app.get("/api/chart/cve-distribution")
def chart_cve_distribution(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get top CVEs found for bar chart."""
    with get_connection(DB_PATH) as conn:
        return ChartingEngine.cve_distribution(conn)


@app.post("/api/notifications/send-alert")
def send_notification_alert(
    to_email: str = Form(...),
    finding_id: int = Form(...),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Send critical finding notification email."""
    with get_connection(DB_PATH) as conn:
        finding = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        sent = notification_engine.send_critical_finding_alert(to_email=to_email, finding=dict(finding))
        if not sent:
            raise HTTPException(status_code=502, detail="Failed to send email")

    return {"status": "sent", "to": to_email, "finding_id": finding_id}


@app.post("/api/notifications/preferences")
def save_notification_preferences(
    preferences: dict,
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Save notification preferences for the authenticated user."""
    user_identifier = auth.user_id or auth.api_key_prefix or "unknown"
    with get_connection(DB_PATH) as conn:
        saved = NotificationPreferencesManager.save_preferences(conn, user_identifier, preferences)
        if not saved:
            raise HTTPException(status_code=500, detail="Failed to save preferences")
    return {"status": "saved", "user": user_identifier}


@app.get("/api/notifications/preferences")
def get_notification_preferences(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get notification preferences for the authenticated user."""
    user_identifier = auth.user_id or auth.api_key_prefix or "unknown"
    with get_connection(DB_PATH) as conn:
        prefs = NotificationPreferencesManager.get_preferences(conn, user_identifier)
    return {"preferences": prefs or {}}


@app.get("/metrics")
def prometheus_metrics(auth: AuthContext = Depends(require_auth)) -> Response:
    """Expose Prometheus metrics in text format."""
    metrics = get_metrics()
    with get_connection(DB_PATH) as conn:
        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) AS total FROM findings GROUP BY severity"
        ).fetchall()
        for row in severity_rows:
            metrics.set_findings_count(row["severity"] or "UNKNOWN", int(row["total"]))

        queue_size = conn.execute(
            "SELECT COUNT(*) AS total FROM scans WHERE UPPER(status) = 'RUNNING'"
        ).fetchone()
        metrics.set_queue_size(int(queue_size["total"]) if queue_size else 0)

    return Response(content=metrics.generate_text(), media_type="text/plain; version=0.0.4")
