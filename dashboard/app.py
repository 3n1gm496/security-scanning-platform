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
