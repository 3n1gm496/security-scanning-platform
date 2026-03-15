from __future__ import annotations

import asyncio
import base64
import os
import secrets
import time
import csv
import io
import json
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timedelta, timezone

from logging_config import configure_logging, get_logger

configure_logging()
LOGGER = get_logger(__name__)

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from csrf import CSRFMiddleware

from db import (
    cache_hit_stats,
    cache_hit_trend,
    distinct_targets,
    distinct_tools,
    fetch_kpis,
    list_scans,
    scans_trend,
    severity_breakdown,
    target_breakdown,
    tool_breakdown,
    get_connection,
)
from monitoring import router as monitoring_router
from rate_limit import (
    is_rate_limited,
    start_cleanup_timer,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    LOGIN_RATE_LIMIT_REQUESTS,
    LOGIN_RATE_LIMIT_WINDOW_SECONDS,
)
from rbac import (
    init_rbac_tables,
    create_default_admin_key,
)
from auth import require_auth, AuthContext
from webhooks import init_webhook_tables
from finding_management import init_finding_management_tables
from metrics import get_metrics

import bcrypt

# ──────────────────────────────────────────────────────────────────────────────
# Router imports
# ──────────────────────────────────────────────────────────────────────────────

from routers import (
    auth_router,
    api_keys_router,
    webhook_router,
    export_router,
    analytics_router,
    scan_router,
    finding_router,
    notification_router,
    audit_router,
)
from routers import auth_routes as _auth_routes_module
from routers._shared import scan_executor as _scan_executor  # noqa: F401 — re-exported for tests
from routers._shared import cached as _cached  # noqa: F401 — re-exported for tests
from routers._shared import _ttl_cache  # noqa: F401 — re-exported for tests

APP_TITLE = "Security Scanning Dashboard"
DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")
USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
# DASHBOARD_PASSWORD accepts either a plain-text password (legacy, not recommended)
# or a bcrypt hash (recommended). To generate a hash:
#   python -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
# A value starting with '$2b$' or '$2a$' is treated as a bcrypt hash.
PASSWORD_RAW = os.getenv("DASHBOARD_PASSWORD", "change-me")
SESSION_SECRET = os.getenv("DASHBOARD_SESSION_SECRET", "please-change-this")


def _is_bcrypt_hash(value: str) -> bool:
    """Return True if the value looks like a bcrypt hash."""
    return value.startswith(("$2b$", "$2a$", "$2y$"))


def _verify_password(plain: str, stored: str) -> bool:
    """Verify a password against the stored credential.

    If *stored* is a bcrypt hash the comparison is done via bcrypt.checkpw.
    Otherwise a timing-safe string comparison is used (legacy plain-text mode).
    A startup warning is emitted when plain-text mode is active.
    """
    if _is_bcrypt_hash(stored):
        try:
            return bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    # Legacy plain-text mode — warn once at module load
    return secrets.compare_digest(plain, stored)


# Set to '1' or 'true' when the dashboard is served over HTTPS (recommended in production).
# Enables the Secure flag on session cookies and enforces https_only in SessionMiddleware.
HTTPS_ONLY = os.getenv("DASHBOARD_HTTPS_ONLY", "0").strip().lower() in ("1", "true", "yes")
SESSION_MAX_AGE = int(os.getenv("DASHBOARD_SESSION_MAX_AGE", "86400"))  # 24 hours
# Scans stuck in RUNNING for longer than this (seconds) are marked FAILED.
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))  # 1 hour
# How often the watchdog checks for stale scans (seconds).
SCAN_WATCHDOG_INTERVAL_SECONDS = int(os.getenv("SCAN_WATCHDOG_INTERVAL_SECONDS", "120"))  # 2 min


async def _scan_timeout_watchdog():
    """Background loop that marks RUNNING scans older than SCAN_TIMEOUT_SECONDS as FAILED."""
    while True:
        await asyncio.sleep(SCAN_WATCHDOG_INTERVAL_SECONDS)
        try:
            cutoff = datetime.now(timezone.utc).replace(microsecond=0) - \
                timedelta(seconds=SCAN_TIMEOUT_SECONDS)
            cutoff_iso = cutoff.isoformat()
            with get_connection(DB_PATH) as conn:
                stale = conn.execute(
                    "SELECT id FROM scans WHERE UPPER(status) = 'RUNNING' AND created_at < ?",
                    (cutoff_iso,),
                ).fetchall()
                if stale:
                    ids = [row["id"] for row in stale]
                    for sid in ids:
                        # Guard with AND status='RUNNING' to avoid overwriting
                        # a scan that completed between SELECT and UPDATE.
                        conn.execute(
                            "UPDATE scans SET status='FAILED', finished_at=?, error_message=? "
                            "WHERE id=? AND UPPER(status) = 'RUNNING'",
                            (
                                datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                                f"Scan timed out after {SCAN_TIMEOUT_SECONDS}s",
                                sid,
                            ),
                        )
                    LOGGER.warning("watchdog.stale_scans_failed", count=len(ids), scan_ids=ids)
        except Exception as exc:
            LOGGER.error("watchdog.error", error=str(exc))


@asynccontextmanager
async def _lifespan(app):
    watchdog_task = asyncio.create_task(_scan_timeout_watchdog())
    yield
    watchdog_task.cancel()
    # Graceful shutdown: wait for running scans to complete.
    from routers._shared import scan_executor as _scan_exec
    LOGGER.info("app.shutdown", detail="Waiting for running scans to finish...")
    _scan_exec.shutdown(wait=True, cancel_futures=False)


app = FastAPI(title=APP_TITLE, lifespan=_lifespan)
app.add_middleware(
    CSRFMiddleware,
    exempt_paths={"/login", "/api/health", "/api/ready", "/api/metrics", "/metrics"},
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=HTTPS_ONLY,
    same_site="lax",
    max_age=SESSION_MAX_AGE,
)

# ── Database initialisation (scans + findings) ───────────────────────────────
# The dashboard may start before the orchestrator has ever written to the DB.
# This block ensures the tables exist, preventing OperationalError on an empty
# database (e.g. first boot, dev environment, CI).
try:
    from db import init_db

    init_db(DB_PATH)
except Exception as _init_err:
    LOGGER.warning("db.init_warning", error=str(_init_err))

# Warn on insecure defaults — these must be overridden in production.
if not _is_bcrypt_hash(PASSWORD_RAW) and PASSWORD_RAW in ("change-me", ""):
    LOGGER.warning(
        "security.weak_password",
        detail="DASHBOARD_PASSWORD is set to an insecure default. Set a bcrypt hash via the env var.",
    )
if SESSION_SECRET in ("please-change-this", ""):
    LOGGER.warning(
        "security.weak_session_secret",
        detail="DASHBOARD_SESSION_SECRET is set to an insecure default. Set a strong random secret.",
    )

# Initialize RBAC tables
init_rbac_tables()
init_webhook_tables()
init_finding_management_tables()
default_key = create_default_admin_key()
if default_key:
    LOGGER.warning(
        "security.default_admin_key_created",
        detail="Store this key securely! It will not be shown again.",
        api_key_prefix=default_key[:12] + "...",
    )

# Add monitoring endpoints
app.include_router(monitoring_router, prefix="/api")

_RATE_LIMIT_EXCLUDED_PATHS = {"/api/health", "/api/ready", "/api/metrics", "/api/metrics/json", "/metrics"}

# Start the background rate-bucket eviction timer (defined in rate_limit.py)
start_cleanup_timer()

# ── Wire auth configuration into the auth_routes module ──────────────────
_auth_routes_module.init(
    username=USERNAME,
    password_raw=PASSWORD_RAW,
    verify_password=_verify_password,
)

# ── Include all routers ──────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(api_keys_router)
app.include_router(webhook_router)
app.include_router(export_router)
app.include_router(analytics_router)
app.include_router(scan_router)
app.include_router(finding_router)
app.include_router(notification_router)
app.include_router(audit_router)


def _client_key(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return "unknown"


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    now = time.monotonic()
    client_id = _client_key(request)
    path = request.url.path

    # Brute-force protection on the login endpoint
    if path == "/login" and request.method == "POST":
        if is_rate_limited("login", client_id, LOGIN_RATE_LIMIT_REQUESTS, LOGIN_RATE_LIMIT_WINDOW_SECONDS, now):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many login attempts. Please wait before retrying."},
                headers={"Retry-After": str(LOGIN_RATE_LIMIT_WINDOW_SECONDS)},
            )

    # General API rate limiting
    if path.startswith("/api") and path not in _RATE_LIMIT_EXCLUDED_PATHS:
        if is_rate_limited("api", client_id, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS, now):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Retry later."},
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

    # Generate a per-request CSP nonce to eliminate 'unsafe-inline' from script-src.
    nonce = base64.b64encode(secrets.token_bytes(16)).decode()
    request.state.csp_nonce = nonce

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    # Content-Security-Policy: nonce-based script-src replaces 'unsafe-inline'.
    # 'unsafe-eval' remains required for Vue.js 3 runtime template compilation.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none';"
    )
    # HSTS: only sent over HTTPS; max-age 1 year
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Permissions-Policy: disable browser features not needed by this app
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), " "interest-cohort=()"
    )
    return response


templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


# ---------------------------------------------------------------------------
# Session-based authentication (login form)
# ---------------------------------------------------------------------------


def get_current_user(request: Request) -> str:
    """Return the authenticated user.
    - For unauthenticated HTML pages: redirect to /login.
    - For API calls: return 401 Unauthorized.
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


# ---------------------------------------------------------------------------
# Page routes (kept in app.py)
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: str = Depends(get_current_user)) -> HTMLResponse:
    context = {
        "user": user,
        "csp_nonce": getattr(request.state, "csp_nonce", ""),
        "kpis": fetch_kpis(DB_PATH),
        "severity_breakdown": severity_breakdown(DB_PATH),
        "tool_breakdown": tool_breakdown(DB_PATH),
        "target_breakdown": target_breakdown(DB_PATH),
        "trend": scans_trend(DB_PATH, 14),
        "recent_scans": list_scans(DB_PATH, limit=12),
        "available_targets": distinct_targets(DB_PATH),
        "available_tools": distinct_tools(DB_PATH),
    }
    return templates.TemplateResponse(request, "app.html", context)


@app.get("/scans")
def scans_page(request: Request, user: str = Depends(get_current_user)) -> HTMLResponse:
    """Deprecated SSR route — redirect to SPA."""
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/#scans"})


@app.get("/findings")
def findings_page(request: Request, user: str = Depends(get_current_user)) -> HTMLResponse:
    """Deprecated SSR route — redirect to SPA."""
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/#findings"})


# ---------------------------------------------------------------------------
# Simple API routes kept in app.py
# ---------------------------------------------------------------------------


@app.get("/api/kpi")
def api_kpi(auth: AuthContext = Depends(require_auth)) -> dict:
    return fetch_kpis(DB_PATH)


@app.get("/api/trends")
def api_trends(days: int = 30, auth: AuthContext = Depends(require_auth)) -> list[dict]:
    return scans_trend(DB_PATH, days)


@app.get("/api/cache-hits")
def api_cache_hits(auth: AuthContext = Depends(require_auth)) -> dict:
    return cache_hit_stats(DB_PATH)


@app.get("/api/cache-hit-trend")
def api_cache_hit_trend(days: int = 14, auth: AuthContext = Depends(require_auth)) -> list[dict]:
    return cache_hit_trend(DB_PATH, days)


@app.get("/api/cache-hit-trend.csv")
def api_cache_hit_trend_csv(days: int = 14, auth: AuthContext = Depends(require_auth)) -> Response:
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


@app.get("/api/users", dependencies=[Depends(require_auth)])
def list_users() -> dict:
    """Return the list of active users (username only) for the assignment datalist."""
    with get_connection(DB_PATH) as conn:
        rows = conn.execute("SELECT username FROM users WHERE is_active = 1 ORDER BY username").fetchall()
    return {"users": [{"username": r["username"]} for r in rows]}


@app.get("/metrics")
def prometheus_metrics(auth: AuthContext = Depends(require_auth)) -> Response:
    """Expose Prometheus metrics in text format."""
    metrics = get_metrics()
    with get_connection(DB_PATH) as conn:
        severity_rows = conn.execute("SELECT severity, COUNT(*) AS total FROM findings GROUP BY severity").fetchall()
        for row in severity_rows:
            metrics.set_findings_count(row["severity"] or "UNKNOWN", int(row["total"]))

        queue_size = conn.execute("SELECT COUNT(*) AS total FROM scans WHERE UPPER(status) = 'RUNNING'").fetchone()
        metrics.set_queue_size(int(queue_size["total"]) if queue_size else 0)

    return Response(content=metrics.generate_text(), media_type="text/plain; version=0.0.4")
