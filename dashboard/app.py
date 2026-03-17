from __future__ import annotations

import asyncio
import base64
import csv
import io
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from logging_config import configure_logging, get_logger

configure_logging()
LOGGER = get_logger(__name__)

import bcrypt
from auth import AuthContext, require_auth, require_permission
from csrf import CSRFMiddleware
from db import (
    cache_hit_stats,
    cache_hit_trend,
    distinct_targets,
    distinct_tools,
    fetch_kpis,
    get_connection,
    list_scans,
    scans_trend,
    severity_breakdown,
    target_breakdown,
    tool_breakdown,
)
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from finding_management import init_finding_management_tables
from monitoring import router as monitoring_router
from rate_limit import (
    LOGIN_RATE_LIMIT_REQUESTS,
    LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    is_rate_limited,
    start_cleanup_timer,
)
from runtime_config import DASHBOARD_DB_PATH
from rbac import Permission, create_default_admin_key, init_rbac_tables
from routers import analytics_router, api_keys_router, audit_router, auth_router
from routers import auth_routes as _auth_routes_module
from routers import export_router, finding_router, notification_router, scan_router, webhook_router
from routers._shared import _ttl_cache  # noqa: F401 — re-exported for tests
from routers._shared import cached as _cached  # noqa: F401 — re-exported for tests
from routers._shared import scan_executor as _scan_executor  # noqa: F401 — re-exported for tests
from starlette.datastructures import MutableHeaders
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from webhooks import init_webhook_tables

# ──────────────────────────────────────────────────────────────────────────────
# Router imports
# ──────────────────────────────────────────────────────────────────────────────


APP_TITLE = "Security Scanning Dashboard"
DB_PATH = DASHBOARD_DB_PATH
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
# Comma-separated list of allowed CORS origins. Empty = same-origin only (no CORS headers).
CORS_ORIGINS = [o.strip() for o in os.getenv("DASHBOARD_CORS_ORIGINS", "").split(",") if o.strip()]
# Scans stuck in RUNNING for longer than this (seconds) are marked FAILED.
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))  # 1 hour
# How often the watchdog checks for stale scans (seconds).
SCAN_WATCHDOG_INTERVAL_SECONDS = int(os.getenv("SCAN_WATCHDOG_INTERVAL_SECONDS", "120"))  # 2 min
# Set to '1' or 'true' when the dashboard is behind a trusted reverse proxy (e.g. nginx).
# Only then will the X-Forwarded-For header be used for rate limiting.
TRUST_PROXY = os.getenv("DASHBOARD_TRUST_PROXY", "0").strip().lower() in ("1", "true", "yes")
DISABLE_LIFESPAN = os.getenv("DASHBOARD_DISABLE_LIFESPAN", "0").strip().lower() in ("1", "true", "yes")
# Vue runtime template compilation needs eval/new Function in-browser.
# Keep this enabled by default for compatibility; set to 0 only after
# migrating to precompiled templates.
ALLOW_UNSAFE_EVAL = os.getenv("DASHBOARD_CSP_ALLOW_UNSAFE_EVAL", "0").strip().lower() in ("1", "true", "yes")


async def _scan_timeout_watchdog():
    """Background loop that marks RUNNING scans older than SCAN_TIMEOUT_SECONDS as FAILED."""
    while True:
        await asyncio.sleep(SCAN_WATCHDOG_INTERVAL_SECONDS)
        try:
            cutoff = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=SCAN_TIMEOUT_SECONDS)
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
    # Store the running event loop so worker threads can schedule SSE events.
    from scan_events import set_loop as _set_sse_loop

    _set_sse_loop(asyncio.get_running_loop())

    watchdog_task = asyncio.create_task(_scan_timeout_watchdog())
    yield
    watchdog_task.cancel()
    # Graceful shutdown: wait for running scans to complete.
    from routers._shared import scan_executor as _scan_exec

    LOGGER.info("app.shutdown", detail="Waiting for running scans to finish...")
    _scan_exec.shutdown(wait=True, cancel_futures=False)


app = FastAPI(title=APP_TITLE, lifespan=None if DISABLE_LIFESPAN else _lifespan)
app.add_middleware(
    CSRFMiddleware,
    exempt_paths={"/login", "/api/health", "/api/ready", "/api/metrics", "/metrics", "/api/scans/events"},
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=HTTPS_ONLY,
    same_site="lax",
    max_age=SESSION_MAX_AGE,
)
if CORS_ORIGINS:
    _cors_allow_creds = "*" not in CORS_ORIGINS
    if not _cors_allow_creds:
        LOGGER.warning(
            "security.cors_wildcard",
            detail="CORS origin '*' detected — disabling allow_credentials for safety.",
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=_cors_allow_creds,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["*"],
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
    """Return the client IP for rate limiting.

    Only trusts X-Forwarded-For when DASHBOARD_TRUST_PROXY is enabled.
    """
    if TRUST_PROXY:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


class SecurityMiddleware:
    """ASGI security middleware for rate limiting and response hardening."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        now = time.monotonic()
        client_id = _client_key(request)
        path = request.url.path

        if path == "/login" and request.method == "POST":
            if is_rate_limited("login", client_id, LOGIN_RATE_LIMIT_REQUESTS, LOGIN_RATE_LIMIT_WINDOW_SECONDS, now):
                response = JSONResponse(
                    status_code=429,
                    content={"detail": "Too many login attempts. Please wait before retrying."},
                    headers={"Retry-After": str(LOGIN_RATE_LIMIT_WINDOW_SECONDS)},
                )
                await response(scope, receive, send)
                return

        if path.startswith("/api") and path not in _RATE_LIMIT_EXCLUDED_PATHS:
            if is_rate_limited("api", client_id, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS, now):
                response = JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Retry later."},
                    headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
                )
                await response(scope, receive, send)
                return

        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        scope.setdefault("state", {})["csp_nonce"] = nonce
        response_status = 500

        async def send_with_security_headers(message):
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Cache-Control"] = "no-store"
                script_src = [f"'nonce-{nonce}'", "'self'", "https://cdn.jsdelivr.net", "https://unpkg.com"]
                if ALLOW_UNSAFE_EVAL:
                    script_src.insert(1, "'unsafe-eval'")
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    f"script-src {' '.join(script_src)}; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "font-src 'self'; "
                    "connect-src 'self' https://cdn.jsdelivr.net; "
                    "frame-ancestors 'none';"
                )
                if scope.get("scheme") == "https":
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                headers["Permissions-Policy"] = (
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
                )
            await send(message)

        try:
            await self.app(scope, receive, send_with_security_headers)
        finally:
            try:
                from monitoring import record_api_request_metric

                record_api_request_metric(request.method, path, response_status)
            except Exception:
                pass


app.add_middleware(SecurityMiddleware)


templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


# ---------------------------------------------------------------------------
# Session-based authentication (login form)
# ---------------------------------------------------------------------------


async def get_current_user(request: Request) -> str:
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
async def index(request: Request, user: str = Depends(get_current_user)) -> HTMLResponse:
    context = {
        "user": user,
        "user_role": request.session.get("role", "admin"),
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
async def scans_page(request: Request, user: str = Depends(get_current_user)) -> HTMLResponse:
    """Deprecated SSR route — redirect to SPA."""
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/#scans"})


@app.get("/findings")
async def findings_page(request: Request, user: str = Depends(get_current_user)) -> HTMLResponse:
    """Deprecated SSR route — redirect to SPA."""
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/#findings"})


# ---------------------------------------------------------------------------
# Simple API routes kept in app.py
# ---------------------------------------------------------------------------


@app.get("/api/kpi")
async def api_kpi(auth: AuthContext = Depends(require_auth)) -> dict:
    return fetch_kpis(DB_PATH)


@app.get("/api/trends")
async def api_trends(days: int = 30, auth: AuthContext = Depends(require_auth)) -> list[dict]:
    return scans_trend(DB_PATH, days)


@app.get("/api/cache-hits")
async def api_cache_hits(auth: AuthContext = Depends(require_auth)) -> dict:
    return cache_hit_stats(DB_PATH)


@app.get("/api/cache-hit-trend")
async def api_cache_hit_trend(days: int = 14, auth: AuthContext = Depends(require_auth)) -> list[dict]:
    return cache_hit_trend(DB_PATH, days)


@app.get("/api/cache-hit-trend.csv")
async def api_cache_hit_trend_csv(days: int = 14, auth: AuthContext = Depends(require_auth)) -> Response:
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


@app.get("/api/users", dependencies=[Depends(require_permission(Permission.FINDING_WRITE))])
async def list_users() -> dict:
    """Return the list of active users (username only) for the assignment datalist."""
    with get_connection(DB_PATH) as conn:
        rows = conn.execute("SELECT username FROM users WHERE is_active = 1 ORDER BY username").fetchall()
    return {"users": [{"username": r["username"]} for r in rows]}


@app.get("/metrics")
async def prometheus_metrics(auth: AuthContext = Depends(require_auth)) -> Response:
    """Expose the authenticated Prometheus metrics scrape endpoint."""
    from monitoring import prometheus_metrics as scrape_metrics

    return await scrape_metrics()
