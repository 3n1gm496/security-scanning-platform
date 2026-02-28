from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from db import (
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

app = FastAPI(title=APP_TITLE)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# Add monitoring endpoints
app.include_router(monitoring_router, prefix="/api")

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
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    # confronta in modo sicuro con le credenziali memorizzate
    if not (secrets.compare_digest(username or "", USERNAME) and secrets.compare_digest(password or "", PASSWORD)):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Credenziali non valide"},
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
        "request": request,
        "user": user,
        "kpis": fetch_kpis(DB_PATH),
        "severity_breakdown": severity_breakdown(DB_PATH),
        "tool_breakdown": tool_breakdown(DB_PATH),
        "target_breakdown": target_breakdown(DB_PATH),
        "trend": scans_trend(DB_PATH, 14),
        "recent_scans": recent_failed_scans(DB_PATH, 10),
    }
    return templates.TemplateResponse("index.html", context)


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
        "scans.html",
        {
            "request": request,
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
        "findings.html",
        {
            "request": request,
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
