"""Authentication routes: login, logout, CSRF token."""

from __future__ import annotations

import os
import secrets

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette import status

from rbac import Role, verify_user_credentials
from routers._shared import templates

router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# These module-level references are wired by app.py before the router is
# included, via ``init()``.  They mirror the values defined in app.py.
# ---------------------------------------------------------------------------
USERNAME: str = ""
PASSWORD_RAW: str = ""
_verify_password = None  # type: ignore[assignment]
_HTTPS_ONLY = os.getenv("DASHBOARD_HTTPS_ONLY", "0").strip().lower() in ("1", "true", "yes")


def init(*, username: str, password_raw: str, verify_password):
    """Called once from app.py to inject auth configuration."""
    global USERNAME, PASSWORD_RAW, _verify_password
    USERNAME = username
    PASSWORD_RAW = password_raw
    _verify_password = verify_password


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    """Show the login form. If already authenticated, redirect to the overview."""
    if request.session.get("user"):
        return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/"})
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    # Verify username with timing-safe comparison, then verify password.
    # _verify_password supports both bcrypt hashes and legacy plain-text.
    username_ok = secrets.compare_digest(username or "", USERNAME)
    password_ok = _verify_password(password or "", PASSWORD_RAW)
    db_user = None
    if not (username_ok and password_ok):
        db_user = verify_user_credentials(username or "", password or "")
    if not (username_ok and password_ok) and not db_user:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid credentials"},
            status_code=401,
        )
    # Regenerate session to prevent session fixation attacks
    request.session.clear()
    csrf_token = os.getenv("DASHBOARD_TEST_CSRF_TOKEN") or secrets.token_urlsafe(32)
    if db_user:
        request.session["user"] = db_user["username"]
        request.session["role"] = db_user["role"]
    else:
        request.session["user"] = username
        request.session["role"] = os.getenv("DASHBOARD_SESSION_ROLE", Role.ADMIN.value).strip().lower() or Role.ADMIN.value
    request.session["csrf_token"] = csrf_token
    response = HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/"})
    response.set_cookie(
        "csrf_token",
        csrf_token,
        httponly=False,
        samesite="lax",
        secure=_HTTPS_ONLY,
    )
    return response


@router.post("/logout")
async def logout(request: Request) -> HTMLResponse:
    request.session.clear()
    response = HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    response.delete_cookie("csrf_token")
    return response


@router.get("/logout")
async def logout_get(request: Request) -> HTMLResponse:
    """Reject logout via GET to avoid CSRF-via-GET side effects."""
    raise HTTPException(status_code=status.HTTP_405_METHOD_NOT_ALLOWED, detail="Use POST /logout")


@router.get("/api/csrf-token")
async def csrf_token(request: Request):
    """Return the CSRF token for the current session."""
    token = request.cookies.get("csrf_token", "")
    return {"csrf_token": token}
