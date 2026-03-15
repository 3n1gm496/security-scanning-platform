"""Authentication routes: login, logout, CSRF token."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from starlette import status

from routers._shared import templates

router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# These module-level references are wired by app.py before the router is
# included, via ``init()``.  They mirror the values defined in app.py.
# ---------------------------------------------------------------------------
USERNAME: str = ""
PASSWORD_RAW: str = ""
_verify_password = None  # type: ignore[assignment]


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
def login_page(request: Request, error: str | None = None) -> HTMLResponse:
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
    if not (username_ok and password_ok):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid credentials"},
            status_code=401,
        )
    # Regenerate session to prevent session fixation attacks
    request.session.clear()
    request.session["user"] = username
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/"})


@router.get("/logout")
def logout(request: Request) -> HTMLResponse:
    request.session.clear()
    return HTMLResponse(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})


@router.get("/api/csrf-token")
def csrf_token(request: Request):
    """Return the CSRF token for the current session."""
    token = request.session.get("csrf_token", "")
    return {"csrf_token": token}
