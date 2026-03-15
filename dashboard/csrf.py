"""
CSRF protection middleware for FastAPI.

Validates that mutating requests (POST, PUT, PATCH, DELETE) carry a valid
``X-CSRF-Token`` header that matches the token stored in the user's session.
This provides defence-in-depth on top of SameSite=Lax cookies.

Exempted paths (e.g. ``/login``, ``/api/health``) can be configured at init.

Usage::

    from csrf import CSRFMiddleware
    app.add_middleware(CSRFMiddleware, exempt_paths={"/login", "/api/health"})
"""

from __future__ import annotations

import secrets
from typing import Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths that are exempt from CSRF validation.  Typically login (needs to
# POST without a token the very first time) and health/readiness probes.
_DEFAULT_EXEMPT: Set[str] = frozenset(
    {
        "/login",
        "/api/health",
        "/api/ready",
        "/api/metrics",
        "/metrics",
    }
)


def _get_or_create_csrf_token(request: Request) -> str:
    """Return the CSRF token from the session, creating one if absent."""
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


class CSRFMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that enforces CSRF token on mutating requests."""

    def __init__(self, app, exempt_paths: Set[str] | None = None):
        super().__init__(app)
        self.exempt_paths: Set[str] = set(exempt_paths) if exempt_paths else set(_DEFAULT_EXEMPT)

    async def dispatch(self, request: Request, call_next):
        # Always ensure a CSRF token exists in the session so GET /api/csrf-token works.
        _get_or_create_csrf_token(request)

        if request.method in _MUTATING_METHODS:
            path = request.url.path

            # Skip exempt paths
            if path not in self.exempt_paths:
                # API-key-authenticated requests are exempt from CSRF (no browser session).
                # However, we must verify the key is valid — a bare "Bearer" header
                # with an invalid/empty token must NOT bypass CSRF protection.
                auth_header = request.headers.get("authorization", "")
                bearer_valid = False
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:].strip()
                    if token:
                        try:
                            from rbac import verify_api_key
                            bearer_valid = verify_api_key(token) is not None
                        except Exception:
                            bearer_valid = False
                if not bearer_valid:
                    expected = request.session.get("csrf_token", "")
                    provided = request.headers.get("x-csrf-token", "")
                    if not expected or not secrets.compare_digest(expected, provided):
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "CSRF token missing or invalid"},
                        )

        response = await call_next(request)
        return response
