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

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths that are exempt from CSRF validation. Typically login (needs to
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


class CSRFMiddleware:
    """ASGI middleware that enforces CSRF token on mutating requests.

    Implemented as plain ASGI instead of BaseHTTPMiddleware to avoid
    request/response deadlocks when stacked with other HTTP middlewares.
    """

    def __init__(self, app, exempt_paths: Set[str] | None = None):
        self.app = app
        self.exempt_paths: Set[str] = set(exempt_paths) if exempt_paths else set(_DEFAULT_EXEMPT)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        if request.method in _MUTATING_METHODS and request.url.path not in self.exempt_paths:
            headers = Headers(scope=scope)
            auth_header = headers.get("authorization", "")
            bearer_valid = False
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
                if token:
                    try:
                        from rbac import verify_api_key

                        key_info = verify_api_key(token)
                        bearer_valid = key_info is not None
                        if bearer_valid:
                            scope["auth_api_key_info"] = key_info
                    except Exception:
                        bearer_valid = False

            if not bearer_valid:
                session = scope.get("session") or {}
                expected = session.get("csrf_token", "") or request.cookies.get("csrf_token", "")
                provided = headers.get("x-csrf-token", "")
                if not expected or not secrets.compare_digest(expected, provided):
                    response = JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF token missing or invalid"},
                    )
                    await response(scope, receive, send)
                    return

        await self.app(scope, receive, send)
