"""
Unit tests for CSRF middleware.
"""

import json
import sys
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
sys.path.insert(0, str(root.parent))

from csrf import CSRFMiddleware


async def _dummy_app(scope, receive, send):
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": b'{"status":"ok"}'})


async def _call_middleware(method="GET", path="/protected", headers=None, session=None):
    app = CSRFMiddleware(_dummy_app, exempt_paths={"/login", "/health"})
    raw_headers = []
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode(), value.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": raw_headers,
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "session": session or {},
    }

    started = {}
    body = bytearray()

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            started["status"] = message["status"]
            started["headers"] = message.get("headers", [])
        elif message["type"] == "http.response.body":
            body.extend(message.get("body", b""))

    await app(scope, receive, send)
    payload = json.loads(body.decode() or "{}")
    return started["status"], payload, scope


@pytest.mark.asyncio
class TestCSRFMiddleware:
    async def test_get_requests_pass_without_token(self):
        status, payload, _scope = await _call_middleware(method="GET")
        assert status == 200
        assert payload["status"] == "ok"

    async def test_post_without_csrf_token_rejected(self):
        status, payload, _scope = await _call_middleware(method="POST")
        assert status == 403
        assert "CSRF" in payload["detail"]

    async def test_post_with_valid_csrf_token_accepted(self):
        status, payload, _scope = await _call_middleware(
            method="POST",
            headers={"x-csrf-token": "valid-token"},
            session={"csrf_token": "valid-token"},
        )
        assert status == 200
        assert payload["status"] == "ok"

    async def test_post_with_invalid_csrf_token_rejected(self):
        status, payload, _scope = await _call_middleware(
            method="POST",
            headers={"x-csrf-token": "wrong-token"},
            session={"csrf_token": "valid-token"},
        )
        assert status == 403
        assert "CSRF" in payload["detail"]

    async def test_exempt_path_allows_post_without_token(self):
        status, payload, _scope = await _call_middleware(method="POST", path="/login")
        assert status == 200
        assert payload["status"] == "ok"

    async def test_delete_requires_csrf_token(self):
        status, payload, _scope = await _call_middleware(method="DELETE")
        assert status == 403
        assert "CSRF" in payload["detail"]

    async def test_delete_with_valid_csrf_succeeds(self):
        status, payload, _scope = await _call_middleware(
            method="DELETE",
            headers={"x-csrf-token": "valid-token"},
            session={"csrf_token": "valid-token"},
        )
        assert status == 200
        assert payload["status"] == "ok"

    async def test_bearer_auth_bypasses_csrf_and_caches_key_info(self, monkeypatch):
        import rbac

        monkeypatch.setattr(
            rbac,
            "verify_api_key",
            lambda key: {"id": 1, "role": "admin", "key_prefix": "ssp_test"} if key == "valid-key" else None,
        )
        status, payload, scope = await _call_middleware(
            method="POST",
            headers={"authorization": "Bearer valid-key"},
        )
        assert status == 200
        assert payload["status"] == "ok"
        assert scope["auth_api_key_info"]["key_prefix"] == "ssp_test"

    async def test_bearer_auth_invalid_key_requires_csrf(self, monkeypatch):
        import rbac

        monkeypatch.setattr(rbac, "verify_api_key", lambda key: None)
        status, payload, _scope = await _call_middleware(
            method="POST",
            headers={"authorization": "Bearer invalid-key"},
        )
        assert status == 403
        assert "CSRF" in payload["detail"]
