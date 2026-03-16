"""Focused route-level safety regressions."""

from __future__ import annotations

import asyncio
import csv
import io
import sys
import types
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

if "bcrypt" not in sys.modules:
    fake_bcrypt = types.ModuleType("bcrypt")
    fake_bcrypt.gensalt = lambda: b"salt"
    fake_bcrypt.hashpw = lambda value, salt: b"$2b$stubbed-hash"
    fake_bcrypt.checkpw = lambda plain, hashed: True
    sys.modules["bcrypt"] = fake_bcrypt

from app import SecurityMiddleware
from fastapi import HTTPException
from routers import audit_routes, auth_routes
from routers.notification_routes import NotificationPreferencesPayload


def test_logout_get_rejected():
    """GET /logout must not perform logout side effects."""
    try:
        asyncio.run(auth_routes.logout_get(request=None))  # type: ignore[arg-type]
    except HTTPException as exc:
        assert exc.status_code == 405
    else:
        raise AssertionError("Expected HTTPException for GET logout")


def test_audit_csv_export_sanitizes_formula_values():
    """Audit CSV export should escape formula-leading values."""

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params):
            class FakeCursor:
                def fetchall(self_inner):
                    return [{"action": "=cmd", "resource": "@evil", "result": "ok"}]

            return FakeCursor()

    audit_routes.get_connection = lambda *_args, **_kwargs: FakeConn()  # type: ignore[assignment]
    response = asyncio.run(
        audit_routes.export_audit_log(
            format="csv",
            limit=10,
            action=None,
            auth=type("Auth", (), {"user_id": "u", "api_key_prefix": None})(),
        )
    )
    rows = list(csv.DictReader(io.StringIO(response.body.decode())))
    assert rows[0]["action"].startswith("'=cmd")
    assert rows[0]["resource"].startswith("'@evil")


def test_notification_preferences_payload_rejects_unknown_fields():
    """Preferences API should reject arbitrary JSON keys."""
    with pytest.raises(Exception):
        NotificationPreferencesPayload.model_validate({"notify_critical": True})


def test_notification_preferences_payload_accepts_expected_fields():
    payload = NotificationPreferencesPayload.model_validate(
        {
            "critical_alerts": True,
            "high_alerts": False,
            "scan_summaries": True,
            "weekly_digest": False,
            "preferred_channel": "email",
        }
    )
    assert payload.critical_alerts is True
    assert payload.high_alerts is False


def test_notification_preferences_payload_rejects_bad_channel():
    with pytest.raises(Exception):
        NotificationPreferencesPayload.model_validate({"preferred_channel": "slack"})


def test_security_middleware_csp_omits_unsafe_eval():
    async def _dummy_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = SecurityMiddleware(_dummy_app)
    messages = []
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    response_start = next(msg for msg in messages if msg["type"] == "http.response.start")
    headers = {k.decode().lower(): v.decode() for k, v in response_start["headers"]}
    csp = headers["content-security-policy"]
    assert "unsafe-eval" not in csp
    assert "nonce-" in csp
