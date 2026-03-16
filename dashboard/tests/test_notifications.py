"""Unit tests for email notifications."""

import os
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

if "bcrypt" not in sys.modules:
    fake_bcrypt = types.ModuleType("bcrypt")
    fake_bcrypt.gensalt = lambda: b"salt"
    fake_bcrypt.hashpw = lambda value, salt: b"$2b$stubbed-hash"
    fake_bcrypt.checkpw = lambda plain, hashed: True
    sys.modules["bcrypt"] = fake_bcrypt

from db_adapter import get_connection
from notifications import EmailNotificationEngine, NotificationPreferencesManager


def test_notification_engine_init():
    """Test email notification engine initialization."""
    engine = EmailNotificationEngine()
    assert engine.smtp_server
    assert engine.from_email


def test_notification_preferences_save():
    """Test saving notification preferences."""
    conn = get_connection(":memory:")
    prefs = {
        "critical_alerts": True,
        "high_alerts": False,
        "weekly_digest": True,
    }
    result = NotificationPreferencesManager.save_preferences(conn, "test@example.com", prefs)
    assert result is True


def test_notification_preferences_get():
    """Test retrieving notification preferences."""
    conn = get_connection(":memory:")
    NotificationPreferencesManager.save_preferences(conn, "test@example.com", {"critical_alerts": True})
    prefs = NotificationPreferencesManager.get_preferences(conn, "test@example.com")
    assert prefs is not None
    assert prefs["user_email"] == "test@example.com"


def test_get_subscribers():
    """Test getting subscribers for alerts."""
    conn = get_connection(":memory:")
    NotificationPreferencesManager.save_preferences(conn, "user1@example.com", {"critical_alerts": True})
    NotificationPreferencesManager.save_preferences(conn, "user2@example.com", {"critical_alerts": False})

    subscribers = NotificationPreferencesManager.get_subscribers_for_alerts(conn, "critical_alerts")
    assert "user1@example.com" in subscribers
    assert "user2@example.com" not in subscribers


os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")

from app import app  # noqa: E402
from conftest import SyncASGITestClient  # noqa: E402


def test_notification_links_escape_identifier_in_href():
    """Finding IDs embedded in hrefs must be URL-encoded, not raw HTML."""
    engine = EmailNotificationEngine()
    captured = {}

    def fake_send(_to_email, _subject, _text_body, html_body):
        captured["html"] = html_body
        return True

    engine._send_email = fake_send  # type: ignore[method-assign]
    finding = {
        "id": 'abc" onclick="alert(1)"',
        "scan_id": "scan-123",
        "title": "Injected",
        "description": "desc",
        "file": "src/app.py",
        "line": 41,
        "cve": "CVE-2026-0001",
    }

    assert engine.send_critical_finding_alert("test@example.com", finding, "https://dashboard.example.com")
    assert "onclick=" not in captured["html"]
    assert "/#findings?scan_id=scan-123&amp;search=Injected" in captured["html"]
    assert "src/app.py" in captured["html"]
    assert "41" in captured["html"]
    assert "CVE-2026-0001" in captured["html"]
    assert "/#settings" in captured["html"]


def test_scan_summary_uses_findings_count_fallback_and_spa_link():
    """Scan summaries should fall back to findings_count and link to a valid SPA route."""
    engine = EmailNotificationEngine()
    captured = {}

    def fake_send(_to_email, _subject, text_body, html_body):
        captured["text"] = text_body
        captured["html"] = html_body
        return True

    engine._send_email = fake_send  # type: ignore[method-assign]

    scan_results = {
        "id": "scan-456",
        "target_name": "demo-service",
        "created_at": "2026-03-16T10:00:00Z",
        "critical_count": 1,
        "high_count": 2,
        "medium_count": 3,
        "findings_count": 6,
    }

    assert engine.send_scan_summary("test@example.com", scan_results, "https://dashboard.example.com")
    assert "6" in captured["html"]
    assert "scan-456" in captured["html"]
    assert "TOTAL: 6" in captured["text"]
    assert "/#scans?search=scan-456" in captured["html"]


def test_send_email_skips_starttls_when_server_does_not_support_it(monkeypatch):
    """SMTP delivery should not fail just because STARTTLS is unavailable."""
    calls = {"starttls": 0, "login": 0, "send": 0}

    class FakeSMTP:
        def __init__(self, host, port):
            self.host = host
            self.port = port

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def ehlo(self):
            return None

        def has_extn(self, name):
            return False

        def starttls(self):
            calls["starttls"] += 1

        def login(self, user, password):
            calls["login"] += 1

        def send_message(self, msg):
            calls["send"] += 1

    monkeypatch.setattr("notifications.smtplib.SMTP", FakeSMTP)
    engine = EmailNotificationEngine()
    engine.smtp_user = "user"
    engine.smtp_password = "pass"

    assert engine._send_email("test@example.com", "Subject", "plain", "<b>html</b>") is True
    assert calls["starttls"] == 0
    assert calls["login"] == 1
    assert calls["send"] == 1


def test_notification_preferences_api_flow(isolated_db):
    """Test the full API flow for saving and retrieving notification preferences."""
    test_prefs = {
        "critical_alerts": False,
        "high_alerts": True,
        "scan_summaries": True,
        "weekly_digest": False,
        "preferred_channel": "email",
    }

    with SyncASGITestClient(app) as client:
        # Authenticate with CSRF
        from conftest import login_with_csrf

        login_with_csrf(client)

        # 1. Save preferences
        save_response = client.post("/api/notifications/preferences", json=test_prefs)
        assert save_response.status_code == 200
        assert save_response.json()["status"] == "saved"

        # 2. Retrieve preferences
        get_response = client.get("/api/notifications/preferences")
        assert get_response.status_code == 200
        retrieved_prefs = get_response.json().get("preferences", {})

        # 3. Verify they match
        # user_email in the DB is the user_identifier (username), not the form email field
        assert retrieved_prefs["user_email"] == "testuser"
        assert retrieved_prefs["critical_alerts"] == test_prefs["critical_alerts"]
        assert retrieved_prefs["high_alerts"] == test_prefs["high_alerts"]
        assert retrieved_prefs["scan_summaries"] == test_prefs["scan_summaries"]
        assert retrieved_prefs["weekly_digest"] == test_prefs["weekly_digest"]
        assert retrieved_prefs["preferred_channel"] == test_prefs["preferred_channel"]
