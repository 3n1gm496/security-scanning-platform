"""Unit tests for email notifications."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

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


import os
from fastapi.testclient import TestClient

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")

from app import app  # noqa: E402


def test_notification_preferences_api_flow(isolated_db):
    """Test the full API flow for saving and retrieving notification preferences."""
    test_prefs = {
        "user_email": "test.user@example.com",
        "critical_alerts": False,
        "high_alerts": True,
        "scan_summaries": True,
        "weekly_digest": False,
    }

    with TestClient(app) as client:
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
