"""Unit tests for email notifications."""

import sys
from pathlib import Path
import sqlite3

sys.path.insert(0, str(Path(__file__).parent.parent))

from notifications import EmailNotificationEngine, NotificationPreferencesManager


def test_notification_engine_init():
    """Test email notification engine initialization."""
    engine = EmailNotificationEngine()
    assert engine.smtp_server
    assert engine.from_email


def test_notification_preferences_save():
    """Test saving notification preferences."""
    conn = sqlite3.connect(":memory:")
    prefs = {
        "critical_alerts": True,
        "high_alerts": False,
        "weekly_digest": True,
    }
    result = NotificationPreferencesManager.save_preferences(conn, "test@example.com", prefs)
    assert result is True


def test_notification_preferences_get():
    """Test retrieving notification preferences."""
    conn = sqlite3.connect(":memory:")
    NotificationPreferencesManager.save_preferences(conn, "test@example.com", {"critical_alerts": True})
    prefs = NotificationPreferencesManager.get_preferences(conn, "test@example.com")
    assert prefs is not None
    assert prefs["user_email"] == "test@example.com"


def test_get_subscribers():
    """Test getting subscribers for alerts."""
    conn = sqlite3.connect(":memory:")
    NotificationPreferencesManager.save_preferences(conn, "user1@example.com", {"critical_alerts": True})
    NotificationPreferencesManager.save_preferences(conn, "user2@example.com", {"critical_alerts": False})

    subscribers = NotificationPreferencesManager.get_subscribers_for_alerts(conn, "critical_alerts")
    assert "user1@example.com" in subscribers
    assert "user2@example.com" not in subscribers
