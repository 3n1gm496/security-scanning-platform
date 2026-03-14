"""Notification routes: /api/notifications/*."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException

from auth import require_auth, AuthContext
from db import get_connection
from notifications import NotificationPreferencesManager

from routers._shared import DB_PATH, notification_engine

router = APIRouter(prefix="/api", tags=["notifications"])


@router.post("/notifications/send-alert")
def send_notification_alert(
    to_email: str = Form(...),
    finding_id: int = Form(...),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Send critical finding notification email."""
    with get_connection(DB_PATH) as conn:
        finding = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        sent = notification_engine.send_critical_finding_alert(to_email=to_email, finding=dict(finding))
        if not sent:
            raise HTTPException(status_code=502, detail="Failed to send email")

    return {"status": "sent", "to": to_email, "finding_id": finding_id}


@router.post("/notifications/preferences")
def save_notification_preferences(
    preferences: dict,
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Save notification preferences for the authenticated user."""
    user_identifier = auth.user_id or auth.api_key_prefix or "unknown"
    with get_connection(DB_PATH) as conn:
        saved = NotificationPreferencesManager.save_preferences(conn, user_identifier, preferences)
        if not saved:
            raise HTTPException(status_code=500, detail="Failed to save preferences")
    return {"status": "saved", "user": user_identifier}


@router.get("/notifications/preferences")
def get_notification_preferences(auth: AuthContext = Depends(require_auth)) -> dict:
    """Get notification preferences for the authenticated user."""
    user_identifier = auth.user_id or auth.api_key_prefix or "unknown"
    with get_connection(DB_PATH) as conn:
        prefs = NotificationPreferencesManager.get_preferences(conn, user_identifier)
    return {"preferences": prefs or {}}
