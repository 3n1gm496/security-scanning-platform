"""Webhook management routes: GET/POST/DELETE/PATCH /api/webhooks."""

from __future__ import annotations

from auth import AuthContext, require_auth, require_permission
from fastapi import APIRouter, Depends, Form, HTTPException
from rbac import Permission, log_audit
from starlette import status
from webhooks import WebhookEvent, create_webhook, delete_webhook, list_webhooks, rotate_webhook_secret, toggle_webhook

router = APIRouter(prefix="/api", tags=["webhooks"])


@router.get("/webhooks", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
async def get_webhooks(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """List all webhooks (admin/operator only)."""
    return list_webhooks()


@router.post("/webhooks", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
async def create_new_webhook(
    name: str = Form(...),
    url: str = Form(...),
    events: str = Form(...),  # Comma-separated event types
    secret: str | None = Form(None),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Create a new webhook (admin/operator only)."""
    # Parse events
    event_list = []
    for event_str in events.split(","):
        event_str = event_str.strip()
        try:
            event_list.append(WebhookEvent(event_str))
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid event type: {event_str}")

    try:
        webhook_id = create_webhook(name, url, event_list, secret)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    log_audit(
        action="webhook.create",
        user_id=auth.user_id,
        api_key_prefix=auth.api_key_prefix,
        resource=f"webhook:{webhook_id}",
        result="success",
    )

    return {"id": webhook_id, "name": name, "url": url, "events": events}


@router.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
async def delete_webhook_endpoint(webhook_id: int, auth: AuthContext = Depends(require_auth)) -> dict:
    """Delete a webhook (admin/operator only)."""
    success = delete_webhook(webhook_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    log_audit(
        action="webhook.delete",
        user_id=auth.user_id,
        api_key_prefix=auth.api_key_prefix,
        resource=f"webhook:{webhook_id}",
        result="success",
    )

    return {"status": "deleted", "id": webhook_id}


@router.patch("/webhooks/{webhook_id}", dependencies=[Depends(require_permission(Permission.SCAN_WRITE))])
async def toggle_webhook_endpoint(
    webhook_id: int, is_active: bool = Form(...), auth: AuthContext = Depends(require_auth)
) -> dict:
    """Enable or disable a webhook (admin/operator only)."""
    success = toggle_webhook(webhook_id, is_active)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    return {"status": "updated", "id": webhook_id, "is_active": is_active}


@router.post(
    "/webhooks/{webhook_id}/rotate-secret",
    dependencies=[Depends(require_permission(Permission.SCAN_WRITE))],
)
def rotate_secret_endpoint(
    webhook_id: int,
    secret: str = Form(...),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Rotate the HMAC signing secret for a webhook (admin/operator only).

    The new secret takes effect immediately. The consumer must be updated
    to use the new secret before the next delivery.
    """
    success = rotate_webhook_secret(webhook_id, secret)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    log_audit(
        action="webhook.secret_rotated",
        user_id=auth.user_id,
        api_key_prefix=auth.api_key_prefix,
        resource=f"webhook:{webhook_id}",
        result="success",
    )

    return {"status": "secret_rotated", "id": webhook_id}
