"""
Webhook system for sending notifications on scan events.
"""
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import httpx

DASHBOARD_DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")
WEBHOOK_TIMEOUT_SECONDS = int(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10"))
WEBHOOK_RETRY_COUNT = int(os.getenv("WEBHOOK_RETRY_COUNT", "3"))

logger = logging.getLogger(__name__)


class WebhookEvent(str, Enum):
    """Available webhook events."""
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    FINDING_HIGH = "finding.high"
    FINDING_CRITICAL = "finding.critical"


def init_webhook_tables():
    """Initialize webhook tables in the database."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()
    
    # Webhooks configuration table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            secret TEXT,
            events TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_triggered_at TEXT,
            success_count INTEGER DEFAULT 0,
            failure_count INTEGER DEFAULT 0
        )
    """)
    
    # Webhook delivery log
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            response_status INTEGER,
            response_body TEXT,
            error TEXT,
            delivered_at TEXT NOT NULL,
            duration_ms INTEGER,
            FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
        )
    """)
    
    conn.commit()
    conn.close()


def create_webhook(
    name: str,
    url: str,
    events: list[WebhookEvent],
    secret: Optional[str] = None
) -> int:
    """
    Create a new webhook.
    Returns webhook ID.
    """
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()
    
    events_str = ",".join([e.value for e in events])
    created_at = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
        INSERT INTO webhooks (name, url, secret, events, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (name, url, secret, events_str, created_at))
    
    webhook_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    logger.info("Created webhook #%d: %s -> %s", webhook_id, name, url)
    return webhook_id


def list_webhooks() -> list[dict]:
    """List all webhooks."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, name, url, events, is_active, created_at, last_triggered_at, 
               success_count, failure_count
        FROM webhooks
        ORDER BY created_at DESC
    """)
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def delete_webhook(webhook_id: int) -> bool:
    """Delete a webhook."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    affected = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    return affected > 0


def toggle_webhook(webhook_id: int, is_active: bool) -> bool:
    """Enable or disable a webhook."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE webhooks SET is_active = ? WHERE id = ?
    """, (1 if is_active else 0, webhook_id))
    
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    
    return affected > 0


def _generate_signature(payload: str, secret: str) -> str:
    """Generate HMAC signature for webhook payload."""
    return hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


async def trigger_webhook(
    webhook: dict,
    event_type: WebhookEvent,
    payload: dict
) -> tuple[bool, Optional[str]]:
    """
    Trigger a webhook delivery.
    Returns (success, error_message).
    """
    start_time = time.time()
    
    # Prepare payload
    payload_with_meta = {
        "event": event_type.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload
    }
    
    payload_str = json.dumps(payload_with_meta)
    
    # Prepare headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SecurityScanning-Webhook/1.0"
    }
    
    # Add signature if secret is configured
    if webhook.get("secret"):
        signature = _generate_signature(payload_str, webhook["secret"])
        headers["X-Webhook-Signature"] = f"sha256={signature}"
    
    # Send request with retries
    error_msg = None
    response_status = None
    response_body = None
    
    async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS) as client:
        for attempt in range(WEBHOOK_RETRY_COUNT):
            try:
                response = await client.post(
                    webhook["url"],
                    content=payload_str,
                    headers=headers
                )
                
                response_status = response.status_code
                response_body = response.text[:1000]  # Limit response body size
                
                if response.is_success:
                    duration_ms = int((time.time() - start_time) * 1000)
                    _log_delivery(
                        webhook["id"],
                        event_type.value,
                        payload_str,
                        response_status,
                        response_body,
                        None,
                        duration_ms
                    )
                    _update_webhook_stats(webhook["id"], success=True)
                    logger.info("Webhook #%d delivered successfully (attempt %d/%d)", 
                                webhook["id"], attempt + 1, WEBHOOK_RETRY_COUNT)
                    return True, None
                else:
                    error_msg = f"HTTP {response_status}: {response_body}"
                    
            except Exception as e:
                error_msg = str(e)
                logger.warning("Webhook #%d delivery failed (attempt %d/%d): %s", 
                              webhook["id"], attempt + 1, WEBHOOK_RETRY_COUNT, error_msg)
            
            # Wait before retry (exponential backoff)
            if attempt < WEBHOOK_RETRY_COUNT - 1:
                await asyncio.sleep(2 ** attempt)
    
    # All retries failed
    duration_ms = int((time.time() - start_time) * 1000)
    _log_delivery(
        webhook["id"],
        event_type.value,
        payload_str,
        response_status,
        response_body,
        error_msg,
        duration_ms
    )
    _update_webhook_stats(webhook["id"], success=False)
    
    return False, error_msg


def _log_delivery(
    webhook_id: int,
    event_type: str,
    payload: str,
    response_status: Optional[int],
    response_body: Optional[str],
    error: Optional[str],
    duration_ms: int
):
    """Log webhook delivery attempt."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO webhook_deliveries 
        (webhook_id, event_type, payload, response_status, response_body, error, delivered_at, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        webhook_id,
        event_type,
        payload,
        response_status,
        response_body,
        error,
        datetime.now(timezone.utc).isoformat(),
        duration_ms
    ))
    
    conn.commit()
    conn.close()


def _update_webhook_stats(webhook_id: int, success: bool):
    """Update webhook statistics."""
    conn = sqlite3.connect(DASHBOARD_DB_PATH)
    cursor = conn.cursor()
    
    if success:
        cursor.execute("""
            UPDATE webhooks 
            SET success_count = success_count + 1,
                last_triggered_at = ?
            WHERE id = ?
        """, (datetime.now(timezone.utc).isoformat(), webhook_id))
    else:
        cursor.execute("""
            UPDATE webhooks 
            SET failure_count = failure_count + 1
            WHERE id = ?
        """, (webhook_id,))
    
    conn.commit()
    conn.close()


async def notify_scan_completed(scan_id: int, scan_data: dict):
    """Notify all webhooks about a completed scan."""
    webhooks = list_webhooks()
    
    for webhook in webhooks:
        if not webhook["is_active"]:
            continue
        
        events = webhook["events"].split(",")
        if WebhookEvent.SCAN_COMPLETED.value not in events:
            continue
        
        payload = {
            "scan_id": scan_id,
            **scan_data
        }
        
        await trigger_webhook(webhook, WebhookEvent.SCAN_COMPLETED, payload)


async def notify_critical_finding(finding_data: dict):
    """Notify all webhooks about a critical/high severity finding."""
    severity = finding_data.get("severity", "").lower()
    
    if severity == "critical":
        event = WebhookEvent.FINDING_CRITICAL
    elif severity == "high":
        event = WebhookEvent.FINDING_HIGH
    else:
        return  # Not critical or high
    
    webhooks = list_webhooks()
    
    for webhook in webhooks:
        if not webhook["is_active"]:
            continue
        
        events = webhook["events"].split(",")
        if event.value not in events:
            continue
        
        await trigger_webhook(webhook, event, finding_data)


# Missing import
import asyncio
