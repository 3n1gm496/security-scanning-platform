"""
Webhook system for sending notifications on scan events.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import random
import socket
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from logging_config import get_logger
from urllib.parse import urlparse

import httpx

from db import get_connection
from db_adapter import is_postgres

DASHBOARD_DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")
WEBHOOK_TIMEOUT_SECONDS = int(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10"))
WEBHOOK_RETRY_COUNT = int(os.getenv("WEBHOOK_RETRY_COUNT", "3"))
WEBHOOK_CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("WEBHOOK_CIRCUIT_BREAKER_THRESHOLD", "5"))

# ---------------------------------------------------------------------------
# SSRF protection — blocked IP ranges
# ---------------------------------------------------------------------------
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS IMDS
    ipaddress.ip_network("100.64.0.0/10"),  # shared address space (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # unique local IPv6
    ipaddress.ip_network("fe80::/10"),  # link-local IPv6
]


def _check_ip_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Raise ValueError if addr is in a private/reserved range."""
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise ValueError(
                f"Webhook URL targets a private/reserved address ({addr}). " "Only public endpoints are allowed."
            )
    # IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) bypass pure IPv6 checks.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        for net in _BLOCKED_NETWORKS:
            if addr.ipv4_mapped in net:
                raise ValueError(
                    f"Webhook URL targets a private/reserved address ({addr}). " "Only public endpoints are allowed."
                )


def validate_webhook_url(url: str, *, resolve_dns: bool = True) -> None:
    """Validate a webhook URL to prevent SSRF attacks.

    Raises ``ValueError`` with a descriptive message if the URL is unsafe.
    Checks:
    - Scheme must be http or https.
    - If the hostname is a literal IP, it must not be in a private/reserved range.
    - If the hostname is a domain name and ``resolve_dns`` is True, resolve it
      and verify that none of the resolved IPs are in a blocked range (DNS-rebinding
      mitigation).
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Webhook URL must use http or https scheme, got: '{parsed.scheme}'")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL must include a hostname")

    # If the hostname is a literal IP address, check it directly.
    try:
        addr = ipaddress.ip_address(hostname)
        _check_ip_blocked(addr)
        return  # literal IP, validated
    except ValueError as exc:
        if "private/reserved" in str(exc):
            raise
        # Not a literal IP — hostname is a domain name, fall through to DNS check.

    # DNS-rebinding mitigation: resolve the hostname and check all IPs.
    if resolve_dns:
        try:
            results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            for _family, _type, _proto, _canonname, sockaddr in results:
                addr = ipaddress.ip_address(sockaddr[0])
                _check_ip_blocked(addr)
        except socket.gaierror:
            # DNS failure at registration: domain may not resolve in this
            # environment (e.g. CI, air-gapped network).  Log a warning but
            # don't block — the *real* SSRF guard runs at delivery time when
            # the resolved IPs are checked again.
            pass


logger = get_logger(__name__)


class WebhookEvent(str, Enum):
    """Available webhook events."""

    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    FINDING_HIGH = "finding.high"
    FINDING_CRITICAL = "finding.critical"


def init_webhook_tables():
    """Initialize webhook tables in the database."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        conn.execute("""
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
                failure_count INTEGER DEFAULT 0,
                consecutive_failures INTEGER DEFAULT 0
            )
        """)

        # Migrate: add column if missing (safe for SQLite)
        try:
            conn.execute("SELECT consecutive_failures FROM webhooks LIMIT 0")
        except Exception:
            conn.execute("ALTER TABLE webhooks ADD COLUMN consecutive_failures INTEGER DEFAULT 0")

        conn.execute("""
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


def create_webhook(name: str, url: str, events: list[WebhookEvent], secret: Optional[str] = None) -> int:
    """
    Create a new webhook.
    Returns webhook ID.
    Raises ``ValueError`` if the URL fails SSRF validation.
    """
    validate_webhook_url(url)
    events_str = ",".join([e.value for e in events])
    created_at = datetime.now(timezone.utc).isoformat()

    sql = "INSERT INTO webhooks (name, url, secret, events, created_at) VALUES (?, ?, ?, ?, ?)"
    if is_postgres():
        sql += " RETURNING id"

    with get_connection(DASHBOARD_DB_PATH) as conn:
        cursor = conn.execute(sql, (name, url, secret, events_str, created_at))
        webhook_id = cursor.fetchone()[0] if is_postgres() else cursor.lastrowid

    logger.info("webhook.created", webhook_id=webhook_id, name=name, url=url)
    return webhook_id


def list_webhooks() -> list[dict]:
    """List all webhooks."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        rows = conn.execute("""
            SELECT id, name, url, events, is_active, created_at, last_triggered_at,
                   success_count, failure_count, consecutive_failures
            FROM webhooks
            ORDER BY created_at DESC
        """).fetchall()
    return [dict(row) for row in rows]


def delete_webhook(webhook_id: int) -> bool:
    """Delete a webhook."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        cursor = conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    return cursor.rowcount > 0


def toggle_webhook(webhook_id: int, is_active: bool) -> bool:
    """Enable or disable a webhook."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE webhooks SET is_active = ? WHERE id = ?",
            (1 if is_active else 0, webhook_id),
        )
    return cursor.rowcount > 0


def _generate_signature(payload: str, secret: str) -> str:
    """Generate HMAC-SHA256 signature for webhook payload."""
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


async def trigger_webhook(webhook: dict, event_type: WebhookEvent, payload: dict) -> tuple[bool, Optional[str]]:
    """
    Trigger a webhook delivery.
    Returns (success, error_message).
    """
    start_time = time.time()

    payload_with_meta = {
        "event": event_type.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    }

    payload_str = json.dumps(payload_with_meta)

    headers = {"Content-Type": "application/json", "User-Agent": "SecurityScanning-Webhook/1.0"}

    if webhook.get("secret"):
        signature = _generate_signature(payload_str, webhook["secret"])
        headers["X-Webhook-Signature"] = f"sha256={signature}"

    error_msg = None
    response_status = None
    response_body = None

    # Re-validate the URL at delivery time to mitigate DNS rebinding attacks
    # (the hostname may now resolve to a different IP than at registration time).
    try:
        validate_webhook_url(webhook["url"], resolve_dns=True)
    except ValueError as exc:
        error_msg = f"SSRF validation failed at delivery: {exc}"
        logger.warning("webhook.ssrf_blocked", webhook_id=webhook["id"], error=error_msg)
        duration_ms = int((time.time() - start_time) * 1000)
        _log_delivery(webhook["id"], event_type.value, payload_str, None, None, error_msg, duration_ms)
        _update_webhook_stats(webhook["id"], success=False)
        return False, error_msg

    async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS, follow_redirects=False) as client:
        for attempt in range(WEBHOOK_RETRY_COUNT):
            try:
                response = await client.post(webhook["url"], content=payload_str, headers=headers)

                response_status = response.status_code
                response_body = response.text[:1000]

                if response.is_success:
                    duration_ms = int((time.time() - start_time) * 1000)
                    _log_delivery(
                        webhook["id"],
                        event_type.value,
                        payload_str,
                        response_status,
                        response_body,
                        None,
                        duration_ms,
                    )
                    _update_webhook_stats(webhook["id"], success=True)
                    logger.info(
                        "webhook.delivered",
                        webhook_id=webhook["id"],
                        attempt=attempt + 1,
                        max_attempts=WEBHOOK_RETRY_COUNT,
                    )
                    return True, None
                else:
                    error_msg = f"HTTP {response_status}: {response_body}"
                    # 4xx client errors will not succeed on retry — break immediately
                    if response_status is not None and 400 <= response_status < 500:
                        break

            except Exception as e:
                error_msg = str(e)
                logger.warning(
                    "webhook.delivery_failed",
                    webhook_id=webhook["id"],
                    attempt=attempt + 1,
                    max_attempts=WEBHOOK_RETRY_COUNT,
                    error=error_msg,
                )

            if attempt < WEBHOOK_RETRY_COUNT - 1:
                base_delay = 2**attempt
                jitter = random.uniform(0, base_delay)
                await asyncio.sleep(base_delay + jitter)

    duration_ms = int((time.time() - start_time) * 1000)
    _log_delivery(webhook["id"], event_type.value, payload_str, response_status, response_body, error_msg, duration_ms)
    _update_webhook_stats(webhook["id"], success=False)

    return False, error_msg


def _log_delivery(
    webhook_id: int,
    event_type: str,
    payload: str,
    response_status: Optional[int],
    response_body: Optional[str],
    error: Optional[str],
    duration_ms: int,
):
    """Log webhook delivery attempt."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO webhook_deliveries
            (webhook_id, event_type, payload, response_status, response_body, error, delivered_at, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                webhook_id,
                event_type,
                payload,
                response_status,
                response_body,
                error,
                datetime.now(timezone.utc).isoformat(),
                duration_ms,
            ),
        )


def _update_webhook_stats(webhook_id: int, success: bool):
    """Update webhook statistics and trip circuit breaker on repeated failures."""
    now = datetime.now(timezone.utc).isoformat()
    with get_connection(DASHBOARD_DB_PATH) as conn:
        if success:
            conn.execute(
                """
                UPDATE webhooks
                SET success_count = success_count + 1,
                    consecutive_failures = 0,
                    last_triggered_at = ?
                WHERE id = ?
                """,
                (now, webhook_id),
            )
        else:
            conn.execute(
                """
                UPDATE webhooks
                SET failure_count = failure_count + 1,
                    consecutive_failures = consecutive_failures + 1
                WHERE id = ?
                """,
                (webhook_id,),
            )
            # Circuit breaker: auto-disable after N consecutive failures
            row = conn.execute("SELECT consecutive_failures FROM webhooks WHERE id = ?", (webhook_id,)).fetchone()
            if row and row["consecutive_failures"] >= WEBHOOK_CIRCUIT_BREAKER_THRESHOLD:
                conn.execute("UPDATE webhooks SET is_active = 0 WHERE id = ?", (webhook_id,))
                logger.warning(
                    "webhook.circuit_breaker_tripped",
                    webhook_id=webhook_id,
                    consecutive_failures=row["consecutive_failures"],
                )


async def notify_scan_completed(scan_id: int, scan_data: dict):
    """Notify all webhooks about a completed scan."""
    webhooks = list_webhooks()

    for webhook in webhooks:
        if not webhook["is_active"]:
            continue

        events = webhook["events"].split(",")
        if WebhookEvent.SCAN_COMPLETED.value not in events:
            continue

        payload = {"scan_id": scan_id, **scan_data}
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
