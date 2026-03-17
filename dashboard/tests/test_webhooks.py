"""
Test per il sistema di webhooks.
"""

import os
import sqlite3
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Add dashboard directory to sys.path so imports work
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

if "bcrypt" not in sys.modules:
    fake_bcrypt = types.ModuleType("bcrypt")
    fake_bcrypt.gensalt = lambda: b"salt"
    fake_bcrypt.hashpw = lambda value, salt: b"$2b$stubbed-hash"
    fake_bcrypt.checkpw = lambda plain, hashed: True
    sys.modules["bcrypt"] = fake_bcrypt

from webhooks import (
    WEBHOOK_SECRET_PREFIX,
    WebhookEvent,
    _generate_signature,
    _update_webhook_stats,
    create_webhook,
    delete_webhook,
    init_webhook_tables,
    list_webhooks,
    notify_scan_failed,
    rotate_webhook_secret,
    toggle_webhook,
    trigger_webhook,
    validate_webhook_url,
)


@pytest.fixture
def db_setup(isolated_db):
    """Setup test database."""
    init_webhook_tables()
    yield isolated_db


def test_init_webhook_tables(db_setup):
    """Test che le tabelle webhooks siano create correttamente."""
    conn = sqlite3.connect(os.environ["DASHBOARD_DB_PATH"])
    cursor = conn.cursor()

    # Verifica tabella webhooks
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='webhooks'")
    assert cursor.fetchone() is not None

    # Verifica tabella webhook_deliveries
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='webhook_deliveries'")
    assert cursor.fetchone() is not None

    conn.close()


def test_create_and_list_webhooks(db_setup):
    """Test creazione e listing webhooks."""
    webhook_id = create_webhook(
        name="Test Webhook",
        url="https://example.com/webhook",
        events=[WebhookEvent.SCAN_COMPLETED, WebhookEvent.FINDING_CRITICAL],
    )

    assert webhook_id > 0

    webhooks = list_webhooks()
    assert len(webhooks) == 1
    assert webhooks[0]["name"] == "Test Webhook"
    assert webhooks[0]["url"] == "https://example.com/webhook"
    assert "scan.completed" in webhooks[0]["events"]
    assert "finding.critical" in webhooks[0]["events"]
    assert webhooks[0]["is_active"] == 1
    assert "secret" not in webhooks[0]


def test_webhook_secret_is_encrypted_at_rest(db_setup):
    """Webhook secrets should not be stored in plaintext in the database."""
    webhook_id = create_webhook(
        name="Encrypted Secret",
        url="https://example.com/webhook",
        events=[WebhookEvent.SCAN_COMPLETED],
        secret="super-secret-value",
    )

    conn = sqlite3.connect(os.environ["DASHBOARD_DB_PATH"])
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM webhooks WHERE id = ?", (webhook_id,))
    stored_secret = cursor.fetchone()[0]
    conn.close()

    assert stored_secret != "super-secret-value"
    assert stored_secret.startswith(WEBHOOK_SECRET_PREFIX)


def test_list_webhooks_can_include_decrypted_secret_for_internal_use(db_setup):
    """Internal callers may request the decrypted secret explicitly."""
    create_webhook(
        name="Internal Secret",
        url="https://example.com/webhook",
        events=[WebhookEvent.SCAN_COMPLETED],
        secret="internal-secret",
    )

    webhook = list_webhooks(include_secret=True)[0]
    assert webhook["secret"] == "internal-secret"


def test_legacy_plaintext_webhook_secret_is_migrated_on_read(db_setup):
    """Existing plaintext secrets are read and rewritten encrypted transparently."""
    conn = sqlite3.connect(os.environ["DASHBOARD_DB_PATH"])
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO webhooks (name, url, secret, events, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "Legacy Hook",
            "https://example.com/legacy",
            "legacy-plaintext-secret",
            WebhookEvent.SCAN_COMPLETED.value,
            "2026-01-01T00:00:00+00:00",
        ),
    )
    webhook_id = cursor.lastrowid
    conn.commit()
    conn.close()

    webhook = list_webhooks(include_secret=True)[0]
    assert webhook["id"] == webhook_id
    assert webhook["secret"] == "legacy-plaintext-secret"

    conn = sqlite3.connect(os.environ["DASHBOARD_DB_PATH"])
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM webhooks WHERE id = ?", (webhook_id,))
    migrated_secret = cursor.fetchone()[0]
    conn.close()

    assert migrated_secret != "legacy-plaintext-secret"
    assert migrated_secret.startswith(WEBHOOK_SECRET_PREFIX)


def test_delete_webhook(db_setup):
    """Test eliminazione webhook."""
    webhook_id = create_webhook(
        name="Delete Test", url="https://example.com/webhook", events=[WebhookEvent.SCAN_COMPLETED]
    )

    # Verifica esista
    webhooks = list_webhooks()
    assert len(webhooks) == 1

    # Elimina
    success = delete_webhook(webhook_id)
    assert success is True

    # Verifica sia stato eliminato
    webhooks = list_webhooks()
    assert len(webhooks) == 0


def test_delete_nonexistent_webhook(db_setup):
    """Test eliminazione webhook inesistente."""
    success = delete_webhook(9999)
    assert success is False


def test_toggle_webhook(db_setup):
    """Test enable/disable webhook."""
    webhook_id = create_webhook(
        name="Toggle Test", url="https://example.com/webhook", events=[WebhookEvent.SCAN_COMPLETED]
    )

    # Verifica sia attivo
    webhooks = list_webhooks()
    assert webhooks[0]["is_active"] == 1


def test_rotate_webhook_secret_rejects_blank_secret(db_setup):
    """Secret rotation should reject empty/blank replacement secrets."""
    webhook_id = create_webhook(
        name="Rotate Test", url="https://example.com/webhook", events=[WebhookEvent.SCAN_COMPLETED]
    )

    with pytest.raises(ValueError, match="must not be empty"):
        rotate_webhook_secret(webhook_id, "   ")

    # Disabilita
    success = toggle_webhook(webhook_id, False)
    assert success is True

    webhooks = list_webhooks()
    assert webhooks[0]["is_active"] == 0

    # Riabilita
    success = toggle_webhook(webhook_id, True)
    assert success is True

    webhooks = list_webhooks()
    assert webhooks[0]["is_active"] == 1


def test_generate_signature():
    """Test generazione signature HMAC."""
    payload = '{"event": "test"}'
    secret = "test_secret"

    sig1 = _generate_signature(payload, secret)
    sig2 = _generate_signature(payload, secret)

    # Deve essere consistente
    assert sig1 == sig2
    assert len(sig1) == 64  # SHA-256

    # Payload diverso -> signature diversa
    sig3 = _generate_signature('{"event": "different"}', secret)
    assert sig1 != sig3


@pytest.mark.asyncio
async def test_trigger_webhook_success(db_setup):
    """Test invio webhook con successo."""
    create_webhook(name="Success Test", url="https://example.com/webhook", events=[WebhookEvent.SCAN_COMPLETED])

    webhook = list_webhooks()[0]

    # Mock httpx client
    with patch("webhooks.httpx.AsyncClient") as mock_client:
        mock_response = AsyncMock()
        mock_response.is_success = True
        mock_response.status_code = 200
        mock_response.text = "OK"

        mock_post = AsyncMock(return_value=mock_response)
        mock_client.return_value.__aenter__.return_value.post = mock_post

        success, error = await trigger_webhook(
            webhook, WebhookEvent.SCAN_COMPLETED, {"scan_id": 1, "status": "completed"}
        )

        assert success is True
        assert error is None
        assert mock_post.call_count == 1


@pytest.mark.asyncio
async def test_trigger_webhook_failure(db_setup):
    """Test invio webhook con fallimento."""
    create_webhook(name="Failure Test", url="https://example.com/webhook", events=[WebhookEvent.SCAN_FAILED])

    webhook = list_webhooks()[0]

    # Mock httpx client con errore
    with patch("webhooks.httpx.AsyncClient") as mock_client:
        mock_post = AsyncMock(side_effect=Exception("Connection error"))
        mock_client.return_value.__aenter__.return_value.post = mock_post

        # Mock asyncio.sleep per velocizzare il test
        with patch("webhooks.asyncio.sleep", new_callable=AsyncMock):
            success, error = await trigger_webhook(webhook, WebhookEvent.SCAN_FAILED, {"scan_id": 1, "error": "test"})

            assert success is False
            assert error is not None
            assert "Connection error" in error

    webhook = list_webhooks()[0]
    assert webhook["last_triggered_at"] is not None


@pytest.mark.asyncio
async def test_trigger_webhook_with_signature(db_setup):
    """Test che la signature sia inclusa nei headers."""
    webhook_id = create_webhook(
        name="Signature Test",
        url="https://example.com/webhook",
        events=[WebhookEvent.SCAN_COMPLETED],
        secret="test_secret_123",
    )

    # Leggi webhook completo dal DB (incluso secret)
    conn = sqlite3.connect(os.environ["DASHBOARD_DB_PATH"])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
    webhook = dict(cursor.fetchone())
    conn.close()

    # Mock httpx client
    with patch("webhooks.httpx.AsyncClient") as mock_client:
        mock_response = AsyncMock()
        mock_response.is_success = True
        mock_response.status_code = 200
        mock_response.text = "OK"

        mock_post = AsyncMock(return_value=mock_response)
        mock_client.return_value.__aenter__.return_value.post = mock_post

        await trigger_webhook(webhook, WebhookEvent.SCAN_COMPLETED, {"scan_id": 1})

        # Verifica che il signature header sia presente
        call_args = mock_post.call_args
        headers = call_args.kwargs["headers"]
        assert "X-Webhook-Signature" in headers
        assert headers["X-Webhook-Signature"].startswith("sha256=")


# ---------------------------------------------------------------------------
# SSRF protection tests (issue #6)
# ---------------------------------------------------------------------------


class TestValidateWebhookUrl:
    """Tests for validate_webhook_url SSRF protection."""

    def test_valid_public_https_url_passes(self):
        """Public HTTPS URLs should be accepted."""
        validate_webhook_url("https://hooks.example.com/notify")

    def test_valid_public_http_url_passes(self):
        """Public HTTP URLs should also be accepted."""
        validate_webhook_url("http://webhook.example.org/events")

    def test_invalid_scheme_rejected(self):
        """Non-HTTP/HTTPS schemes must be rejected."""
        with pytest.raises(ValueError, match="http or https"):
            validate_webhook_url("ftp://example.com/data")

    def test_file_scheme_rejected(self):
        with pytest.raises(ValueError, match="http or https"):
            validate_webhook_url("file:///etc/passwd")

    def test_loopback_ipv4_rejected(self):
        """Loopback address (127.x.x.x) must be rejected to prevent localhost SSRF."""
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("http://127.0.0.1/admin")

    def test_aws_imds_rejected(self):
        """AWS Instance Metadata Service (169.254.169.254) must be blocked."""
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("http://169.254.169.254/latest/meta-data/")

    def test_rfc1918_10_block_rejected(self):
        """10.0.0.0/8 (RFC 1918) must be rejected."""
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("http://10.10.10.10/hook")

    def test_rfc1918_172_block_rejected(self):
        """172.16.0.0/12 (RFC 1918) must be rejected."""
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("https://172.20.0.1/secret")

    def test_rfc1918_192_168_rejected(self):
        """192.168.0.0/16 (RFC 1918) must be rejected."""
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("http://192.168.1.100/api")

    def test_ipv6_loopback_rejected(self):
        """IPv6 loopback (::1) must be rejected."""
        with pytest.raises(ValueError, match="private/reserved"):
            validate_webhook_url("http://[::1]/internal")

    def test_domain_name_allowed(self):
        """Domain names are allowed (DNS-rebinding not mitigated at this layer)."""
        validate_webhook_url("https://my-company.slack.com/services/hook")

    def test_create_webhook_ssrf_url_rejected(self, db_setup):
        """create_webhook must reject SSRF URLs at storage time."""
        with pytest.raises(ValueError, match="private/reserved"):
            create_webhook(
                name="SSRF Test",
                url="http://10.0.0.1/internal",
                events=[WebhookEvent.SCAN_COMPLETED],
            )


# ---------------------------------------------------------------------------
# Circuit breaker tests (Phase 2)
# ---------------------------------------------------------------------------


class TestWebhookCircuitBreaker:
    """Webhook circuit breaker should auto-disable after consecutive failures."""

    def test_circuit_breaker_trips_after_threshold(self, db_setup):
        """Webhook is auto-disabled after WEBHOOK_CIRCUIT_BREAKER_THRESHOLD failures."""
        from webhooks import WEBHOOK_CIRCUIT_BREAKER_THRESHOLD

        wid = create_webhook(
            name="CB Test",
            url="https://example.com/hook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )

        # Simulate consecutive failures up to threshold
        for _ in range(WEBHOOK_CIRCUIT_BREAKER_THRESHOLD):
            _update_webhook_stats(wid, success=False)

        webhook = list_webhooks()[0]
        assert webhook["is_active"] == 0  # auto-disabled
        assert webhook["consecutive_failures"] >= WEBHOOK_CIRCUIT_BREAKER_THRESHOLD

    def test_success_resets_consecutive_failures(self, db_setup):
        """A successful delivery resets the consecutive_failures counter."""
        wid = create_webhook(
            name="Reset Test",
            url="https://example.com/hook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )

        _update_webhook_stats(wid, success=False)
        _update_webhook_stats(wid, success=False)
        _update_webhook_stats(wid, success=True)

        webhook = list_webhooks()[0]
        assert webhook["consecutive_failures"] == 0
        assert webhook["is_active"] == 1

    def test_failure_updates_last_triggered_at(self, db_setup):
        """Operational timestamps should record failed delivery attempts too."""
        wid = create_webhook(
            name="Timestamp Test",
            url="https://example.com/hook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )

        _update_webhook_stats(wid, success=False)

        webhook = list_webhooks()[0]
        assert webhook["last_triggered_at"] is not None


@pytest.mark.asyncio
async def test_notify_scan_failed_only_targets_matching_events(monkeypatch, db_setup):
    create_webhook(name="Failure Hook", url="https://example.com/fail", events=[WebhookEvent.SCAN_FAILED])
    create_webhook(name="Completion Hook", url="https://example.com/done", events=[WebhookEvent.SCAN_COMPLETED])

    calls = []

    async def fake_trigger(webhook, event_type, payload):
        calls.append((event_type, payload["scan_id"], webhook["name"]))
        return True, None

    monkeypatch.setattr("webhooks.trigger_webhook", fake_trigger)

    await notify_scan_failed("scan-failed", {"status": "FAILED", "error_message": "boom"})

    assert calls == [(WebhookEvent.SCAN_FAILED, "scan-failed", "Failure Hook")]
