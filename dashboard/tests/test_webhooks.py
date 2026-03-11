"""
Test per il sistema di webhooks.
"""

import asyncio
import os
import sqlite3
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Add dashboard directory to sys.path so imports work
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

from webhooks import (
    WebhookEvent,
    init_webhook_tables,
    create_webhook,
    list_webhooks,
    delete_webhook,
    toggle_webhook,
    trigger_webhook,
    validate_webhook_url,
    _generate_signature,
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
