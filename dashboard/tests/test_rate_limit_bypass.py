"""
Tests for rate limiting bypass attempts via X-Forwarded-For header spoofing.
"""

import sys
import time
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

from rate_limit import _rate_buckets, is_rate_limited


@pytest.fixture(autouse=True)
def clear_buckets():
    """Clear rate limit state before each test."""
    _rate_buckets.clear()
    yield
    _rate_buckets.clear()


class TestRateLimitBypass:
    """Verify rate limiting cannot be trivially bypassed."""

    def test_different_ips_have_separate_buckets(self):
        """Each IP should have its own rate limit bucket."""
        now = time.monotonic()
        limit = 3
        window = 60

        # IP1: use up the limit
        for _ in range(limit):
            is_rate_limited("api", "192.168.1.1", limit, window, now)

        # IP1 should now be limited
        assert is_rate_limited("api", "192.168.1.1", limit, window, now)

        # IP2 should NOT be limited
        assert not is_rate_limited("api", "192.168.1.2", limit, window, now)

    def test_spoofed_xff_different_from_real_ip(self):
        """Requests from the same real IP should share a bucket regardless
        of what X-Forwarded-For might claim.

        NOTE: This test documents the current behavior — rate limiting is
        keyed on the client identifier passed by the middleware. If the
        middleware trusts X-Forwarded-For directly, an attacker can bypass
        rate limits by rotating the XFF header value.
        """
        now = time.monotonic()
        limit = 3
        window = 60

        # Simulate requests where app.py would use client.host (real IP)
        real_ip = "10.0.0.1"
        for _ in range(limit):
            is_rate_limited("api", real_ip, limit, window, now)

        # Same real IP should be rate limited
        assert is_rate_limited("api", real_ip, limit, window, now)

        # If attacker spoofs XFF and the app uses XFF as key, they bypass limits.
        # This test demonstrates the vulnerability — using a different key escapes.
        spoofed = "203.0.113.99"
        assert not is_rate_limited("api", spoofed, limit, window, now)

    def test_rate_limit_exhaustion_then_recovery(self):
        """After the window expires, requests should be allowed again."""
        now = time.monotonic()
        limit = 2
        window = 1  # 1 second window

        ip = "10.0.0.50"
        for _ in range(limit):
            is_rate_limited("api", ip, limit, window, now)

        assert is_rate_limited("api", ip, limit, window, now)

        # After the window passes, should be allowed
        future = now + window + 0.1
        assert not is_rate_limited("api", ip, limit, window, future)

    def test_login_and_api_separate_namespaces(self):
        """Login and API rate limits should not interfere with each other."""
        now = time.monotonic()
        limit = 2
        window = 60
        ip = "10.0.0.100"

        # Exhaust login limit
        for _ in range(limit):
            is_rate_limited("login", ip, limit, window, now)
        assert is_rate_limited("login", ip, limit, window, now)

        # API limit should still be available
        assert not is_rate_limited("api", ip, limit, window, now)

    def test_ipv4_and_ipv6_separate_buckets(self):
        """IPv4 and IPv6 addresses for the same host are separate buckets."""
        now = time.monotonic()
        limit = 2
        window = 60

        # Exhaust IPv4
        for _ in range(limit):
            is_rate_limited("api", "127.0.0.1", limit, window, now)
        assert is_rate_limited("api", "127.0.0.1", limit, window, now)

        # IPv6 loopback should be separate
        assert not is_rate_limited("api", "::1", limit, window, now)
