"""
Sliding-window in-process rate limiter.

Extracted from app.py to allow independent unit testing and cleaner imports.
"""

from __future__ import annotations

import os
import time
from collections import deque
from threading import Lock, Timer

RATE_LIMIT_REQUESTS = int(os.getenv("DASHBOARD_RATE_LIMIT_REQUESTS", "180"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DASHBOARD_RATE_LIMIT_WINDOW_SECONDS", "60"))
LOGIN_RATE_LIMIT_REQUESTS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_REQUESTS", "10"))
LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DASHBOARD_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "60"))

_CLEANUP_INTERVAL_SECONDS = 300  # evict stale buckets every 5 minutes

# Maps (scope, client_id) -> deque of monotonic timestamps
_rate_buckets: dict[tuple[str, str], deque] = {}
_rate_lock = Lock()


def is_rate_limited(scope: str, client_id: str, limit: int, window: int, now: float) -> bool:
    """Sliding-window rate limiter. Returns True if the request should be blocked."""
    key = (scope, client_id)
    with _rate_lock:
        if key not in _rate_buckets:
            _rate_buckets[key] = deque()
        bucket = _rate_buckets[key]
        threshold = now - window
        while bucket and bucket[0] < threshold:
            bucket.popleft()
        if len(bucket) >= limit:
            return True
        bucket.append(now)
    return False


def _evict_stale_buckets() -> None:
    """Remove bucket entries whose last timestamp is older than the longest window."""
    cutoff = time.monotonic() - max(RATE_LIMIT_WINDOW_SECONDS, LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    with _rate_lock:
        stale = [k for k, dq in _rate_buckets.items() if not dq or dq[-1] < cutoff]
        for k in stale:
            del _rate_buckets[k]
    # Self-reschedule: only one timer active at a time
    t = Timer(_CLEANUP_INTERVAL_SECONDS, _evict_stale_buckets)
    t.daemon = True
    t.start()


def start_cleanup_timer() -> None:
    """Start the background bucket-eviction timer. Call once at app startup."""
    t = Timer(_CLEANUP_INTERVAL_SECONDS, _evict_stale_buckets)
    t.daemon = True
    t.start()
