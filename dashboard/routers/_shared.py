"""Shared state and utilities used across router modules.

This module holds references to objects that are initialised once in app.py
and need to be accessible from individual routers (DB_PATH, executors, engines,
templates, etc.).  The values are set by app.py at startup via the ``init()``
function.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

from fastapi.templating import Jinja2Templates
from notifications import EmailNotificationEngine
from runtime_config import DASHBOARD_DB_PATH

# ── Database path ──────────────────────────────────────────────────────────
DB_PATH: str = DASHBOARD_DB_PATH

# ── Templates ──────────────────────────────────────────────────────────────
templates: Jinja2Templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

# ── Notification engine ───────────────────────────────────────────────────
notification_engine: EmailNotificationEngine = EmailNotificationEngine()

# ── Bounded thread pool for background scans ──────────────────────────────
MAX_SCAN_WORKERS: int = int(os.getenv("DASHBOARD_MAX_SCAN_WORKERS", "4"))
MAX_SCAN_QUEUE: int = int(os.getenv("DASHBOARD_MAX_SCAN_QUEUE", "20"))
scan_executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS, thread_name_prefix="scan-worker")
_scan_queue_depth = 0
_scan_queue_lock = Lock()
_active_scan_workers = 0
_active_scan_workers_lock = Lock()


def scan_queue_submit(fn, *args, **kwargs):
    """Submit a scan to the bounded pool. Raises RuntimeError if the queue is full."""
    global _scan_queue_depth
    with _scan_queue_lock:
        if _scan_queue_depth >= MAX_SCAN_QUEUE:
            raise RuntimeError(
                f"Scan queue is full ({MAX_SCAN_QUEUE} pending). "
                "Wait for running scans to complete before submitting new ones."
            )
        _scan_queue_depth += 1

    def _wrapper():
        global _scan_queue_depth, _active_scan_workers
        try:
            with _active_scan_workers_lock:
                _active_scan_workers += 1
                try:
                    from monitoring import set_active_scan_workers

                    set_active_scan_workers(_active_scan_workers)
                except Exception:
                    pass
            return fn(*args, **kwargs)
        finally:
            with _active_scan_workers_lock:
                _active_scan_workers = max(0, _active_scan_workers - 1)
                try:
                    from monitoring import set_active_scan_workers

                    set_active_scan_workers(_active_scan_workers)
                except Exception:
                    pass
            with _scan_queue_lock:
                _scan_queue_depth -= 1

    return scan_executor.submit(_wrapper)


# ── TTL cache for analytics queries ──────────────────────────────────────
_ttl_cache: dict[str, tuple[float, object]] = {}
_ttl_lock = Lock()
# Tracks keys currently being computed to prevent thundering herd.
_ttl_inflight: dict[str, Lock] = {}
_ttl_inflight_lock = Lock()
ANALYTICS_CACHE_TTL: int = int(os.getenv("ANALYTICS_CACHE_TTL_SECONDS", "300"))


def cached(key: str, fn, ttl: int = ANALYTICS_CACHE_TTL):
    """Return cached result or call *fn()* and store for *ttl* seconds.

    Uses per-key locks to prevent thundering herd: when multiple threads
    miss the cache for the same key, only one calls *fn()* while the
    others wait for the result.
    """
    now = time.monotonic()
    with _ttl_lock:
        if key in _ttl_cache:
            expires, value = _ttl_cache[key]
            if now < expires:
                return value

    # Acquire a per-key lock so only one thread computes the value.
    with _ttl_inflight_lock:
        if key not in _ttl_inflight:
            _ttl_inflight[key] = Lock()
        key_lock = _ttl_inflight[key]

    with key_lock:
        # Double-check: another thread may have populated the cache while we waited.
        now = time.monotonic()
        with _ttl_lock:
            if key in _ttl_cache:
                expires, value = _ttl_cache[key]
                if now < expires:
                    return value
        result = fn()
        with _ttl_lock:
            _ttl_cache[key] = (now + ttl, result)
    with _ttl_inflight_lock:
        existing = _ttl_inflight.get(key)
        if existing is key_lock and not key_lock.locked():
            _ttl_inflight.pop(key, None)
    return result
