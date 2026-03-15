"""Shared state and utilities used across router modules.

This module holds references to objects that are initialised once in app.py
and need to be accessible from individual routers (DB_PATH, executors, engines,
templates, etc.).  The values are set by app.py at startup via the ``init()``
function.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from queue import SimpleQueue

from fastapi.templating import Jinja2Templates

from notifications import EmailNotificationEngine

# ── Database path ──────────────────────────────────────────────────────────
DB_PATH: str = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")

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
        global _scan_queue_depth
        try:
            return fn(*args, **kwargs)
        finally:
            with _scan_queue_lock:
                _scan_queue_depth -= 1

    return scan_executor.submit(_wrapper)

# ── TTL cache for analytics queries ──────────────────────────────────────
_ttl_cache: dict[str, tuple[float, object]] = {}
_ttl_lock = Lock()
ANALYTICS_CACHE_TTL: int = int(os.getenv("ANALYTICS_CACHE_TTL_SECONDS", "300"))


def cached(key: str, fn, ttl: int = ANALYTICS_CACHE_TTL):
    """Return cached result or call *fn()* and store for *ttl* seconds."""
    now = time.monotonic()
    with _ttl_lock:
        if key in _ttl_cache:
            expires, value = _ttl_cache[key]
            if now < expires:
                return value
    result = fn()
    with _ttl_lock:
        _ttl_cache[key] = (now + ttl, result)
    return result
