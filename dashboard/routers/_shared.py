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
scan_executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS, thread_name_prefix="scan-worker")

# ── TTL cache for analytics queries ──────────────────────────────────────
_ttl_cache: dict[str, tuple[float, object]] = {}
_ttl_lock = Lock()
ANALYTICS_CACHE_TTL: int = int(os.getenv("ANALYTICS_CACHE_TTL_SECONDS", "60"))


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
