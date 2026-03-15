"""Server-Sent Events (SSE) based scan progress bus.

Provides a lightweight publish/subscribe mechanism so the dashboard can
stream real-time scan status updates to connected clients without polling.

SSE is chosen over WebSocket because:
 - No extra dependency (starlette supports it natively via StreamingResponse)
 - Works through HTTP/1.1 reverse proxies without special configuration
 - Simpler client code (EventSource API)
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from logging_config import get_logger

LOGGER = get_logger(__name__)

# In-memory subscribers: dict of asyncio.Queue per client
_subscribers: dict[str, asyncio.Queue] = {}
_subscriber_lock = asyncio.Lock()
_counter = 0

# Reference to the main event loop, set by set_loop() at app startup.
_main_loop: asyncio.AbstractEventLoop | None = None


def set_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Store the main event loop reference so worker threads can schedule tasks."""
    global _main_loop
    _main_loop = loop


async def subscribe(client_id: str) -> asyncio.Queue:
    """Register a new SSE client and return its event queue."""
    global _counter
    async with _subscriber_lock:
        _counter += 1
        queue: asyncio.Queue = asyncio.Queue(maxsize=64)
        _subscribers[client_id] = queue
        LOGGER.info("sse.subscribe", client_id=client_id, total=len(_subscribers))
    return queue


async def unsubscribe(client_id: str) -> None:
    """Remove an SSE client."""
    async with _subscriber_lock:
        _subscribers.pop(client_id, None)
        LOGGER.info("sse.unsubscribe", client_id=client_id, total=len(_subscribers))


async def publish(event_type: str, data: dict[str, Any]) -> None:
    """Broadcast an event to all subscribers (non-blocking, drops if queue full)."""
    payload = json.dumps({"type": event_type, "data": data, "ts": time.time()})
    async with _subscriber_lock:
        dead: list[str] = []
        for client_id, queue in _subscribers.items():
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(client_id)
        for cid in dead:
            _subscribers.pop(cid, None)
            LOGGER.debug("sse.dropped_slow_client", client_id=cid)


def publish_sync(event_type: str, data: dict[str, Any]) -> None:
    """Synchronous wrapper for publish() — safe to call from any thread.

    Uses asyncio.run_coroutine_threadsafe() to schedule the coroutine on the
    main event loop, which works correctly from ThreadPoolExecutor workers.
    """
    loop = _main_loop
    if loop is None or loop.is_closed():
        LOGGER.debug("sse.publish_sync_skipped", reason="no_event_loop")
        return
    try:
        future = asyncio.run_coroutine_threadsafe(publish(event_type, data), loop)
        # Wait briefly so the event is dispatched before the caller moves on,
        # but don't block the worker thread for long.
        future.result(timeout=2.0)
    except Exception as exc:
        LOGGER.debug("sse.publish_sync_error", error=str(exc))
