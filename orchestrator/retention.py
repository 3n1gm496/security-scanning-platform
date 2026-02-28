from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)


def _is_expired(path: Path, cutoff_ts: float) -> bool:
    try:
        return path.stat().st_mtime < cutoff_ts
    except FileNotFoundError:
        return False


def cleanup_path(path: Path, cutoff_ts: float) -> int:
    removed = 0
    if not path.exists() or not path.is_dir():
        return removed

    for child in path.iterdir():
        if not _is_expired(child, cutoff_ts):
            continue
        try:
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink(missing_ok=True)
            removed += 1
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Retention cleanup failed for %s: %s", child, exc)
    return removed


def apply_retention(settings: dict[str, Any]) -> dict[str, int]:
    retention = settings.get("retention", {})
    enabled = bool(retention.get("enabled", False))
    if not enabled:
        return {"reports_removed": 0, "workspaces_removed": 0, "cache_removed": 0}

    reports_days = int(retention.get("reports_days", 14))
    workspaces_days = int(retention.get("workspaces_days", 3))
    cache_days = int(retention.get("cache_days", 7))

    paths = settings.get("paths", {})
    cache = settings.get("cache", {})

    reports_dir = Path(str(paths.get("reports_dir", "/data/reports")))
    workspaces_dir = Path(str(paths.get("workspace_dir", "/data/workspaces")))
    cache_dir = Path(str(cache.get("dir", "/data/cache/orchestrator")))

    now = time.time()
    reports_removed = cleanup_path(reports_dir, now - reports_days * 86400)
    workspaces_removed = cleanup_path(workspaces_dir, now - workspaces_days * 86400)
    cache_removed = cleanup_path(cache_dir, now - cache_days * 86400)

    return {
        "reports_removed": reports_removed,
        "workspaces_removed": workspaces_removed,
        "cache_removed": cache_removed,
    }
