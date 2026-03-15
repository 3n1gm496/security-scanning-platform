from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

_CACHE_LOCKS: dict[str, threading.Lock] = {}
_CACHE_LOCKS_GUARD = threading.Lock()


def build_cache_key(tool_name: str, target_type: str, target_value: str, context: dict[str, Any] | None = None) -> str:
    payload = {
        "tool": tool_name,
        "target_type": target_type,
        "target_value": target_value,
        "context": context or {},
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _cache_file(cache_dir: Path, cache_key: str) -> Path:
    return cache_dir / f"{cache_key}.json"


def _cache_lock(cache_key: str) -> threading.Lock:
    with _CACHE_LOCKS_GUARD:
        lock = _CACHE_LOCKS.get(cache_key)
        if lock is None:
            lock = threading.Lock()
            _CACHE_LOCKS[cache_key] = lock
        return lock


def load_cached_output(cache_dir: Path, cache_key: str, output_path: str, ttl_seconds: int) -> bool:
    cache_file = _cache_file(cache_dir, cache_key)
    with _cache_lock(cache_key):
        if not cache_file.exists():
            return False

        age = time.time() - cache_file.stat().st_mtime
        if age > ttl_seconds:
            return False

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cache_file, output_path)
        return True


def store_cached_output(cache_dir: Path, cache_key: str, output_path: str) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = _cache_file(cache_dir, cache_key)
    with _cache_lock(cache_key):
        fd, temp_name = tempfile.mkstemp(prefix=f"{cache_key}.", suffix=".tmp", dir=str(cache_dir))
        os.close(fd)
        temp_path = Path(temp_name)
        try:
            shutil.copyfile(output_path, temp_path)
            os.replace(temp_path, cache_file)
        finally:
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
