from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any


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


def load_cached_output(cache_dir: Path, cache_key: str, output_path: str, ttl_seconds: int) -> bool:
    cache_file = _cache_file(cache_dir, cache_key)
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
    shutil.copyfile(output_path, cache_file)
