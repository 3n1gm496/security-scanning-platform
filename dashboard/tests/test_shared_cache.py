"""Tests for shared router cache helpers."""

from __future__ import annotations

import sys
import types
from pathlib import Path

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

if "bcrypt" not in sys.modules:
    fake_bcrypt = types.ModuleType("bcrypt")
    fake_bcrypt.gensalt = lambda: b"salt"
    fake_bcrypt.hashpw = lambda value, salt: b"$2b$stubbed-hash"
    fake_bcrypt.checkpw = lambda plain, hashed: True
    sys.modules["bcrypt"] = fake_bcrypt

from routers import _shared


def test_cached_cleans_inflight_lock_after_compute():
    _shared._ttl_cache.clear()
    _shared._ttl_inflight.clear()

    result = _shared.cached("alpha", lambda: {"ok": True}, ttl=10)

    assert result == {"ok": True}
    assert "alpha" not in _shared._ttl_inflight
