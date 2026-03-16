"""Unit tests for finding route helpers."""

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

from auth import AuthContext
from rbac import Role
from routers.finding_routes import _actor


def test_actor_prefers_session_user_id():
    auth = AuthContext(role=Role.ADMIN, api_key_prefix="ssp_abc", user_id="alice")
    assert _actor(auth) == "alice"


def test_actor_falls_back_to_api_key_prefix():
    auth = AuthContext(role=Role.ADMIN, api_key_prefix="ssp_abc", user_id=None)
    assert _actor(auth) == "ssp_abc"
