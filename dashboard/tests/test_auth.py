import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

# make sure the dashboard directory is on sys.path so `import app` works
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

if "bcrypt" not in sys.modules:
    fake_bcrypt = types.ModuleType("bcrypt")
    fake_bcrypt.gensalt = lambda: b"salt"
    fake_bcrypt.hashpw = lambda value, salt: b"$2b$stubbed-hash"
    fake_bcrypt.checkpw = lambda plain, hashed: True
    sys.modules["bcrypt"] = fake_bcrypt

# ensure app imports the env vars for tests
os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_SESSION_SECRET", "test-session-secret")
# override database path to avoid writing to /data
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

import app as _app
import auth as _auth

# stub out DB calls so index page can render without real database
import db as _db
from app import app  # import after env vars
from conftest import SyncASGITestClient


@pytest.fixture(autouse=True)
def stub_db(monkeypatch):
    for module in (_db, _app):
        monkeypatch.setattr(module, "fetch_kpis", lambda path: {})
        monkeypatch.setattr(
            module,
            "cache_hit_stats",
            lambda path: {"overall_cache_hit_pct": 0.0, "cached_runs": 0, "total_runs": 0, "by_tool": []},
        )
        monkeypatch.setattr(module, "cache_hit_trend", lambda path, days: [])
        monkeypatch.setattr(module, "severity_breakdown", lambda path: {})
        monkeypatch.setattr(module, "tool_breakdown", lambda path: {})
        monkeypatch.setattr(module, "target_breakdown", lambda path: {})
        monkeypatch.setattr(module, "scans_trend", lambda path, days: [])
        monkeypatch.setattr(module, "list_scans", lambda path, limit=12: [])
        monkeypatch.setattr(module, "distinct_targets", lambda path: [])
        monkeypatch.setattr(module, "distinct_tools", lambda path: [])


@pytest.fixture
def client():
    yield SyncASGITestClient(app)


def test_login_redirects_anonymous(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (307, 302)
    # should redirect to login
    assert "/login" in resp.headers["location"]


def test_login_wrong_credentials(client):
    resp = client.post("/login", data={"username": "foo", "password": "bar"})
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.text


def test_login_and_access(client):
    resp = client.post("/login", data={"username": "testuser", "password": "testpass"}, follow_redirects=False)
    assert resp.status_code == 302
    # use persisted session cookie on the same client
    resp2 = client.get("/")
    assert resp2.status_code == 200
    assert "Security Scanning" in resp2.text


def test_logout(client):
    # login first
    client.post("/login", data={"username": "testuser", "password": "testpass"}, follow_redirects=False)
    client.headers["X-CSRF-Token"] = client.cookies.get("csrf_token", "")
    # logout
    resp2 = client.post("/logout", follow_redirects=False)
    assert resp2.status_code == 302
    assert "/login" in resp2.headers["location"]
    # attempt access again (no cookies)
    resp3 = client.get("/", follow_redirects=False)
    assert resp3.status_code in (307, 302)


def test_cache_hit_trend_csv(client):
    client.post("/login", data={"username": "testuser", "password": "testpass"}, follow_redirects=False)
    resp = client.get("/api/cache-hit-trend.csv?days=14")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert 'attachment; filename="cache-hit-trend.csv"' in resp.headers.get("content-disposition", "")
    assert "day,tool_runs,cached_runs,cache_hit_pct" in resp.text


@pytest.mark.asyncio
async def test_auth_from_api_key_reuses_scope_cache(monkeypatch):
    seen = {"calls": 0}

    def fake_verify(_key):
        seen["calls"] += 1
        return {"role": "admin", "key_prefix": "ssp_cached", "tenant_id": "default"}

    monkeypatch.setattr(_auth, "verify_api_key", fake_verify)
    monkeypatch.setattr(_auth, "log_audit", lambda **_kwargs: None)

    request = SimpleNamespace(
        scope={"auth_api_key_info": {"role": "admin", "key_prefix": "ssp_cached", "tenant_id": "default"}},
        url=SimpleNamespace(path="/api/test"),
        client=SimpleNamespace(host="127.0.0.1"),
    )
    ctx = await _auth._auth_from_api_key(request, "Bearer cached-key")
    assert ctx is not None
    assert ctx.api_key_prefix == "ssp_cached"
    assert seen["calls"] == 0


@pytest.mark.asyncio
async def test_auth_from_session_uses_session_role():
    request = SimpleNamespace(session={"user": "viewer_user", "role": "viewer"})

    ctx = await _auth._auth_from_session(request)

    assert ctx is not None
    assert ctx.user_id == "viewer_user"
    assert ctx.role == _auth.Role.VIEWER
