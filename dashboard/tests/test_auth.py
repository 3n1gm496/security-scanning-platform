from fastapi.testclient import TestClient
import os
import sys
from pathlib import Path
import pytest

# make sure the dashboard directory is on sys.path so `import app` works
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

# ensure app imports the env vars for tests
os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
# override database path to avoid writing to /data
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from app import app  # import after env vars

# stub out DB calls so index page can render without real database
import dashboard.db as _db
import dashboard.app as _dashapp
import app as _topapp

@pytest.fixture(autouse=True)
def stub_db(monkeypatch):
    for module in (_db, _dashapp, _topapp):
        monkeypatch.setattr(module, "fetch_kpis", lambda path: {})
        monkeypatch.setattr(module, "cache_hit_stats", lambda path: {"overall_cache_hit_pct": 0.0, "cached_runs": 0, "total_runs": 0, "by_tool": []})
        monkeypatch.setattr(module, "severity_breakdown", lambda path: {})
        monkeypatch.setattr(module, "tool_breakdown", lambda path: {})
        monkeypatch.setattr(module, "target_breakdown", lambda path: {})
        monkeypatch.setattr(module, "scans_trend", lambda path, days: [])
        monkeypatch.setattr(module, "recent_failed_scans", lambda path, n: [])

client = TestClient(app)


def test_login_redirects_anonymous():
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (307, 302)
    # should redirect to login
    assert "/login" in resp.headers["location"]


def test_login_wrong_credentials():
    resp = client.post("/login", data={"username": "foo", "password": "bar"})
    assert resp.status_code == 401
    assert "Credenziali non valide" in resp.text


def test_login_and_access():
    resp = client.post("/login", data={"username": "testuser", "password": "testpass"}, follow_redirects=False)
    assert resp.status_code == 302
    # capture session cookie
    cookie = resp.cookies.get("session")
    assert cookie
    # use cookie to access protected page
    resp2 = client.get("/", cookies={"session": cookie})
    assert resp2.status_code == 200
    assert "Security Scanning Dashboard" in resp2.text


def test_logout():
    # login first
    resp = client.post("/login", data={"username": "testuser", "password": "testpass"}, follow_redirects=False)
    cookie = resp.cookies.get("session")
    assert cookie
    # logout
    resp2 = client.get("/logout", cookies={"session": cookie}, follow_redirects=False)
    assert resp2.status_code == 302
    assert "/login" in resp2.headers["location"]
    # attempt access again (no cookies)
    resp3 = client.get("/", follow_redirects=False)
    assert resp3.status_code in (307, 302)
