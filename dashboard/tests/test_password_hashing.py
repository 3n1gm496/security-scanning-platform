"""
Tests for bcrypt password hashing support in app.py.

Covers:
- _is_bcrypt_hash detection
- _verify_password with bcrypt hash
- _verify_password with plain-text (legacy)
- _verify_password rejects wrong passwords
- Login endpoint works with bcrypt-hashed password in env
- Login endpoint works with plain-text password in env (legacy)
- Login endpoint rejects wrong credentials
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import bcrypt
import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

os.environ.setdefault("DASHBOARD_USERNAME", "testuser")
os.environ.setdefault("DASHBOARD_PASSWORD", "testpass")
os.environ.setdefault("DASHBOARD_DB_PATH", str(root / "test.db"))

from fastapi.testclient import TestClient

import app as _app
from app import _is_bcrypt_hash, _verify_password, app

# ---------------------------------------------------------------------------
# Unit tests for _is_bcrypt_hash
# ---------------------------------------------------------------------------


def test_is_bcrypt_hash_detects_2b_prefix():
    h = bcrypt.hashpw(b"password", bcrypt.gensalt()).decode()
    assert _is_bcrypt_hash(h) is True


def test_is_bcrypt_hash_rejects_plain_text():
    assert _is_bcrypt_hash("plaintext") is False
    assert _is_bcrypt_hash("change-me") is False
    assert _is_bcrypt_hash("") is False


def test_is_bcrypt_hash_detects_2a_prefix():
    # $2a$ is an older bcrypt variant
    assert _is_bcrypt_hash("$2a$12$somehashvalue") is True


def test_is_bcrypt_hash_detects_2y_prefix():
    assert _is_bcrypt_hash("$2y$12$somehashvalue") is True


# ---------------------------------------------------------------------------
# Unit tests for _verify_password
# ---------------------------------------------------------------------------


def test_verify_password_correct_bcrypt():
    hashed = bcrypt.hashpw(b"mysecret", bcrypt.gensalt()).decode()
    assert _verify_password("mysecret", hashed) is True


def test_verify_password_wrong_bcrypt():
    hashed = bcrypt.hashpw(b"mysecret", bcrypt.gensalt()).decode()
    assert _verify_password("wrongpassword", hashed) is False


def test_verify_password_plain_text_correct():
    assert _verify_password("plainpass", "plainpass") is True


def test_verify_password_plain_text_wrong():
    assert _verify_password("wrongpass", "plainpass") is False


def test_verify_password_empty_string():
    assert _verify_password("", "") is True
    assert _verify_password("something", "") is False


def test_verify_password_invalid_bcrypt_hash_returns_false():
    # A string that starts with $2b$ but is not a valid hash
    assert _verify_password("anything", "$2b$invalid_hash") is False


# ---------------------------------------------------------------------------
# Integration tests via TestClient
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def test_login_with_plain_text_password(client):
    """Login must succeed when DASHBOARD_PASSWORD is a plain-text value."""
    with patch.object(_app, "USERNAME", "admin"), patch.object(_app, "PASSWORD_RAW", "myplainpass"):
        resp = client.post("/login", data={"username": "admin", "password": "myplainpass"}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/"


def test_login_with_bcrypt_hashed_password(client):
    """Login must succeed when DASHBOARD_PASSWORD is a bcrypt hash."""
    hashed = bcrypt.hashpw(b"securepass", bcrypt.gensalt()).decode()
    with patch.object(_app, "USERNAME", "admin"), patch.object(_app, "PASSWORD_RAW", hashed):
        resp = client.post("/login", data={"username": "admin", "password": "securepass"}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/"


def test_login_rejects_wrong_password_plain(client):
    """Login must fail with 401 when the plain-text password is wrong."""
    with patch.object(_app, "USERNAME", "admin"), patch.object(_app, "PASSWORD_RAW", "correctpass"):
        resp = client.post("/login", data={"username": "admin", "password": "wrongpass"}, follow_redirects=False)
    assert resp.status_code == 401


def test_login_rejects_wrong_password_bcrypt(client):
    """Login must fail with 401 when the bcrypt password is wrong."""
    hashed = bcrypt.hashpw(b"correctpass", bcrypt.gensalt()).decode()
    with patch.object(_app, "USERNAME", "admin"), patch.object(_app, "PASSWORD_RAW", hashed):
        resp = client.post("/login", data={"username": "admin", "password": "wrongpass"}, follow_redirects=False)
    assert resp.status_code == 401


def test_login_rejects_wrong_username(client):
    """Login must fail with 401 when the username is wrong."""
    with patch.object(_app, "USERNAME", "admin"), patch.object(_app, "PASSWORD_RAW", "pass"):
        resp = client.post("/login", data={"username": "notadmin", "password": "pass"}, follow_redirects=False)
    assert resp.status_code == 401
