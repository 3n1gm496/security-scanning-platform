"""
Tests for CSRF middleware.
"""

import sys
from pathlib import Path

import pytest

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
sys.path.insert(0, str(root.parent))

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient

from csrf import CSRFMiddleware


def _make_app():
    """Create a minimal FastAPI app with session + CSRF middleware."""
    app = FastAPI()
    app.add_middleware(
        CSRFMiddleware,
        exempt_paths={"/login", "/health"},
    )
    app.add_middleware(
        SessionMiddleware,
        secret_key="test-secret-key",
    )

    @app.get("/csrf-token")
    def get_csrf(request: Request):
        return {"csrf_token": request.session.get("csrf_token", "")}

    @app.post("/protected")
    def protected():
        return {"status": "ok"}

    @app.post("/login")
    def login():
        return {"status": "logged in"}

    @app.get("/health")
    def health():
        return {"status": "healthy"}

    @app.delete("/resource")
    def delete_resource():
        return {"status": "deleted"}

    return app


@pytest.fixture
def client():
    return TestClient(_make_app())


class TestCSRFMiddleware:

    def test_get_requests_pass_without_token(self, client):
        """GET requests should not require CSRF token."""
        resp = client.get("/csrf-token")
        assert resp.status_code == 200

    def test_post_without_csrf_token_rejected(self, client):
        """POST to a protected endpoint without CSRF token returns 403."""
        resp = client.post("/protected")
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    def test_post_with_valid_csrf_token_accepted(self, client):
        """POST with valid X-CSRF-Token header should succeed."""
        # First GET to establish session and get CSRF token
        get_resp = client.get("/csrf-token")
        token = get_resp.json()["csrf_token"]
        assert token  # Should not be empty

        # POST with the token
        resp = client.post("/protected", headers={"X-CSRF-Token": token})
        assert resp.status_code == 200

    def test_post_with_invalid_csrf_token_rejected(self, client):
        """POST with wrong CSRF token returns 403."""
        # Establish session
        client.get("/csrf-token")
        resp = client.post("/protected", headers={"X-CSRF-Token": "wrong-token"})
        assert resp.status_code == 403

    def test_exempt_path_allows_post_without_token(self, client):
        """Exempt paths (like /login) should not require CSRF token."""
        resp = client.post("/login")
        assert resp.status_code == 200

    def test_delete_requires_csrf_token(self, client):
        """DELETE requests should also require CSRF token."""
        resp = client.delete("/resource")
        assert resp.status_code == 403

    def test_delete_with_valid_csrf_succeeds(self, client):
        get_resp = client.get("/csrf-token")
        token = get_resp.json()["csrf_token"]
        resp = client.delete("/resource", headers={"X-CSRF-Token": token})
        assert resp.status_code == 200

    def test_bearer_auth_bypasses_csrf(self, client):
        """API-key-authenticated requests (Bearer token) should bypass CSRF."""
        resp = client.post(
            "/protected",
            headers={"Authorization": "Bearer some-api-key"},
        )
        assert resp.status_code == 200
