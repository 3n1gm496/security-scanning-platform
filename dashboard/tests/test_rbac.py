"""
Test per il sistema RBAC e API keys.
"""

import os
import sqlite3
import sys
import types
from pathlib import Path

import pytest

# Add dashboard directory to sys.path so imports work
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

if "bcrypt" not in sys.modules:
    fake_bcrypt = types.ModuleType("bcrypt")
    fake_bcrypt.gensalt = lambda: b"salt"
    fake_bcrypt.hashpw = lambda value, salt: b"$2b$" + value
    fake_bcrypt.checkpw = lambda plain, hashed: hashed == (b"$2b$" + plain)
    sys.modules["bcrypt"] = fake_bcrypt

from rbac import (
    Permission,
    Role,
    create_api_key,
    create_default_admin_key,
    has_permission,
    hash_api_key,
    init_rbac_tables,
    list_api_keys,
    revoke_api_key,
    verify_api_key,
)


@pytest.fixture
def db_setup(isolated_db):
    """Setup test database."""
    init_rbac_tables()
    yield isolated_db


def test_init_rbac_tables(db_setup):
    """Test that RBAC tables are created correctly."""
    conn = sqlite3.connect(os.environ["DASHBOARD_DB_PATH"])
    cursor = conn.cursor()

    # Verify api_keys table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys'")
    assert cursor.fetchone() is not None

    # Verify users table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    assert cursor.fetchone() is not None

    # Verify audit_log table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
    assert cursor.fetchone() is not None

    conn.close()


def test_create_and_verify_api_key(db_setup):
    """Test creating and verifying an API key."""
    full_key, prefix = create_api_key(name="Test Key", role=Role.ADMIN, created_by="test_user")

    assert full_key.startswith("ssp_")
    assert len(full_key) == 68  # ssp_ + 64 hex chars
    assert prefix == full_key[:12]

    # Verify the key
    key_info = verify_api_key(full_key)
    assert key_info is not None
    assert key_info["name"] == "Test Key"
    assert key_info["role"] == Role.ADMIN.value
    assert key_info["is_active"] == 1


def test_verify_invalid_api_key(db_setup):
    """Test that invalid keys return None."""
    invalid_key = "ssp_invalid_key_0000000000000000000000000000000000000000000000000000000000000000"
    key_info = verify_api_key(invalid_key)
    assert key_info is None


def test_api_key_expiration(db_setup):
    """Test that expired keys are not valid."""
    full_key, prefix = create_api_key(
        name="Expiring Key", role=Role.VIEWER, expires_days=-1, created_by="test_user"  # Already expired
    )

    key_info = verify_api_key(full_key)
    assert key_info is None


def test_list_api_keys(db_setup):
    """Test listing di tutte le API keys."""
    create_api_key("Key 1", Role.ADMIN, created_by="user1")
    create_api_key("Key 2", Role.VIEWER, created_by="user2")

    keys = list_api_keys()
    assert len(keys) == 2
    assert all("key_hash" not in k for k in keys)  # No sensitive data
    assert any(k["name"] == "Key 1" for k in keys)
    assert any(k["name"] == "Key 2" for k in keys)


def test_revoke_api_key(db_setup):
    """Test revoca di una API key."""
    full_key, prefix = create_api_key("Revoke Test", Role.OPERATOR, created_by="test")

    # Verifica funzioni prima della revoca
    assert verify_api_key(full_key) is not None

    # Revoca la key
    success = revoke_api_key(prefix)
    assert success is True

    # Verifica non funzioni dopo la revoca
    assert verify_api_key(full_key) is None


def test_revoke_nonexistent_key(db_setup):
    """Test revoca di key inesistente."""
    success = revoke_api_key("ssp_nonexist")
    assert success is False


def test_create_default_admin_key_only_once(db_setup):
    first = create_default_admin_key()
    second = create_default_admin_key()

    assert first is not None
    assert second is None

    keys = list_api_keys()
    assert len(keys) == 1


def test_permissions():
    """Test sistema di permessi."""
    # Admin ha tutti i permessi
    assert has_permission(Role.ADMIN, Permission.SCAN_READ)
    assert has_permission(Role.ADMIN, Permission.SCAN_WRITE)
    assert has_permission(Role.ADMIN, Permission.SCAN_DELETE)
    assert has_permission(Role.ADMIN, Permission.USER_MANAGE)

    # Operator ha permessi limitati
    assert has_permission(Role.OPERATOR, Permission.SCAN_READ)
    assert has_permission(Role.OPERATOR, Permission.SCAN_WRITE)
    assert not has_permission(Role.OPERATOR, Permission.SCAN_DELETE)
    assert not has_permission(Role.OPERATOR, Permission.USER_MANAGE)

    # Viewer ha solo lettura
    assert has_permission(Role.VIEWER, Permission.SCAN_READ)
    assert not has_permission(Role.VIEWER, Permission.SCAN_WRITE)
    assert not has_permission(Role.VIEWER, Permission.SCAN_DELETE)
    assert not has_permission(Role.VIEWER, Permission.USER_MANAGE)


def test_api_key_hash_is_bcrypt():
    """API key hashing must produce a bcrypt hash verifiable by _verify_key_hash."""
    key = "bcrypt-roundtrip-placeholder-key-for-tests-only"
    hashed = hash_api_key(key)
    # bcrypt hashes start with $2b$
    assert hashed.startswith("$2b$")
    # Verify round-trip
    from rbac import _verify_key_hash

    assert _verify_key_hash(key, hashed) is True
    assert _verify_key_hash("wrong_key", hashed) is False


def test_api_key_legacy_sha256_still_verified():
    """Legacy SHA-256 hashes must still verify during migration period."""
    import hashlib as _hl

    from rbac import _verify_key_hash

    key = "legacy-sha256-placeholder-key"
    legacy_hash = _hl.sha256(key.encode()).hexdigest()
    assert _verify_key_hash(key, legacy_hash) is True
    assert _verify_key_hash("wrong", legacy_hash) is False


def test_api_key_last_used_update(db_setup):
    """Test that last_used_at is updated on verification."""
    import time

    full_key, prefix = create_api_key("Usage Test", Role.VIEWER, created_by="test")

    # First verification
    key_info1 = verify_api_key(full_key)
    assert key_info1 is not None

    # Wait briefly
    time.sleep(0.1)

    # Second verification
    key_info2 = verify_api_key(full_key)
    last_used2 = key_info2["last_used_at"]

    # last_used_at should be present
    assert last_used2 is not None


# ---------------------------------------------------------------------------
# Privilege escalation tests (issue #3)
# ---------------------------------------------------------------------------


class TestOperatorRolePermissions:
    """OPERATOR must NOT have API_KEY_MANAGE — prevents privilege escalation."""

    def test_operator_cannot_manage_api_keys(self):
        """OPERATOR role must not include API_KEY_MANAGE permission."""
        assert not has_permission(Role.OPERATOR, Permission.API_KEY_MANAGE)

    def test_admin_can_manage_api_keys(self):
        """ADMIN role must retain API_KEY_MANAGE permission."""
        assert has_permission(Role.ADMIN, Permission.API_KEY_MANAGE)

    def test_viewer_cannot_manage_api_keys(self):
        """VIEWER role must not include API_KEY_MANAGE permission."""
        assert not has_permission(Role.VIEWER, Permission.API_KEY_MANAGE)

    def test_operator_has_expected_permissions(self):
        """OPERATOR should retain scan and finding permissions."""
        assert has_permission(Role.OPERATOR, Permission.SCAN_READ)
        assert has_permission(Role.OPERATOR, Permission.SCAN_WRITE)
        assert has_permission(Role.OPERATOR, Permission.FINDING_READ)
        assert has_permission(Role.OPERATOR, Permission.FINDING_WRITE)

    def test_operator_cannot_delete_scans(self):
        """OPERATOR must not be able to delete scans (ADMIN-only)."""
        assert not has_permission(Role.OPERATOR, Permission.SCAN_DELETE)

    def test_operator_cannot_manage_users(self):
        """OPERATOR must not be able to manage users."""
        assert not has_permission(Role.OPERATOR, Permission.USER_MANAGE)
