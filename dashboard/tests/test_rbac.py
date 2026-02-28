"""
Test per il sistema RBAC e API keys.
"""
import os
import sqlite3
from pathlib import Path

import pytest

from rbac import (
    Role,
    Permission,
    init_rbac_tables,
    create_api_key,
    verify_api_key,
    has_permission,
    list_api_keys,
    revoke_api_key,
    hash_api_key,
)


@pytest.fixture
def db_setup(isolated_db):
    """Setup test database."""
    init_rbac_tables()
    yield isolated_db


def test_init_rbac_tables(db_setup):
    """Test che le tabelle RBAC siano create correttamente."""
    conn = sqlite3.connect(os.environ["DASHBOARD_DB_PATH"])
    cursor = conn.cursor()
    
    # Verifica tabella api_keys
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys'")
    assert cursor.fetchone() is not None
    
    # Verifica tabella users
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    assert cursor.fetchone() is not None
    
    # Verifica tabella audit_log
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
    assert cursor.fetchone() is not None
    
    conn.close()


def test_create_and_verify_api_key(db_setup):
    """Test creazione e verifica API key."""
    full_key, prefix = create_api_key(
        name="Test Key",
        role=Role.ADMIN,
        created_by="test_user"
    )
    
    assert full_key.startswith("ssp_")
    assert len(full_key) == 68  # ssp_ + 64 hex chars
    assert prefix == full_key[:12]
    
    # Verifica la key
    key_info = verify_api_key(full_key)
    assert key_info is not None
    assert key_info["name"] == "Test Key"
    assert key_info["role"] == Role.ADMIN.value
    assert key_info["is_active"] == 1


def test_verify_invalid_api_key(db_setup):
    """Test che chiavi invalide ritornino None."""
    invalid_key = "ssp_invalid_key_0000000000000000000000000000000000000000000000000000000000000000"
    key_info = verify_api_key(invalid_key)
    assert key_info is None


def test_api_key_expiration(db_setup):
    """Test che le chiavi scadute non siano valide."""
    full_key, prefix = create_api_key(
        name="Expiring Key",
        role=Role.VIEWER,
        expires_days=-1,  # Già scaduta
        created_by="test_user"
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


def test_api_key_hash_consistency():
    """Test che l'hash sia consistente."""
    key = "ssp_test_key_0000000000000000000000000000000000000000000000000000000000000000"
    hash1 = hash_api_key(key)
    hash2 = hash_api_key(key)
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256


def test_api_key_last_used_update(db_setup):
    """Test che last_used_at sia aggiornato."""
    import time
    
    full_key, prefix = create_api_key("Usage Test", Role.VIEWER, created_by="test")
    
    # Prima verifica
    key_info1 = verify_api_key(full_key)
    assert key_info1 is not None
    
    # Aspetta un attimo
    time.sleep(0.1)
    
    # Seconda verifica
    key_info2 = verify_api_key(full_key)
    last_used2 = key_info2["last_used_at"]
    
    # last_used_at dovrebbe essere presente
    assert last_used2 is not None
