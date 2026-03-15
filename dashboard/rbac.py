"""
RBAC (Role-Based Access Control) implementation with API key authentication.
"""

import hashlib
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import bcrypt

from db import get_connection
from db_adapter import adapt_schema, is_postgres

# Database path
DASHBOARD_DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")
_DEFAULT_ADMIN_KEY_LOCK = threading.Lock()


class Role(str, Enum):
    """Available roles in the system."""

    ADMIN = "admin"
    VIEWER = "viewer"
    OPERATOR = "operator"


class Permission(str, Enum):
    """Available permissions in the system."""

    SCAN_READ = "scan:read"
    SCAN_WRITE = "scan:write"
    SCAN_DELETE = "scan:delete"
    FINDING_READ = "finding:read"
    FINDING_WRITE = "finding:write"
    USER_MANAGE = "user:manage"
    API_KEY_MANAGE = "apikey:manage"


# Role -> Permissions mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.SCAN_READ,
        Permission.SCAN_WRITE,
        Permission.SCAN_DELETE,
        Permission.FINDING_READ,
        Permission.FINDING_WRITE,
        Permission.USER_MANAGE,
        Permission.API_KEY_MANAGE,
    ],
    Role.OPERATOR: [
        Permission.SCAN_READ,
        Permission.SCAN_WRITE,
        Permission.FINDING_READ,
        Permission.FINDING_WRITE,
        # API_KEY_MANAGE intentionally excluded: operators must not be able to
        # create keys with elevated roles (privilege escalation via key creation).
    ],
    Role.VIEWER: [
        Permission.SCAN_READ,
        Permission.FINDING_READ,
    ],
}


def init_rbac_tables():
    """Initialize RBAC tables in the database."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        conn.execute(adapt_schema("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                expires_at TEXT,
                is_active INTEGER DEFAULT 1,
                created_by TEXT
            )
        """))

        conn.execute(adapt_schema("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT,
                is_active INTEGER DEFAULT 1
            )
        """))

        conn.execute(adapt_schema("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                api_key_prefix TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                result TEXT,
                ip_address TEXT
            )
        """))


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key.
    Returns (full_key, key_prefix).
    Format: ssp_<random_32_hex>
    """
    random_part = secrets.token_hex(32)
    full_key = f"ssp_{random_part}"
    prefix = full_key[:12]  # ssp_xxxxxxxx
    return full_key, prefix


def hash_api_key(key: str) -> str:
    """Hash an API key using bcrypt (brute-force resistant)."""
    return bcrypt.hashpw(key.encode(), bcrypt.gensalt()).decode()


def _verify_key_hash(key: str, stored_hash: str) -> bool:
    """Verify a key against a stored hash.

    Supports both bcrypt (new) and SHA-256 (legacy) hashes for backward
    compatibility during the migration period.
    Returns True if the key matches. Legacy SHA-256 hashes will be
    transparently upgraded to bcrypt by verify_api_key().
    """
    if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
        try:
            return bcrypt.checkpw(key.encode(), stored_hash.encode())
        except Exception:
            return False
    # Legacy SHA-256 fallback
    return secrets.compare_digest(hashlib.sha256(key.encode()).hexdigest(), stored_hash)


def create_api_key(
    name: str, role: Role, expires_days: Optional[int] = None, created_by: Optional[str] = None
) -> tuple[str, str]:
    """
    Create a new API key.
    Returns (full_key, key_prefix).
    """
    full_key, prefix = generate_api_key()
    key_hash = hash_api_key(full_key)

    created_at = datetime.now(timezone.utc).isoformat()
    expires_at = None
    if expires_days:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

    with get_connection(DASHBOARD_DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO api_keys (key_hash, key_prefix, name, role, created_at, expires_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (key_hash, prefix, name, role.value, created_at, expires_at, created_by),
        )

    return full_key, prefix


def verify_api_key(key: str) -> Optional[dict]:
    """
    Verify an API key and return its details.
    Returns None if key is invalid, expired, or inactive.

    Uses the key prefix (first 12 chars) as a fast DB filter, then verifies
    the full key against the stored bcrypt (or legacy SHA-256) hash.
    """
    prefix = key[:12] if len(key) >= 12 else key

    with get_connection(DASHBOARD_DB_PATH) as conn:
        rows = conn.execute(
            "SELECT * FROM api_keys WHERE key_prefix = ? AND is_active = 1",
            (prefix,),
        ).fetchall()

        for row in rows:
            if not _verify_key_hash(key, row["key_hash"]):
                continue

            # Transparently upgrade legacy SHA-256 hashes to bcrypt on successful verification.
            stored_hash = row["key_hash"]
            if not (stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$")):
                new_hash = hash_api_key(key)
                conn.execute(
                    "UPDATE api_keys SET key_hash = ? WHERE id = ?",
                    (new_hash, row["id"]),
                )

            # Check expiration
            if row["expires_at"]:
                expires_at = datetime.fromisoformat(row["expires_at"])
                if datetime.now(timezone.utc) > expires_at:
                    return None

            # Update last_used_at
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), row["id"]),
            )
            return dict(row)

    return None


def has_permission(role: Role, permission: Permission) -> bool:
    """Check if a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, [])


def _verify_password_hash(password: str, stored_hash: str) -> bool:
    """Verify a dashboard user password hash.

    Supports bcrypt hashes and a legacy plain-text fallback for older setups.
    """
    if not stored_hash:
        return False
    if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False
    return secrets.compare_digest(password, stored_hash)


def verify_user_credentials(username: str, password: str) -> Optional[dict]:
    """Verify an active dashboard user from the users table."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()
        if not row:
            return None
        if not _verify_password_hash(password, row["password_hash"]):
            return None
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), row["id"]),
        )
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
    }


def list_api_keys() -> list[dict]:
    """List all API keys (without sensitive data)."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        rows = conn.execute("""
            SELECT id, key_prefix, name, role, created_at, last_used_at, expires_at, is_active, created_by
            FROM api_keys
            ORDER BY created_at DESC
        """).fetchall()
    return [dict(row) for row in rows]


def revoke_api_key(key_prefix: str) -> bool:
    """Revoke (deactivate) an API key by prefix."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE api_keys SET is_active = 0 WHERE key_prefix = ?",
            (key_prefix,),
        )
    return cursor.rowcount > 0


def log_audit(
    action: str,
    user_id: Optional[str] = None,
    api_key_prefix: Optional[str] = None,
    resource: Optional[str] = None,
    result: str = "success",
    ip_address: Optional[str] = None,
):
    """Log an audit event."""
    with get_connection(DASHBOARD_DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_log (timestamp, user_id, api_key_prefix, action, resource, result, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (datetime.now(timezone.utc).isoformat(), user_id, api_key_prefix, action, resource, result, ip_address),
        )


def purge_audit_log(retention_days: int = 90) -> int:
    """Delete audit log entries older than retention_days.

    Returns the number of rows deleted.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    with get_connection(DASHBOARD_DB_PATH) as conn:
        if is_postgres():
            cursor = conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff.isoformat(),))
        else:
            cursor = conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?",
                (cutoff.date().isoformat(),),
            )
    return cursor.rowcount


def create_default_admin_key():
    """Create a default admin API key if no keys exist."""
    with _DEFAULT_ADMIN_KEY_LOCK:
        with get_connection(DASHBOARD_DB_PATH) as conn:
            count = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
            if count != 0:
                return None

        full_key, prefix = create_api_key(name="Default Admin Key", role=Role.ADMIN, created_by="system")
        return full_key
    return None
