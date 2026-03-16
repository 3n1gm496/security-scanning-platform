"""
Authentication middleware for API key and session validation.
"""

from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPBearer
from rbac import Permission, Role, has_permission, log_audit, verify_api_key

security = HTTPBearer(auto_error=False)


class AuthContext:
    """Authentication context for the current request."""

    def __init__(
        self,
        role: Role,
        api_key_prefix: Optional[str] = None,
        user_id: Optional[str] = None,
        tenant_id: str = "default",
    ):
        self.role = role
        self.api_key_prefix = api_key_prefix
        self.user_id = user_id
        self.tenant_id = tenant_id

    def has_permission(self, permission: Permission) -> bool:
        """Check if the current user has a specific permission."""
        return has_permission(self.role, permission)

    def require_permission(self, permission: Permission):
        """Raise HTTPException if permission is not granted."""
        if not self.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=f"Permission denied: {permission.value} required"
            )


async def _auth_from_api_key(request: Request, authorization: Optional[str]) -> Optional[AuthContext]:
    """
    Extract and validate API key from the Authorization header.
    Returns AuthContext if valid, None otherwise.

    Header format: Authorization: Bearer ssp_xxxxxxxxxxxxx
    """
    if not authorization:
        return None

    if not authorization.startswith("Bearer "):
        return None

    api_key = authorization.replace("Bearer ", "").strip()

    # Reuse API key data already validated by CSRFMiddleware when available.
    key_info = request.scope.get("auth_api_key_info")
    if key_info is None:
        key_info = verify_api_key(api_key)
    if not key_info:
        log_audit(
            action="api_key_auth_failed",
            resource=request.url.path,
            result="invalid_key",
            ip_address=request.client.host if request.client else None,
        )
        return None

    # Log successful authentication
    log_audit(
        action="api_key_auth_success",
        api_key_prefix=key_info["key_prefix"],
        resource=request.url.path,
        result="success",
        ip_address=request.client.host if request.client else None,
    )

    return AuthContext(
        role=Role(key_info["role"]),
        api_key_prefix=key_info["key_prefix"],
        tenant_id=key_info.get("tenant_id", "default"),
    )


async def _auth_from_session(request: Request) -> Optional[AuthContext]:
    """
    Extract authentication from the session cookie.
    Returns AuthContext with the session role if a valid session is found, None otherwise.
    """
    user = request.session.get("user")
    if not user:
        return None
    session_role = request.session.get("role", Role.ADMIN.value)
    try:
        role = Role(session_role)
    except ValueError:
        role = Role.ADMIN
    return AuthContext(role=role, user_id=user)


async def get_auth_context(request: Request, authorization: Optional[str] = Header(None)) -> Optional[AuthContext]:
    """
    Try session first, then API key.
    Returns AuthContext if either method succeeds, None otherwise.
    """
    # 1. Session-based auth (browser UI)
    ctx = await _auth_from_session(request)
    if ctx:
        return ctx
    # 2. API key auth (programmatic access)
    return await _auth_from_api_key(request, authorization)


async def require_auth(request: Request, authorization: Optional[str] = Header(None)) -> AuthContext:
    """
    Dependency to enforce authentication via session or API key.
    Raises HTTPException(401) if neither method succeeds.
    """
    auth_context = await get_auth_context(request, authorization)

    if not auth_context:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return auth_context


def require_permission(permission: Permission):
    """
    Dependency factory to enforce a specific permission.
    Usage: auth = Depends(require_permission(Permission.SCAN_WRITE))
    """

    async def _check_permission(auth: AuthContext = Depends(require_auth)) -> AuthContext:
        auth.require_permission(permission)
        return auth

    return _check_permission
