"""
Authentication middleware for API key validation.
"""
from typing import Optional

from fastapi import Header, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from rbac import Permission, Role, has_permission, verify_api_key, log_audit

security = HTTPBearer(auto_error=False)


class AuthContext:
    """Authentication context for the current request."""
    
    def __init__(self, role: Role, api_key_prefix: Optional[str] = None, user_id: Optional[str] = None):
        self.role = role
        self.api_key_prefix = api_key_prefix
        self.user_id = user_id
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if the current user has a specific permission."""
        return has_permission(self.role, permission)
    
    def require_permission(self, permission: Permission):
        """Raise HTTPException if permission is not granted."""
        if not self.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value} required"
            )


def get_auth_context(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Optional[AuthContext]:
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
    
    # Verify the API key
    key_info = verify_api_key(api_key)
    if not key_info:
        log_audit(
            action="api_key_auth_failed",
            resource=request.url.path,
            result="invalid_key",
            ip_address=request.client.host if request.client else None
        )
        return None
    
    # Log successful authentication
    log_audit(
        action="api_key_auth_success",
        api_key_prefix=key_info["key_prefix"],
        resource=request.url.path,
        result="success",
        ip_address=request.client.host if request.client else None
    )
    
    return AuthContext(
        role=Role(key_info["role"]),
        api_key_prefix=key_info["key_prefix"]
    )


def require_auth(request: Request, authorization: Optional[str] = Header(None)) -> AuthContext:
    """
    Dependency to enforce API key authentication.
    Raises HTTPException if authentication fails.
    """
    auth_context = get_auth_context(request, authorization)
    
    if not auth_context:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return auth_context


def require_permission(permission: Permission):
    """
    Dependency factory to enforce a specific permission.
    Usage: auth = Depends(require_permission(Permission.SCAN_WRITE))
    """
    def _check_permission(auth: AuthContext = require_auth) -> AuthContext:
        auth.require_permission(permission)
        return auth
    return _check_permission
