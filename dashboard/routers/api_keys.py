"""API key management routes: GET/POST/DELETE /api/keys."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException
from starlette import status

from auth import require_auth, require_permission, AuthContext
from rbac import Role, Permission, create_api_key, list_api_keys, revoke_api_key, log_audit

router = APIRouter(prefix="/api", tags=["api-keys"])


@router.get("/keys", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def get_api_keys(auth: AuthContext = Depends(require_auth)) -> list[dict]:
    """List all API keys (admin/operator only)."""
    return list_api_keys()


@router.post("/keys", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def create_new_api_key(
    name: str = Form(...),
    role: str = Form(...),
    expires_days: int | None = Form(None),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """Create a new API key (admin only -- privilege ceiling enforced)."""
    try:
        role_enum = Role(role)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role: {role}")

    # Role-ceiling: a caller may only create keys for roles <= their own.
    # Role hierarchy: ADMIN > OPERATOR > VIEWER
    _ROLE_RANK: dict[Role, int] = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}
    caller_rank = _ROLE_RANK.get(auth.role, 0)
    target_rank = _ROLE_RANK.get(role_enum, 0)
    if target_rank > caller_rank:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot create a key with role '{role_enum.value}': exceeds your role ({auth.role.value})",
        )

    full_key, prefix = create_api_key(
        name=name, role=role_enum, expires_days=expires_days, created_by=auth.api_key_prefix or auth.user_id
    )

    log_audit(
        action="api_key.create",
        user_id=auth.user_id,
        api_key_prefix=auth.api_key_prefix,
        resource=f"key:{prefix}",
        result="success",
    )

    return {
        "key": full_key,
        "prefix": prefix,
        "role": role,
        "name": name,
        "warning": "Store this key securely! It will not be shown again.",
    }


@router.delete("/keys/{key_prefix}", dependencies=[Depends(require_permission(Permission.API_KEY_MANAGE))])
def delete_api_key(key_prefix: str, auth: AuthContext = Depends(require_auth)) -> dict:
    """Revoke an API key (admin/operator only)."""
    success = revoke_api_key(key_prefix)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    log_audit(
        action="api_key.revoke",
        user_id=auth.user_id,
        api_key_prefix=auth.api_key_prefix,
        resource=f"key:{key_prefix}",
        result="success",
    )

    return {"status": "revoked", "key_prefix": key_prefix}
