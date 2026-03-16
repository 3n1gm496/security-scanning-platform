"""FastAPI router modules for the security scanning dashboard."""

from .analytics_routes import router as analytics_router
from .api_keys import router as api_keys_router
from .audit_routes import router as audit_router
from .auth_routes import router as auth_router
from .export_routes import router as export_router
from .finding_routes import router as finding_router
from .notification_routes import router as notification_router
from .scan_routes import router as scan_router
from .webhook_routes import router as webhook_router

__all__ = [
    "auth_router",
    "api_keys_router",
    "webhook_router",
    "export_router",
    "analytics_router",
    "scan_router",
    "finding_router",
    "notification_router",
    "audit_router",
]
