"""
Health check and monitoring endpoints for Security Scanning Platform Dashboard.
"""
import time
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

router = APIRouter(tags=["monitoring"])

# Application start time
START_TIME = time.time()


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    timestamp: str
    uptime_seconds: float
    version: str
    component: str


class ReadinessResponse(BaseModel):
    """Readiness check response model."""

    ready: bool
    checks: Dict[str, Dict[str, Any]]


@router.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """
    Basic health check endpoint.
    Returns 200 OK if the service is running.
    """
    uptime = time.time() - START_TIME

    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        uptime_seconds=round(uptime, 2),
        version="1.0.0",
        component="dashboard",
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check(response: Response) -> ReadinessResponse:
    """
    Readiness check endpoint.
    Verifies that all dependencies are available.
    """
    checks = {}
    all_ready = True

    # Check database connectivity
    try:
        import os
        from pathlib import Path

        db_path = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")
        if Path(db_path).exists():
            checks["database"] = {"status": "ok", "path": db_path, "exists": True}
        else:
            checks["database"] = {
                "status": "warning",
                "path": db_path,
                "exists": False,
                "message": "Database will be created on first scan",
            }
    except Exception as e:
        checks["database"] = {"status": "error", "error": str(e)}
        all_ready = False

    # Check templates directory
    try:
        from pathlib import Path

        template_dir = Path(__file__).parent / "templates"
        if template_dir.exists():
            checks["templates"] = {"status": "ok", "available": True}
        else:
            checks["templates"] = {"status": "error", "available": False}
            all_ready = False
    except Exception as e:
        checks["templates"] = {"status": "error", "error": str(e)}
        all_ready = False

    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        ready=all_ready,
        checks=checks,
    )


@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """
    Basic metrics endpoint.
    Returns application metrics in JSON format.
    """
    uptime = time.time() - START_TIME

    return {
        "app_uptime_seconds": round(uptime, 2),
        "app_version": "1.0.0",
        "app_name": "security-scanner-dashboard",
        "component": "dashboard",
        "timestamp": datetime.utcnow().isoformat(),
    }
