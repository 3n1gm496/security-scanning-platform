"""
Health check and monitoring endpoints for Security Scanning Platform Dashboard.
"""

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict

from auth import AuthContext, require_auth
from fastapi import APIRouter, Depends, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel
from runtime_config import DASHBOARD_DB_PATH

router = APIRouter(tags=["monitoring"])

# Application start time
START_TIME = time.time()

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
# Guard against duplicate-registration errors when modules are reloaded in
# tests. prometheus_client raises ValueError if a metric name is registered
# twice in the same process.


def _get_or_create_counter(name: str, documentation: str, labelnames=()) -> Counter:
    try:
        return Counter(name, documentation, labelnames)
    except ValueError:
        return REGISTRY._names_to_collectors[name]  # type: ignore[return-value]


def _get_or_create_histogram(name: str, documentation: str, buckets=None) -> Histogram:
    kwargs = {"buckets": buckets} if buckets else {}
    try:
        return Histogram(name, documentation, **kwargs)
    except ValueError:
        return REGISTRY._names_to_collectors[name]  # type: ignore[return-value]


def _get_or_create_gauge(name: str, documentation: str, labelnames=()) -> Gauge:
    try:
        return Gauge(name, documentation, labelnames)
    except ValueError:
        return REGISTRY._names_to_collectors[name]  # type: ignore[return-value]


SSP_SCANS_TOTAL: Counter = _get_or_create_counter(
    "ssp_scans_total",
    "Total number of scans completed, partitioned by status and policy result",
    ["status", "policy_status"],
)

SSP_SCAN_DURATION_SECONDS: Histogram = _get_or_create_histogram(
    "ssp_scan_duration_seconds",
    "Scan duration in seconds",
    buckets=[10, 30, 60, 120, 300, 600, 1800, 3600],
)

SSP_FINDINGS_TOTAL: Gauge = _get_or_create_gauge(
    "ssp_findings_total",
    "Current total number of findings in the database, partitioned by severity",
    ["severity"],
)

SSP_API_REQUESTS_TOTAL: Counter = _get_or_create_counter(
    "ssp_api_requests_total",
    "Total HTTP requests to the dashboard API",
    ["method", "path", "status_code"],
)

SSP_ACTIVE_SCAN_WORKERS: Gauge = _get_or_create_gauge(
    "ssp_active_scan_workers",
    "Number of currently running background scan workers",
)

SSP_WEBHOOK_DELIVERIES_TOTAL: Counter = _get_or_create_counter(
    "ssp_webhook_deliveries_total",
    "Total webhook delivery attempts, partitioned by status",
    ["status"],
)

SSP_WEBHOOK_LATENCY_SECONDS: Histogram = _get_or_create_histogram(
    "ssp_webhook_latency_seconds",
    "Webhook delivery latency in seconds",
    buckets=[0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
)

SSP_CACHE_OPERATIONS_TOTAL: Counter = _get_or_create_counter(
    "ssp_cache_operations_total",
    "Orchestrator cache operations, partitioned by result (hit/miss)",
    ["result"],
)


# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _app_version() -> str:
    """Return the application version from env or package metadata."""
    v = os.getenv("APP_VERSION", "")
    if v:
        return v
    try:
        import importlib.metadata

        return importlib.metadata.version("security-scanning-platform")
    except Exception:
        return "dev"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check(response: Response) -> HealthResponse:
    """
    Deep health check endpoint.
    Verifies the service is running and the database is accessible.
    Returns 200 OK if healthy, 503 if DB is unreachable.
    """
    uptime = time.time() - START_TIME
    health_status = "healthy"

    # Verify database connectivity with a real query
    try:
        db_path = os.getenv("DASHBOARD_DB_PATH", DASHBOARD_DB_PATH)
        from db import get_connection

        with get_connection(db_path) as conn:
            conn.execute("SELECT 1")
    except Exception:
        health_status = "degraded"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status=health_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        uptime_seconds=round(uptime, 2),
        version=_app_version(),
        component="dashboard",
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check(response: Response) -> ReadinessResponse:
    """
    Readiness check endpoint.
    Verifies that all dependencies are available.
    """
    checks: dict[str, dict[str, Any]] = {}
    all_ready = True

    # Check database connectivity
    try:
        from pathlib import Path

        db_path = os.getenv("DASHBOARD_DB_PATH", DASHBOARD_DB_PATH)
        if Path(db_path).exists():
            checks["database"] = {"status": "ok", "exists": True}
        else:
            checks["database"] = {
                "status": "warning",
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


@router.get("/metrics/json")
async def metrics_json(auth: AuthContext = Depends(require_auth)) -> Dict[str, Any]:
    """
    Basic metrics in JSON format (for dashboards that prefer JSON over Prometheus text).
    For Prometheus scraping use GET /api/metrics instead.
    """
    uptime = time.time() - START_TIME

    return {
        "app_uptime_seconds": round(uptime, 2),
        "app_version": _app_version(),
        "app_name": "security-scanner-dashboard",
        "component": "dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/metrics",
    response_class=Response,
    summary="Prometheus metrics",
    description=(
        "Prometheus-compatible metrics endpoint. Configure your Prometheus server to scrape this path.\n\n"
        "Metrics exported:\n"
        "- `ssp_scans_total{status,policy_status}` — scan completion counter\n"
        "- `ssp_scan_duration_seconds` — scan duration histogram\n"
        "- `ssp_findings_total{severity}` — current findings gauge (refreshed on scrape)\n"
        "- `ssp_api_requests_total{method,path,status_code}` — HTTP request counter\n"
        "- `ssp_active_scan_workers` — active background scan worker gauge\n"
        "- Standard `process_*` and `python_*` metrics"
    ),
)
async def prometheus_metrics(auth: AuthContext = Depends(require_auth)) -> Response:
    """Expose Prometheus metrics for scraping."""
    # Refresh the findings gauge from the DB on each scrape.
    # This is a cheap aggregation query (indexed by severity).
    try:
        db_path = os.getenv("DASHBOARD_DB_PATH", DASHBOARD_DB_PATH)
        from db import get_connection

        with get_connection(db_path) as conn:
            rows = conn.execute("SELECT severity, COUNT(*) AS cnt FROM findings GROUP BY severity").fetchall()
        for row in rows:
            SSP_FINDINGS_TOTAL.labels(severity=row["severity"]).set(row["cnt"])
    except Exception:
        # Non-fatal: a failed DB query must not break the metrics scrape.
        pass

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
