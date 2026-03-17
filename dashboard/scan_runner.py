"""
Scan runner: subprocess wrapper around the orchestrator CLI.

Extracted from app.py to allow independent unit testing and cleaner imports.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
import sys
import uuid
from datetime import datetime, timezone
from time import monotonic
from pathlib import Path

from db import get_connection
from db_adapter import is_postgres
from logging_config import get_logger
from monitoring import record_cache_operation, record_scan_metric
from runtime_config import DASHBOARD_DB_PATH
from scan_events import publish_sync

LOGGER = get_logger(__name__)


def _db_path() -> str:
    """Return the current DB path (reads env var each call so tests can override)."""
    return os.getenv("DASHBOARD_DB_PATH", DASHBOARD_DB_PATH)


def _extract_primary_result(payload: dict) -> dict:
    """Return the primary orchestrator result item from the aggregate JSON payload."""
    results = payload.get("results")
    if isinstance(results, list) and results:
        first = results[0]
        if isinstance(first, dict):
            return first
    return {}


def _record_cache_metrics(payload: dict) -> None:
    """Update cache hit/miss counters from orchestrator result payloads."""
    results = payload.get("results")
    if not isinstance(results, list):
        return
    for result in results:
        if not isinstance(result, dict):
            continue
        tools = result.get("tools")
        if not isinstance(tools, list):
            continue
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            record_cache_operation("hit" if tool.get("cache_hit") else "miss")


def insert_running_scan(scan_id: str, started_at: str, target_type: str, name: str, target: str) -> None:
    """Pre-insert a RUNNING placeholder row so the scan shows up in the list immediately."""
    try:
        with get_connection(_db_path()) as conn:
            if is_postgres():
                conn.execute(
                    """
                    INSERT INTO scans (
                        id, created_at, finished_at, target_type, target_name, target_value,
                        status, policy_status, findings_count, critical_count, high_count,
                        medium_count, low_count, info_count, unknown_count,
                        raw_report_dir, normalized_report_path, artifacts_json, tools_json
                    ) VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', 'PENDING', 0, 0, 0, 0, 0, 0, 0, '', '', '{}', '[]')
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (scan_id, started_at, started_at, target_type, name, target),
                )
            else:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO scans (
                        id, created_at, finished_at, target_type, target_name, target_value,
                        status, policy_status, findings_count, critical_count, high_count,
                        medium_count, low_count, info_count, unknown_count,
                        raw_report_dir, normalized_report_path, artifacts_json, tools_json
                    ) VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', 'PENDING', 0, 0, 0, 0, 0, 0, 0, '', '', '{}', '[]')
                    """,
                    (scan_id, started_at, started_at, target_type, name, target),
                )
    except Exception:
        LOGGER.warning("insert_running_scan failed for %s", scan_id, exc_info=True)


def update_scan_failed(scan_id: str, error_message: str) -> None:
    """Update a RUNNING scan to FAILED when the subprocess exits abnormally."""
    try:
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        with get_connection(_db_path()) as conn:
            conn.execute(
                "UPDATE scans SET status='FAILED', finished_at=?, error_message=? WHERE id=? AND status='RUNNING'",
                (now, error_message, scan_id),
            )
    except Exception:
        LOGGER.warning("update_scan_failed failed for %s", scan_id, exc_info=True)


def run_scan(
    target_type: str,
    target: str,
    name: str,
    root_dir: str,
    scan_id: str | None = None,
    started_at: str | None = None,
) -> dict:
    """Execute the orchestrator subprocess and return a status dict.

    Args:
        target_type: 'local', 'git', 'image', or 'url'
        target: path, git URL, image reference, or web URL to scan
        name: display name for the target
        root_dir: repository root directory (passed as cwd and for PYTHONPATH)
        scan_id: pre-assigned UUID (generated if None)
        started_at: ISO timestamp (generated if None)

    Returns:
        dict with keys: status, output (on success), message (on error), returncode
    """
    scan_id = scan_id or str(uuid.uuid4())
    started_at = started_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    insert_running_scan(scan_id, started_at, target_type, name, target)
    LOGGER.info("scan.starting", scan_id=scan_id, name=name, target=target, target_type=target_type)
    publish_sync("scan_started", {"scan_id": scan_id, "target_name": name, "target_type": target_type})
    started_monotonic = monotonic()

    try:
        resolved_root_dir = Path(root_dir).resolve()
        settings_path = resolved_root_dir / "config" / "settings.yaml"

        env = os.environ.copy()
        env["PYTHONPATH"] = f"{resolved_root_dir}:{env.get('PYTHONPATH', '')}"
        dashboard_db_path = _db_path()
        env["ORCH_DB_PATH"] = dashboard_db_path
        env["REPORTS_DIR"] = os.getenv("REPORTS_DIR", f"{resolved_root_dir}/data/reports")
        env["WORKSPACE_DIR"] = os.getenv("WORKSPACE_DIR", f"{resolved_root_dir}/data/workspaces")
        env["ORCH_CACHE_DIR"] = os.getenv("ORCH_CACHE_DIR", f"{resolved_root_dir}/data/cache")
        env["DASHBOARD_DB_PATH"] = dashboard_db_path

        log_level = os.getenv("LOG_LEVEL", "INFO")

        cmd = [
            sys.executable,
            "-m",
            "orchestrator.main",
            "--target-type",
            target_type,
            "--target",
            target,
            "--target-name",
            name,
            "--settings",
            str(settings_path),
            "--scan-id",
            scan_id,
            "--log-level",
            log_level,
        ]

        # stdout=PIPE captures the JSON result; stderr=None lets orchestrator logs
        # flow to the dashboard process stderr (visible via docker compose logs -f).
        # Command argv is passed as a list with shell=False to the local orchestrator module.
        result = subprocess.run(  # nosec B603
            cmd,
            cwd=str(resolved_root_dir),
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            env=env,
            timeout=1800,
        )

        try:
            output_json = json.loads(result.stdout)
            primary_result = _extract_primary_result(output_json)
            _record_cache_metrics(output_json)
            duration_seconds = monotonic() - started_monotonic
            if result.returncode == 0:
                record_scan_metric(
                    primary_result.get("status") or "COMPLETED",
                    primary_result.get("policy_status") or "UNKNOWN",
                    duration_seconds,
                )
                LOGGER.info("scan.completed", scan_id=scan_id, returncode=result.returncode)
                publish_sync(
                    "scan_completed", {"scan_id": scan_id, "target_name": name, "returncode": result.returncode}
                )
                return {
                    "status": "completed",
                    "scan_id": scan_id,
                    "output": output_json,
                    "returncode": result.returncode,
                }

            if primary_result.get("status") == "BLOCK" or result.returncode == 3:
                msg = primary_result.get("error_message") or "Scan blocked by policy"
                record_scan_metric(
                    primary_result.get("status") or "BLOCKED",
                    primary_result.get("policy_status") or "BLOCK",
                    duration_seconds,
                )
                LOGGER.warning("scan.blocked", scan_id=scan_id, returncode=result.returncode, message=msg)
                publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": msg})
                return {
                    "status": "blocked",
                    "scan_id": scan_id,
                    "message": msg,
                    "output": output_json,
                    "returncode": result.returncode,
                }

            msg = primary_result.get("error_message") or f"Orchestrator exited with code {result.returncode}"
            record_scan_metric(
                primary_result.get("status") or "FAILED",
                primary_result.get("policy_status") or "UNKNOWN",
                duration_seconds,
            )
            LOGGER.error("scan.failed", scan_id=scan_id, returncode=result.returncode, message=msg)
            update_scan_failed(scan_id, msg)
            publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": msg})
            return {
                "status": "error",
                "scan_id": scan_id,
                "message": msg,
                "output": output_json,
                "returncode": result.returncode,
            }
        except json.JSONDecodeError:
            msg = "Failed to parse orchestrator output"
            record_scan_metric("FAILED", "UNKNOWN", monotonic() - started_monotonic)
            LOGGER.error("scan.output_parse_error", scan_id=scan_id, returncode=result.returncode)
            update_scan_failed(scan_id, msg)
            publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": msg})
            return {"status": "error", "scan_id": scan_id, "message": msg, "returncode": result.returncode}

    except subprocess.TimeoutExpired:
        msg = "Scan timed out after 30 minutes"
        record_scan_metric("FAILED", "UNKNOWN", monotonic() - started_monotonic)
        LOGGER.error("scan.timeout", scan_id=scan_id, name=name)
        update_scan_failed(scan_id, msg)
        publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": msg})
        return {"status": "error", "scan_id": scan_id, "message": msg}
    except Exception as e:
        record_scan_metric("FAILED", "UNKNOWN", monotonic() - started_monotonic)
        LOGGER.exception("scan.unexpected_error", scan_id=scan_id, error=str(e))
        update_scan_failed(scan_id, str(e))
        publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": str(e)})
        return {"status": "error", "scan_id": scan_id, "message": str(e)}
