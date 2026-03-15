"""
Scan runner: subprocess wrapper around the orchestrator CLI.

Extracted from app.py to allow independent unit testing and cleaner imports.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone

from db import get_connection
from logging_config import get_logger
from scan_events import publish_sync

LOGGER = get_logger(__name__)

# Resolved at import time so tests can override via env var
_DB_PATH = os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")


def _db_path() -> str:
    """Return the current DB path (reads env var each call so tests can override)."""
    return os.getenv("DASHBOARD_DB_PATH", "/data/security_scans.db")


def insert_running_scan(scan_id: str, started_at: str, target_type: str, name: str, target: str) -> None:
    """Pre-insert a RUNNING placeholder row so the scan shows up in the list immediately."""
    try:
        with get_connection(_db_path()) as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    id, created_at, finished_at, target_type, target_name, target_value,
                    status, policy_status, findings_count, critical_count, high_count,
                    medium_count, low_count, info_count, unknown_count,
                    raw_report_dir, normalized_report_path, artifacts_json, tools_json
                ) VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', 'PENDING', 0, 0, 0, 0, 0, 0, 0, '', '', '{}', '[]')
                ON CONFLICT(id) DO NOTHING
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

    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{root_dir}:{env.get('PYTHONPATH', '')}"
        env["ORCH_DB_PATH"] = f"{root_dir}/data/security_scans.db"
        env["REPORTS_DIR"] = f"{root_dir}/data/reports"
        env["WORKSPACE_DIR"] = f"{root_dir}/data/workspaces"
        env["ORCH_CACHE_DIR"] = f"{root_dir}/data/cache"
        env["DASHBOARD_DB_PATH"] = f"{root_dir}/data/security_scans.db"

        log_level = os.getenv("LOG_LEVEL", "INFO")

        cmd = [
            "python3",
            "-m",
            "orchestrator.main",
            "--target-type",
            target_type,
            "--target",
            target,
            "--target-name",
            name,
            "--settings",
            f"{root_dir}/config/settings.yaml",
            "--scan-id",
            scan_id,
            "--log-level",
            log_level,
        ]

        # stdout=PIPE captures the JSON result; stderr=None lets orchestrator logs
        # flow to the dashboard process stderr (visible via docker compose logs -f).
        result = subprocess.run(
            cmd,
            cwd=root_dir,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            env=env,
            timeout=1800,
        )

        try:
            output_json = json.loads(result.stdout)
            LOGGER.info("scan.completed", scan_id=scan_id, returncode=result.returncode)
            publish_sync("scan_completed", {"scan_id": scan_id, "target_name": name, "returncode": result.returncode})
            return {"status": "completed", "scan_id": scan_id, "output": output_json, "returncode": result.returncode}
        except json.JSONDecodeError:
            msg = "Failed to parse orchestrator output"
            LOGGER.error("scan.output_parse_error", scan_id=scan_id, returncode=result.returncode)
            update_scan_failed(scan_id, msg)
            publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": msg})
            return {"status": "error", "scan_id": scan_id, "message": msg, "returncode": result.returncode}

    except subprocess.TimeoutExpired:
        msg = "Scan timed out after 30 minutes"
        LOGGER.error("scan.timeout", scan_id=scan_id, name=name)
        update_scan_failed(scan_id, msg)
        publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": msg})
        return {"status": "error", "scan_id": scan_id, "message": msg}
    except Exception as e:
        LOGGER.exception("scan.unexpected_error", scan_id=scan_id, error=str(e))
        update_scan_failed(scan_id, str(e))
        publish_sync("scan_failed", {"scan_id": scan_id, "target_name": name, "error": str(e)})
        return {"status": "error", "scan_id": scan_id, "message": str(e)}
