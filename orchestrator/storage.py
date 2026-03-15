from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make common package importable when running from the project root
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from common.schema import SCHEMA_SQL, MIGRATIONS as _MIGRATIONS
from orchestrator.db_adapter import adapt_schema, get_connection
from orchestrator.logging_config import get_logger
from orchestrator.models import ScanResult

LOGGER = get_logger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run_migrations(db_path: str) -> None:
    """Apply any schema migrations not yet recorded in schema_migrations."""
    for version, description, sql in _MIGRATIONS:
        with get_connection(db_path) as conn:
            row = conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (version,)).fetchone()
            if row:
                continue
            if sql.strip():
                adapted = adapt_schema(sql)
                for stmt in adapted.split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        conn.execute(stmt)
            conn.execute(
                "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                (version, description, _utc_now()),
            )
        LOGGER.info("schema.migration_applied", version=version, description=description)


def connect(db_path: str):
    """Return a connection wrapper (backward-compatible alias)."""
    return get_connection(db_path)


def init_db(db_path: str) -> None:
    adapted = adapt_schema(SCHEMA_SQL)
    with get_connection(db_path) as conn:
        conn.executescript(adapted)
        conn.commit()
    run_migrations(db_path)
    LOGGER.info("db.initialized", db_path=db_path)


def _to_text(value):
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def save_scan_result(db_path: str, result: ScanResult) -> None:
    counts = result.severity_counts()
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scans (
                id, created_at, finished_at, target_type, target_name, target_value,
                status, policy_status, findings_count, critical_count, high_count,
                medium_count, low_count, info_count, unknown_count, raw_report_dir,
                normalized_report_path, artifacts_json, tools_json, error_message, git_sha
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                finished_at             = excluded.finished_at,
                status                  = excluded.status,
                policy_status           = excluded.policy_status,
                findings_count          = excluded.findings_count,
                critical_count          = excluded.critical_count,
                high_count              = excluded.high_count,
                medium_count            = excluded.medium_count,
                low_count               = excluded.low_count,
                info_count              = excluded.info_count,
                unknown_count           = excluded.unknown_count,
                raw_report_dir          = excluded.raw_report_dir,
                normalized_report_path  = excluded.normalized_report_path,
                artifacts_json          = excluded.artifacts_json,
                tools_json              = excluded.tools_json,
                error_message           = excluded.error_message,
                git_sha                 = excluded.git_sha
            """,
            (
                result.scan_id,
                result.started_at,
                result.finished_at,
                result.target_type,
                result.target_name,
                result.target_value,
                result.status,
                result.policy_status,
                len(result.findings),
                counts.get("CRITICAL", 0),
                counts.get("HIGH", 0),
                counts.get("MEDIUM", 0),
                counts.get("LOW", 0),
                counts.get("INFO", 0),
                counts.get("UNKNOWN", 0),
                result.raw_report_dir,
                result.normalized_report_path,
                json.dumps(result.artifacts, ensure_ascii=False),
                json.dumps([tool.to_dict() for tool in result.tools], ensure_ascii=False),
                result.error_message,
                result.git_sha,
            ),
        )
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (result.scan_id,))
        conn.executemany(
            """
            INSERT INTO findings (
                scan_id, timestamp, target_type, target_name, tool, category, severity,
                title, description, file, line, package, version, cve, remediation,
                raw_reference, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    finding.scan_id,
                    finding.timestamp,
                    finding.target_type,
                    finding.target_name,
                    finding.tool,
                    finding.category,
                    finding.severity,
                    _to_text(finding.title),
                    _to_text(finding.description),
                    _to_text(finding.file),
                    finding.line,
                    _to_text(finding.package),
                    _to_text(finding.version),
                    _to_text(finding.cve),
                    _to_text(finding.remediation),
                    _to_text(finding.raw_reference),
                    _to_text(finding.fingerprint),
                )
                for finding in result.findings
            ],
        )
        conn.commit()
    LOGGER.info("scan.persisted", scan_id=result.scan_id, findings=len(result.findings))


def write_json_file(path: str | Path, payload: dict | list) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def get_last_scan_sha(db_path: str, target_name: str) -> str | None:
    """Return the git_sha of the most recent successful scan for a target, or None."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT git_sha FROM scans
            WHERE target_name = ? AND git_sha IS NOT NULL
              AND status IN ('COMPLETED_CLEAN', 'COMPLETED_WITH_FINDINGS')
            ORDER BY created_at DESC LIMIT 1
            """,
            (target_name,),
        ).fetchone()
    if row:
        return row["git_sha"] or row[0]
    return None
