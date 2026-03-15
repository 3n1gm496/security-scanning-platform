from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import shutil
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from orchestrator.cache import build_cache_key, load_cached_output, store_cached_output
from orchestrator.models import ScanResult, TargetSpec, ToolExecutionResult
from orchestrator.normalizer import (
    normalize_checkov,
    normalize_gitleaks,
    normalize_semgrep,
    normalize_trivy,
    normalize_bandit,
    normalize_nuclei,
    normalize_grype,
    normalize_zap,
    sbom_metadata,
)
from orchestrator.retention import apply_retention
from orchestrator.compatibility import get_compatible_scanners, preflight_check
from orchestrator.scanners import (
    ScannerError,
    clone_repo,
    get_git_commit_sha,
    load_json,
    run_checkov,
    run_gitleaks,
    run_semgrep,
    run_syft,
    run_trivy_fs,
    run_trivy_image,
    run_bandit,
    run_nuclei,
    run_grype,
    run_owasp_zap,
)
from orchestrator.storage import init_db, save_scan_result, write_json_file
from orchestrator.policy_engine import load_policy_engine

LOGGER = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def setup_logging(level: str = "INFO") -> None:
    from orchestrator.logging_config import configure_logging

    configure_logging(level)


def load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _safe_int(value: str, default: int) -> int:
    """Parse an integer from a string, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def resolve_settings(path: str) -> dict[str, Any]:
    settings = load_yaml(path)
    settings.setdefault("paths", {})
    settings.setdefault("scanners", {})
    settings.setdefault("policy", {})
    settings.setdefault("execution", {})
    settings.setdefault("cache", {})
    settings.setdefault("retention", {})
    # Environment variables have priority over settings.yaml
    settings["paths"]["db_path"] = os.getenv(
        "ORCH_DB_PATH", settings["paths"].get("db_path", "/data/security_scans.db")
    )
    settings["paths"]["reports_dir"] = os.getenv("REPORTS_DIR", settings["paths"].get("reports_dir", "/data/reports"))
    settings["paths"]["workspace_dir"] = os.getenv(
        "WORKSPACE_DIR", settings["paths"].get("workspace_dir", "/data/workspaces")
    )
    settings["scanners"].setdefault("semgrep", {"enabled": True, "configs": ["p/default"]})
    settings["scanners"].setdefault(
        "trivy", {"enabled": True, "severities": ["CRITICAL", "HIGH", "MEDIUM"], "ignore_unfixed": False}
    )
    settings["scanners"].setdefault("gitleaks", {"enabled": True})
    settings["scanners"].setdefault("checkov", {"enabled": True})
    settings["scanners"].setdefault("syft", {"enabled": True})
    settings["scanners"].setdefault("bandit", {"enabled": False})
    settings["scanners"].setdefault("nuclei", {"enabled": False, "templates": []})
    settings["scanners"].setdefault("grype", {"enabled": False})
    # Environment variable overrides for ZAP (useful in docker-compose)
    # ZAP_API_URL auto-enables the scanner; ZAP_API_KEY sets the API key.
    _zap = settings["scanners"].setdefault("owasp_zap", {"enabled": False})
    if os.getenv("ZAP_API_URL"):
        _zap["api_url"] = os.getenv("ZAP_API_URL")
        _zap["enabled"] = True  # auto-enable when ZAP URL is provided
    if os.getenv("ZAP_API_KEY") is not None:
        _zap["api_key"] = os.getenv("ZAP_API_KEY", "")
    settings["policy"].setdefault("block_on_severities", ["CRITICAL"])
    settings["policy"].setdefault("block_on_secret_categories", True)
    settings["execution"].setdefault(
        "max_concurrent_targets", _safe_int(os.getenv("ORCH_MAX_CONCURRENT_TARGETS", "2"), 2)
    )
    # git_clone_depth: 0 = full history (recommended for secret scanning via gitleaks).
    # Set to a positive integer for shallow clones in bandwidth-constrained environments.
    settings["execution"].setdefault("git_clone_depth", _safe_int(os.getenv("ORCH_GIT_CLONE_DEPTH", "0"), 0))
    settings["cache"].setdefault(
        "enabled", os.getenv("ORCH_CACHE_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
    )
    settings["cache"].setdefault("ttl_seconds", _safe_int(os.getenv("ORCH_CACHE_TTL_SECONDS", "900"), 900))
    settings["cache"]["dir"] = os.getenv("ORCH_CACHE_DIR", settings["cache"].get("dir", "/data/cache/orchestrator"))
    settings["retention"].setdefault(
        "enabled", os.getenv("ORCH_RETENTION_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
    )
    settings["retention"].setdefault("reports_days", _safe_int(os.getenv("ORCH_RETENTION_REPORTS_DAYS", "14"), 14))
    settings["retention"].setdefault("workspaces_days", _safe_int(os.getenv("ORCH_RETENTION_WORKSPACES_DAYS", "3"), 3))
    settings["retention"].setdefault("cache_days", _safe_int(os.getenv("ORCH_RETENTION_CACHE_DAYS", "7"), 7))
    return settings


def resolve_targets(args: argparse.Namespace) -> list[TargetSpec]:
    targets: list[TargetSpec] = []
    if args.targets_file:
        data = load_yaml(args.targets_file)
        for item in data.get("targets", []):
            spec = TargetSpec.from_dict(item)
            if spec.enabled:
                targets.append(spec)
        return targets

    if not args.target or not args.target_type:
        raise ValueError("Either --targets-file or both --target-type and --target are required")

    payload = {
        "name": args.target_name or args.target,
        "type": args.target_type,
        "path": args.target if args.target_type == "local" else None,
        "repo": args.target if args.target_type == "git" else None,
        "image": args.target if args.target_type == "image" else None,
        "url": args.target if args.target_type == "url" else None,
        "ref": args.ref,
        "enabled": True,
    }
    targets.append(TargetSpec.from_dict(payload))
    return targets


def prepare_target(target: TargetSpec, settings: dict[str, Any], scan_id: str) -> tuple[str, str, str | None]:
    """Prepare the scan workspace and return (target_input, target_value, git_sha).

    git_sha is the HEAD commit SHA for git targets (used to bust the cache when
    new commits are pushed within the TTL window). It is None for all other target types.
    """
    workspace_root = Path(settings["paths"]["workspace_dir"])
    workspace_root.mkdir(parents=True, exist_ok=True)

    if target.type == "git":
        destination = workspace_root / scan_id / "repo"
        clone_depth = int(settings.get("execution", {}).get("git_clone_depth", 0))
        try:
            clone_repo(target.repo or "", str(destination), target.ref, depth=clone_depth)
        except Exception:
            # Clean up partial workspace to avoid disk leaks
            scan_workspace = workspace_root / scan_id
            if scan_workspace.exists():
                shutil.rmtree(scan_workspace, ignore_errors=True)
                LOGGER.warning("Cleaned up partial workspace for scan_id=%s after clone failure", scan_id)
            raise
        git_sha = get_git_commit_sha(str(destination))
        LOGGER.debug("Git target %s resolved to commit sha=%s", target.repo, git_sha)
        return str(destination), target.repo or "", git_sha
    if target.type == "local":
        if not target.path or not Path(target.path).exists():
            raise FileNotFoundError(f"Local path does not exist: {target.path}")
        git_sha = get_git_commit_sha(target.path)
        return target.path, target.path, git_sha
    if target.type == "image":
        return target.image or "", target.image or "", None
    if target.type == "url":
        return target.url or "", target.url or "", None
    raise ValueError(f"Unsupported target type: {target.type}")


def evaluate_policy(
    findings: list[dict[str, Any]], settings: dict[str, Any], target_name: str = "", target_type: str = "local"
) -> str:
    """Evaluate findings against policy engine or fallback to simple rules."""

    # Try advanced policy engine first
    policies_file = settings.get("policy", {}).get("policies_file", "/app/config/policies.yaml")
    try:
        from pathlib import Path

        if Path(policies_file).exists():
            policy_engine = load_policy_engine(policies_file)
            result = policy_engine.evaluate(findings, target_name, target_type)
            return result["status"]
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Policy engine failed, falling back to simple policy: %s", exc)

    # Fallback to simple policy
    blocking_severities = {str(item).upper() for item in settings["policy"].get("block_on_severities", [])}
    block_secret_categories = bool(settings["policy"].get("block_on_secret_categories", True))
    for finding in findings:
        # Support both Finding dataclass objects and plain dicts
        if hasattr(finding, "severity"):
            sev = str(finding.severity or "").upper()
            cat = str(finding.category or "").lower()
        else:
            sev = str(finding.get("severity", "")).upper()
            cat = str(finding.get("category", "")).lower()
        if sev in blocking_severities:
            return "BLOCK"
        if block_secret_categories and cat == "secret":
            return "BLOCK"
    return "PASS"


def run_single_scan(target: TargetSpec, settings: dict[str, Any], scan_id: str | None = None) -> ScanResult:
    scan_id = scan_id or str(uuid.uuid4())
    started_at = utc_now_iso()
    db_path = settings["paths"]["db_path"]
    reports_root = Path(settings["paths"]["reports_dir"]) / scan_id
    raw_dir = reports_root / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    tools: list[ToolExecutionResult] = []
    findings = []
    artifacts: dict[str, str] = {}
    status = "COMPLETED_CLEAN"
    error_messages: list[str] = []

    target_input, target_value, git_sha = prepare_target(target, settings, scan_id)

    compatible_scanners = get_compatible_scanners(target.type, settings)
    runnable_scanners, skipped_scanners = preflight_check(compatible_scanners)

    for skipped in skipped_scanners:
        tools.append(
            ToolExecutionResult(
                tool=skipped["tool"],
                enabled=True,
                success=False,
                exit_code=-1,
                started_at=started_at,
                finished_at=started_at,
                error=skipped["reason"],
                finding_count=0,
                cache_hit=False,
            )
        )

    # git_sha is injected into every tool's cache_context so that a new commit
    # pushed within the TTL window produces a cache miss instead of stale results.
    _git_ctx: dict[str, Any] = {"git_sha": git_sha} if git_sha else {}
    cache_settings = settings.get("cache", {})
    cache_enabled = bool(cache_settings.get("enabled", False))
    cache_ttl = int(cache_settings.get("ttl_seconds", 900))
    cache_dir = Path(str(cache_settings.get("dir", "/data/cache/orchestrator")))

    def execute_tool(
        tool_name: str,
        runner,
        parser,
        parser_kwargs: dict[str, Any] | None = None,
        cache_context: dict[str, Any] | None = None,
    ) -> None:
        nonlocal status
        parser_kwargs = parser_kwargs or {}
        cache_context = cache_context or {}
        started_tool = utc_now_iso()
        output_path = str(raw_dir / f"{tool_name}.json")
        try:
            cache_hit = False
            cache_key = ""
            if cache_enabled:
                cache_key = build_cache_key(
                    tool_name=tool_name,
                    target_type=target.type,
                    target_value=target_value,
                    context=cache_context,
                )
                cache_hit = load_cached_output(cache_dir, cache_key, output_path, cache_ttl)

            if cache_hit:
                result = {"exit_code": 0, "stderr": "cache_hit"}
            else:
                result = runner(output_path)
                if cache_enabled and Path(output_path).exists():
                    store_cached_output(cache_dir, cache_key, output_path)

            raw_payload = load_json(output_path)
            new_findings = parser(raw_payload, output_path, **parser_kwargs)
            findings.extend(new_findings)
            tools.append(
                ToolExecutionResult(
                    tool=tool_name,
                    enabled=True,
                    success=True,
                    exit_code=int(result.get("exit_code", 0)),
                    started_at=started_tool,
                    finished_at=utc_now_iso(),
                    raw_output_path=output_path,
                    stderr=result.get("stderr"),
                    finding_count=len(new_findings),
                    cache_hit=cache_hit,
                )
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Tool %s failed for target %s", tool_name, target.name)
            status = "PARTIAL_FAILED"
            error_messages.append(str(exc))
            tools.append(
                ToolExecutionResult(
                    tool=tool_name,
                    enabled=True,
                    success=False,
                    exit_code=2,
                    started_at=started_tool,
                    finished_at=utc_now_iso(),
                    raw_output_path=output_path if Path(output_path).exists() else None,
                    error=str(exc),
                    finding_count=0,
                    cache_hit=False,
                )
            )

    def execute_syft() -> None:
        nonlocal status
        started_tool = utc_now_iso()
        output_path = str(raw_dir / "syft.spdx.json")
        try:
            result = run_syft(target_input, output_path)
            artifacts["sbom_spdx_json"] = output_path
            meta = sbom_metadata(output_path)
            tools.append(
                ToolExecutionResult(
                    tool="syft",
                    enabled=True,
                    success=True,
                    exit_code=int(result.get("exit_code", 0)),
                    started_at=started_tool,
                    finished_at=utc_now_iso(),
                    raw_output_path=output_path,
                    stderr=result.get("stderr"),
                    finding_count=meta.get("package_count", 0),
                )
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Tool syft failed for target %s", target.name)
            status = "PARTIAL_FAILED"
            error_messages.append(str(exc))
            tools.append(
                ToolExecutionResult(
                    tool="syft",
                    enabled=True,
                    success=False,
                    exit_code=2,
                    started_at=started_tool,
                    finished_at=utc_now_iso(),
                    raw_output_path=output_path if Path(output_path).exists() else None,
                    error=str(exc),
                    finding_count=0,
                )
            )

    for tool in runnable_scanners:
        if tool == "semgrep":
            execute_tool(
                "semgrep",
                lambda output_path: run_semgrep(
                    target_input, output_path, settings["scanners"]["semgrep"].get("configs", ["p/default"])
                ),
                lambda raw_payload, output_path, **_: normalize_semgrep(
                    scan_id, target, raw_payload, output_path, base_path=target_input
                ),
                cache_context={
                    "configs": settings["scanners"]["semgrep"].get("configs", ["p/default"]),
                    **_git_ctx,
                },
            )
        elif tool == "bandit":
            execute_tool(
                "bandit",
                lambda output_path: run_bandit(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_bandit(
                    scan_id, target, raw_payload, output_path, base_path=target_input
                ),
                cache_context={"mode": "bandit", **_git_ctx},
            )
        elif tool == "nuclei":
            _nuclei_cfg = settings["scanners"]["nuclei"]
            _nuclei_ttype = target.type
            execute_tool(
                "nuclei",
                lambda output_path, _cfg=_nuclei_cfg, _tt=_nuclei_ttype: run_nuclei(
                    target_input,
                    output_path,
                    _cfg.get("templates") or [],
                    _cfg.get("severity"),
                    _cfg.get("tags"),
                    target_type=_tt,
                ),
                lambda raw_payload, output_path, **_: normalize_nuclei(
                    scan_id, target, raw_payload, output_path, base_path=target_input
                ),
                cache_context={
                    "templates": _nuclei_cfg.get("templates"),
                    "severity": _nuclei_cfg.get("severity"),
                    "tags": _nuclei_cfg.get("tags"),
                    "target_type": target.type,
                    **_git_ctx,
                },
            )
        elif tool == "trivy_fs":
            execute_tool(
                "trivy_fs",
                lambda output_path: run_trivy_fs(
                    target_input,
                    output_path,
                    settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                ),
                lambda raw_payload, output_path, **_: normalize_trivy(
                    scan_id, target, raw_payload, output_path, base_path=target_input, category="sca"
                ),
                cache_context={
                    "severities": settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    "ignore_unfixed": bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                    **_git_ctx,
                },
            )
        elif tool == "trivy_image":
            execute_tool(
                "trivy_image",
                lambda output_path: run_trivy_image(
                    target_input,
                    output_path,
                    settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                ),
                lambda raw_payload, output_path, **_: normalize_trivy(
                    scan_id, target, raw_payload, output_path, category="container"
                ),
                cache_context={
                    "severities": settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    "ignore_unfixed": bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                },
            )
        elif tool == "gitleaks":
            use_git = Path(target_input, ".git").exists()
            execute_tool(
                "gitleaks",
                lambda output_path: run_gitleaks(target_input, output_path, use_git_history=use_git),
                lambda raw_payload, output_path, **_: normalize_gitleaks(
                    scan_id, target, raw_payload, output_path, base_path=target_input
                ),
                cache_context={"use_git_history": use_git, **_git_ctx},
            )
        elif tool == "checkov":
            execute_tool(
                "checkov",
                lambda output_path: run_checkov(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_checkov(
                    scan_id, target, raw_payload, output_path, base_path=target_input
                ),
                cache_context={"mode": "checkov", **_git_ctx},
            )
        elif tool == "grype":
            execute_tool(
                "grype",
                lambda output_path: run_grype(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_grype(
                    scan_id, target, raw_payload, output_path, base_path=target_input
                ),
                cache_context={"mode": "grype", **_git_ctx},
            )
        elif tool == "zap":
            _zap_cfg = settings["scanners"].get("owasp_zap", {})
            execute_tool(
                "zap",
                lambda output_path, _cfg=_zap_cfg: run_owasp_zap(
                    target_input,
                    output_path,
                    zap_api_url=_cfg.get("api_url", "http://localhost:8090"),
                    zap_api_key=_cfg.get("api_key", ""),
                    spider_timeout=int(_cfg.get("spider_timeout", 120)),
                    scan_timeout=int(_cfg.get("scan_timeout", 600)),
                ),
                lambda raw_payload, output_path, **_: normalize_zap(
                    scan_id, target, raw_payload, output_path, base_path=target_input
                ),
                cache_context={"mode": "zap", **_git_ctx},
            )
        elif tool == "syft":
            execute_syft()

    if not findings and status == "COMPLETED_CLEAN":
        status = "COMPLETED_CLEAN"
    elif findings and status == "COMPLETED_CLEAN":
        status = "COMPLETED_WITH_FINDINGS"

    policy_status = evaluate_policy([f.to_dict() for f in findings], settings, target.name, target.type)

    finished_at = utc_now_iso()
    normalized_report_path = str(reports_root / "normalized.json")
    write_json_file(normalized_report_path, [f.to_dict() for f in findings])

    result = ScanResult(
        scan_id=scan_id,
        started_at=started_at,
        finished_at=finished_at,
        target_name=target.name,
        target_type=target.type,
        target_value=target_value,
        status=status,
        policy_status=policy_status,
        tools=tools,
        findings=findings,
        artifacts=artifacts,
        raw_report_dir=str(raw_dir),
        normalized_report_path=normalized_report_path,
        error_message="; ".join(error_messages) if error_messages else None,
    )

    if db_path:
        save_scan_result(db_path, result)

    return result


def run_all_scans(settings: dict[str, Any], targets: list[TargetSpec]) -> list[ScanResult]:
    """Run scans for all targets concurrently, returning ScanResult objects."""
    max_workers = settings.get("execution", {}).get("max_concurrent_targets", 2)
    results: list[ScanResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(run_single_scan, target, settings): target for target in targets}
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append(result)
                LOGGER.info("Scan %s for target %s completed.", result.scan_id, target.name)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Scan for target %s generated an exception: %s", target.name, exc)
    return results


def run_targets_concurrently(
    targets: list[TargetSpec],
    settings: dict[str, Any],
    fail_on_policy_block: bool,
    scan_id_override: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Run scans for all targets concurrently, returning serialized dicts and an exit code.

    This is the primary entry point used by the dashboard's scan runner and the CLI
    ``main()`` function. It wraps :func:`run_single_scan` with per-target exception
    handling and optional policy-block exit-code escalation.

    Returns:
        A tuple of (list of scan result dicts, overall exit code).
        Exit codes: 0 = success, 3 = policy BLOCK, 4 = scan FAILED.
    """
    max_workers = max(1, int(settings.get("execution", {}).get("max_concurrent_targets", 1)))
    results: list[dict[str, Any]] = []
    has_block = False
    has_failure = False

    def _scan_target(target: TargetSpec) -> dict[str, Any]:
        LOGGER.info("Starting scan for target=%s type=%s", target.name, target.type)
        target_settings = copy.deepcopy(settings)
        # Use the pre-assigned scan_id only for single-target runs (dashboard flow).
        sid = scan_id_override if len(targets) == 1 else None
        try:
            result = run_single_scan(target, target_settings, scan_id=sid)
            return {
                "payload": result.to_dict(),
                "policy_status": result.policy_status,
                "status": result.status,
                "target": target.name,
                "error": None,
            }
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Scan failed for target=%s", target.name)
            return {
                "payload": {
                    "scan_id": sid or str(uuid.uuid4()),
                    "target_name": target.name,
                    "target_type": target.type,
                    "target_value": target.resolved_target,
                    "status": "FAILED",
                    "policy_status": "UNKNOWN",
                    "error_message": str(exc),
                    "tools": [],
                    "findings": [],
                },
                "policy_status": "UNKNOWN",
                "status": "FAILED",
                "target": target.name,
                "error": str(exc),
            }

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="target-scan") as executor:
        futures = [executor.submit(_scan_target, target) for target in targets]
        for future in as_completed(futures):
            item = future.result()
            results.append(item["payload"])
            if item["policy_status"] == "BLOCK":
                has_block = True
            if item["status"] in {"PARTIAL_FAILED", "FAILED"}:
                has_failure = True

    # BLOCK takes priority over FAILED (security policy violation is more important)
    if has_block and fail_on_policy_block:
        overall_exit = 3
    elif has_failure:
        overall_exit = 4
    else:
        overall_exit = 0
    return results, overall_exit


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Centralized Linux-based security scan orchestrator")
    parser.add_argument(
        "--target-type",
        choices=["git", "local", "image", "url"],
        help="Target type to scan",
    )
    parser.add_argument("--target", help="Git URL, local path, image reference, or web URL")
    parser.add_argument("--target-name", help="Display name for the target")
    parser.add_argument("--ref", help="Optional git branch/tag/ref")
    parser.add_argument("--targets-file", help="YAML file with multiple targets")
    parser.add_argument("--settings", default="/app/config/settings.yaml", help="Path to settings YAML")
    parser.add_argument("--config", dest="settings", help="Alias for --settings (path to settings YAML)")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Logging level")
    parser.add_argument(
        "--fail-on-policy-block", action="store_true", help="Exit with code 3 when policy status is BLOCK"
    )
    parser.add_argument("--json-output", help="Optional path for aggregate JSON output")
    parser.add_argument("--retention-only", action="store_true", help="Run only retention cleanup and exit")
    parser.add_argument(
        "--retention-dry-run", action="store_true", help="Preview retention cleanup without deleting files"
    )
    parser.add_argument(
        "--scan-id",
        help="Pre-assigned scan UUID (used by the dashboard to correlate the RUNNING placeholder row)",
    )
    return parser


def main() -> int:
    """CLI entry point."""
    parser = build_arg_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)
    settings = resolve_settings(args.settings)
    retention_result = apply_retention(settings, dry_run=args.retention_dry_run)
    LOGGER.info(
        "Retention cleanup: reports=%s workspaces=%s cache=%s dry_run=%s",
        retention_result["reports_removed"],
        retention_result["workspaces_removed"],
        retention_result["cache_removed"],
        retention_result["dry_run"],
    )

    if args.retention_only:
        payload = {"retention": retention_result, "generated_at": utc_now_iso()}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    init_db(settings["paths"]["db_path"])

    try:
        targets = resolve_targets(args)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("Invalid arguments: %s", exc)
        return 2

    results, overall_exit = run_targets_concurrently(
        targets=targets,
        settings=settings,
        fail_on_policy_block=getattr(args, "fail_on_policy_block", False),
        scan_id_override=getattr(args, "scan_id", None),
    )
    payload = {"results": results, "generated_at": utc_now_iso()}
    if args.json_output:
        write_json_file(args.json_output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return overall_exit


if __name__ == "__main__":
    sys.exit(main())
