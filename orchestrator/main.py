from __future__ import annotations

import argparse
import copy
import json
import logging
import os
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
from orchestrator.scanners import (
    ScannerError,
    clone_repo,
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

LOGGER = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def resolve_settings(path: str) -> dict[str, Any]:
    settings = load_yaml(path)
    settings.setdefault("paths", {})
    settings.setdefault("scanners", {})
    settings.setdefault("policy", {})
    settings.setdefault("execution", {})
    settings.setdefault("cache", {})
    settings["paths"].setdefault("db_path", os.getenv("ORCH_DB_PATH", "/data/security_scans.db"))
    settings["paths"].setdefault("reports_dir", os.getenv("REPORTS_DIR", "/data/reports"))
    settings["paths"].setdefault("workspace_dir", os.getenv("WORKSPACE_DIR", "/data/workspaces"))
    settings["scanners"].setdefault("semgrep", {"enabled": True, "configs": ["p/default"]})
    settings["scanners"].setdefault("trivy", {"enabled": True, "severities": ["CRITICAL", "HIGH", "MEDIUM"], "ignore_unfixed": False})
    settings["scanners"].setdefault("gitleaks", {"enabled": True})
    settings["scanners"].setdefault("checkov", {"enabled": True})
    settings["scanners"].setdefault("syft", {"enabled": True})
    settings["scanners"].setdefault("bandit", {"enabled": False})
    settings["scanners"].setdefault("nuclei", {"enabled": False, "templates": []})
    settings["scanners"].setdefault("grype", {"enabled": False})
    settings["scanners"].setdefault("owasp_zap", {"enabled": False})
    settings["policy"].setdefault("block_on_severities", ["CRITICAL"])
    settings["policy"].setdefault("block_on_secret_categories", True)
    settings["execution"].setdefault("max_concurrent_targets", int(os.getenv("ORCH_MAX_CONCURRENT_TARGETS", "2")))
    settings["cache"].setdefault("enabled", os.getenv("ORCH_CACHE_ENABLED", "true").lower() in {"1", "true", "yes", "on"})
    settings["cache"].setdefault("ttl_seconds", int(os.getenv("ORCH_CACHE_TTL_SECONDS", "900")))
    settings["cache"].setdefault("dir", os.getenv("ORCH_CACHE_DIR", "/data/cache/orchestrator"))
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
        "ref": args.ref,
        "enabled": True,
    }
    targets.append(TargetSpec.from_dict(payload))
    return targets


def prepare_target(target: TargetSpec, settings: dict[str, Any], scan_id: str) -> tuple[str, str]:
    workspace_root = Path(settings["paths"]["workspace_dir"])
    workspace_root.mkdir(parents=True, exist_ok=True)

    if target.type == "git":
        destination = workspace_root / scan_id / "repo"
        clone_repo(target.repo or "", str(destination), target.ref)
        return str(destination), target.repo or ""
    if target.type == "local":
        if not target.path or not Path(target.path).exists():
            raise FileNotFoundError(f"Local path does not exist: {target.path}")
        return target.path, target.path
    if target.type == "image":
        return target.image or "", target.image or ""
    raise ValueError(f"Unsupported target type: {target.type}")


def evaluate_policy(findings: list[dict[str, Any]], settings: dict[str, Any]) -> str:
    blocking_severities = {str(item).upper() for item in settings["policy"].get("block_on_severities", [])}
    block_secret_categories = bool(settings["policy"].get("block_on_secret_categories", True))
    for finding in findings:
        if str(finding.get("severity", "")).upper() in blocking_severities:
            return "BLOCK"
        if block_secret_categories and str(finding.get("category", "")).lower() == "secret":
            return "BLOCK"
    return "PASS"


def run_single_scan(target: TargetSpec, settings: dict[str, Any]) -> ScanResult:
    scan_id = str(uuid.uuid4())
    started_at = utc_now_iso()
    db_path = settings["paths"]["db_path"]
    reports_root = Path(settings["paths"]["reports_dir"]) / scan_id
    raw_dir = reports_root / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    tools: list[ToolExecutionResult] = []
    findings = []
    artifacts: dict[str, str] = {}
    status = "COMPLETED_CLEAN"
    error_message = None

    target_input, target_value = prepare_target(target, settings, scan_id)
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
        nonlocal status, error_message, findings, artifacts
        parser_kwargs = parser_kwargs or {}
        cache_context = cache_context or {}
        started_tool = utc_now_iso()
        output_path = str(raw_dir / f"{tool_name}.json")
        try:
            cache_hit = False
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
                )
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Tool %s failed for target %s", tool_name, target.name)
            status = "PARTIAL_FAILED"
            if not error_message:
                error_message = str(exc)
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
                )
            )

    if target.type in {"git", "local"}:
        if settings["scanners"]["semgrep"].get("enabled", True):
            execute_tool(
                "semgrep",
                lambda output_path: run_semgrep(target_input, output_path, settings["scanners"]["semgrep"].get("configs", ["p/default"])),
                lambda raw_payload, output_path, **_: normalize_semgrep(scan_id, target, raw_payload, output_path, base_path=target_input),
                cache_context={"configs": settings["scanners"]["semgrep"].get("configs", ["p/default"])},
            )
        if settings["scanners"]["bandit"].get("enabled", False):
            execute_tool(
                "bandit",
                lambda output_path: run_bandit(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_bandit(scan_id, target, raw_payload, output_path, base_path=target_input),
                cache_context={"mode": "bandit"},
            )
        if settings["scanners"]["nuclei"].get("enabled", False):
            execute_tool(
                "nuclei",
                lambda output_path: run_nuclei(
                    target_input,
                    output_path,
                    settings["scanners"]["nuclei"].get("templates"),
                    settings["scanners"]["nuclei"].get("severity"),
                    settings["scanners"]["nuclei"].get("tags"),
                ),
                lambda raw_payload, output_path, **_: normalize_nuclei(scan_id, target, raw_payload, output_path, base_path=target_input),
                cache_context={
                    "templates": settings["scanners"]["nuclei"].get("templates"),
                    "severity": settings["scanners"]["nuclei"].get("severity"),
                    "tags": settings["scanners"]["nuclei"].get("tags"),
                },
            )
        if settings["scanners"]["trivy"].get("enabled", True):
            execute_tool(
                "trivy_fs",
                lambda output_path: run_trivy_fs(
                    target_input,
                    output_path,
                    settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                ),
                lambda raw_payload, output_path, **_: normalize_trivy(scan_id, target, raw_payload, output_path, base_path=target_input, category="sca"),
                cache_context={
                    "severities": settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    "ignore_unfixed": bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                },
            )
        if settings["scanners"]["gitleaks"].get("enabled", True):
            use_git = Path(target_input, ".git").exists()
            execute_tool(
                "gitleaks",
                lambda output_path: run_gitleaks(target_input, output_path, use_git_history=use_git),
                lambda raw_payload, output_path, **_: normalize_gitleaks(scan_id, target, raw_payload, output_path, base_path=target_input),
                cache_context={"use_git_history": use_git},
            )
        if settings["scanners"]["checkov"].get("enabled", True):
            execute_tool(
                "checkov",
                lambda output_path: run_checkov(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_checkov(scan_id, target, raw_payload, output_path, base_path=target_input),
                cache_context={"mode": "checkov"},
            )
        if settings["scanners"]["grype"].get("enabled", False):
            execute_tool(
                "grype",
                lambda output_path: run_grype(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_grype(scan_id, target, raw_payload, output_path, base_path=target_input),
                cache_context={"mode": "grype"},
            )
        if settings["scanners"]["owasp_zap"].get("enabled", False) and target.type != "image":
            execute_tool(
                "owasp_zap",
                lambda output_path: run_owasp_zap(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_zap(scan_id, target, raw_payload, output_path, base_path=target_input),
                cache_context={"mode": "zap"},
            )
        if settings["scanners"]["syft"].get("enabled", True):
            started_tool = utc_now_iso()
            output_path = str(raw_dir / "syft.spdx.json")
            try:
                result = run_syft(target_input, output_path)
                artifacts["sbom"] = output_path
                artifacts["sbom_metadata"] = json.dumps(sbom_metadata(output_path), ensure_ascii=False)
                tools.append(
                    ToolExecutionResult(
                        tool="syft",
                        enabled=True,
                        success=True,
                        exit_code=int(result.get("exit_code", 0)),
                        started_at=started_tool,
                        finished_at=utc_now_iso(),
                        raw_output_path=output_path,
                        artifact_paths=[output_path],
                        finding_count=0,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Syft failed for target %s", target.name)
                status = "PARTIAL_FAILED"
                if not error_message:
                    error_message = str(exc)
                tools.append(
                    ToolExecutionResult(
                        tool="syft",
                        enabled=True,
                        success=False,
                        exit_code=2,
                        started_at=started_tool,
                        finished_at=utc_now_iso(),
                        error=str(exc),
                        finding_count=0,
                    )
                )

    elif target.type == "image":
        if settings["scanners"]["bandit"].get("enabled", False):
            # bandit not meaningful for images, skip
            pass
        if settings["scanners"]["nuclei"].get("enabled", False):
            # nuclei can scan images via docker and others; treat as filesystem
            execute_tool(
                "nuclei",
                lambda output_path: run_nuclei(
                    target_input,
                    output_path,
                    settings["scanners"]["nuclei"].get("templates"),
                    settings["scanners"]["nuclei"].get("severity"),
                    settings["scanners"]["nuclei"].get("tags"),
                ),
                lambda raw_payload, output_path, **_: normalize_nuclei(scan_id, target, raw_payload, output_path),
                cache_context={
                    "templates": settings["scanners"]["nuclei"].get("templates"),
                    "severity": settings["scanners"]["nuclei"].get("severity"),
                    "tags": settings["scanners"]["nuclei"].get("tags"),
                },
            )
        if settings["scanners"]["trivy"].get("enabled", True):
            execute_tool(
                "trivy_image",
                lambda output_path: run_trivy_image(
                    target_input,
                    output_path,
                    settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                ),
                lambda raw_payload, output_path, **_: normalize_trivy(scan_id, target, raw_payload, output_path, category="container"),
                cache_context={
                    "severities": settings["scanners"]["trivy"].get("severities", ["CRITICAL", "HIGH", "MEDIUM"]),
                    "ignore_unfixed": bool(settings["scanners"]["trivy"].get("ignore_unfixed", False)),
                },
            )
        if settings["scanners"]["grype"].get("enabled", False):
            execute_tool(
                "grype",
                lambda output_path: run_grype(target_input, output_path),
                lambda raw_payload, output_path, **_: normalize_grype(scan_id, target, raw_payload, output_path),
                cache_context={"mode": "grype"},
            )
        if settings["scanners"]["syft"].get("enabled", True):
            started_tool = utc_now_iso()
            output_path = str(raw_dir / "syft.spdx.json")
            try:
                result = run_syft(target_input, output_path)
                artifacts["sbom"] = output_path
                artifacts["sbom_metadata"] = json.dumps(sbom_metadata(output_path), ensure_ascii=False)
                tools.append(
                    ToolExecutionResult(
                        tool="syft",
                        enabled=True,
                        success=True,
                        exit_code=int(result.get("exit_code", 0)),
                        started_at=started_tool,
                        finished_at=utc_now_iso(),
                        raw_output_path=output_path,
                        artifact_paths=[output_path],
                        finding_count=0,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Syft failed for image %s", target.name)
                status = "PARTIAL_FAILED"
                if not error_message:
                    error_message = str(exc)
                tools.append(
                    ToolExecutionResult(
                        tool="syft",
                        enabled=True,
                        success=False,
                        exit_code=2,
                        started_at=started_tool,
                        finished_at=utc_now_iso(),
                        error=str(exc),
                        finding_count=0,
                    )
                )
    else:
        raise ValueError(f"Unsupported target type: {target.type}")

    if findings and status == "COMPLETED_CLEAN":
        status = "COMPLETED_WITH_FINDINGS"

    normalized_path = str(reports_root / "normalized_findings.json")
    summary_path = str(reports_root / "summary.json")
    findings_payload = [finding.to_dict() for finding in findings]
    write_json_file(normalized_path, findings_payload)
    policy_status = evaluate_policy(findings_payload, settings)
    result = ScanResult(
        scan_id=scan_id,
        started_at=started_at,
        finished_at=utc_now_iso(),
        target_name=target.name,
        target_type=target.type,
        target_value=target_value,
        status=status,
        policy_status=policy_status,
        tools=tools,
        findings=findings,
        artifacts=artifacts,
        raw_report_dir=str(raw_dir),
        normalized_report_path=normalized_path,
        error_message=error_message,
    )
    write_json_file(summary_path, result.to_dict())
    save_scan_result(db_path, result)
    return result


def run_targets_concurrently(
    targets: list[TargetSpec],
    settings: dict[str, Any],
    fail_on_policy_block: bool,
) -> tuple[list[dict[str, Any]], int]:
    max_workers = max(1, int(settings.get("execution", {}).get("max_concurrent_targets", 1)))
    results: list[dict[str, Any]] = []
    overall_exit = 0

    def _scan_target(target: TargetSpec) -> dict[str, Any]:
        LOGGER.info("Starting scan for target=%s type=%s", target.name, target.type)
        target_settings = copy.deepcopy(settings)
        try:
            result = run_single_scan(target, target_settings)
            return {
                "payload": result.to_dict(),
                "policy_status": result.policy_status,
                "status": result.status,
                "target": target.name,
                "error": None,
            }
        except (ScannerError, FileNotFoundError, ValueError) as exc:
            LOGGER.exception("Scan failed for target=%s", target.name)
            return {
                "payload": {
                    "scan_id": str(uuid.uuid4()),
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
            if item["policy_status"] == "BLOCK" and fail_on_policy_block:
                overall_exit = max(overall_exit, 3)
            elif item["status"] in {"PARTIAL_FAILED", "FAILED"}:
                overall_exit = max(overall_exit, 4)

    return results, overall_exit


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Centralized Linux-based security scan orchestrator")
    parser.add_argument("--target-type", choices=["git", "local", "image"], help="Target type to scan")
    parser.add_argument("--target", help="Git URL, local path, or image reference")
    parser.add_argument("--target-name", help="Display name for the target")
    parser.add_argument("--ref", help="Optional git branch/tag/ref")
    parser.add_argument("--targets-file", help="YAML file with multiple targets")
    parser.add_argument("--settings", default="/app/config/settings.yaml", help="Path to settings YAML")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Logging level")
    parser.add_argument("--fail-on-policy-block", action="store_true", help="Exit with code 3 when policy status is BLOCK")
    parser.add_argument("--json-output", help="Optional path for aggregate JSON output")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)
    settings = resolve_settings(args.settings)
    init_db(settings["paths"]["db_path"])

    try:
        targets = resolve_targets(args)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("Invalid arguments: %s", exc)
        return 2

    results, overall_exit = run_targets_concurrently(
        targets=targets,
        settings=settings,
        fail_on_policy_block=args.fail_on_policy_block,
    )

    payload = {"results": results, "generated_at": utc_now_iso()}
    if args.json_output:
        write_json_file(args.json_output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return overall_exit


if __name__ == "__main__":
    sys.exit(main())
