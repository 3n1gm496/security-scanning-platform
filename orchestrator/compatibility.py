# -*- coding: utf-8 -*-
"""Scanner compatibility matrix and preflight checks."""

from __future__ import annotations
import importlib
import subprocess
from typing import Any

from orchestrator.logging_config import get_logger
from orchestrator.scanners import command_exists

LOGGER = get_logger(__name__)

# Centralized compatibility matrix: maps scanner name to supported target types.
# This is the single source of truth for scanner-target routing.
SCANNER_COMPATIBILITY: dict[str, set[str]] = {
    # SAST / filesystem-based tools
    "semgrep": {"git", "local"},
    "bandit": {"git", "local"},
    "checkov": {"git", "local"},
    "gitleaks": {"git", "local"},
    # SCA / dependency / SBOM tools
    "trivy_fs": {"git", "local"},
    "grype": {"git", "local", "image"},
    "syft": {"git", "local", "image"},
    # DAST / URL-based tools
    "nuclei": {"git", "local", "url"},
    "zap": {"url"},
    # Image scanners
    "trivy_image": {"image"},
}

# Mapping from the tool name in settings.yaml to the required binary name.
# Most are the same, but some differ (e.g. owasp_zap -> zap-cli).
REQUIRED_BINARIES: dict[str, str] = {
    "semgrep": "semgrep",
    "bandit": "bandit",
    "checkov": "checkov",
    "gitleaks": "gitleaks",
    "trivy": "trivy",  # Covers both trivy_fs and trivy_image
    "grype": "grype",
    "syft": "syft",
    "nuclei": "nuclei",
    # ZAP uses the python-owasp-zap-v2.4 client library (zapv2 module),
    # not a CLI binary.  Preflight handles this as a special case below.
}

_TOOL_BINARY_KEYS: dict[str, str] = {
    "trivy_fs": "trivy",
    "trivy_image": "trivy",
}


def get_compatible_scanners(target_type: str, settings: dict[str, Any]) -> list[str]:
    """Return a list of enabled and compatible scanners for the given target type."""
    enabled_scanners = {name for name, config in settings.get("scanners", {}).items() if config.get("enabled")}

    compatible_scanners: list[str] = []
    for tool in sorted(list(enabled_scanners)):
        # Handle special cases like trivy, which has two modes (fs, image)
        if tool == "trivy":
            if target_type in SCANNER_COMPATIBILITY.get("trivy_fs", set()):
                compatible_scanners.append("trivy_fs")
            if target_type in SCANNER_COMPATIBILITY.get("trivy_image", set()):
                compatible_scanners.append("trivy_image")
            continue

        # owasp_zap in settings.yaml maps to 'zap' in the compatibility matrix
        matrix_key = "zap" if tool == "owasp_zap" else tool
        if target_type in SCANNER_COMPATIBILITY.get(matrix_key, set()):
            compatible_scanners.append(matrix_key)

    LOGGER.info(
        "scanner.discovery",
        count=len(compatible_scanners),
        target_type=target_type,
        scanners=", ".join(compatible_scanners) or "none",
    )
    return compatible_scanners


def preflight_check(scanners: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Check for required binaries, returning runnable and skipped scanners."""
    runnable = []
    skipped = []
    for tool in scanners:
        # ZAP uses a Python client library instead of a CLI binary.
        if tool == "zap":
            try:
                importlib.import_module("zapv2")
                runnable.append(tool)
            except ImportError:
                LOGGER.warning(
                    "preflight.missing_package",
                    tool=tool,
                    package="python-owasp-zap-v2.4",
                )
                skipped.append(
                    {
                        "tool": tool,
                        "reason": "Required Python package 'python-owasp-zap-v2.4' is not installed",
                    }
                )
            continue

        # Trivy is a special case, as both trivy_fs and trivy_image use the same binary
        binary_name = REQUIRED_BINARIES.get(_TOOL_BINARY_KEYS.get(tool, tool))
        if not binary_name:
            LOGGER.warning("preflight.no_binary_defined", tool=tool)
            runnable.append(tool)
            continue

        if command_exists(binary_name):
            runnable.append(tool)
        else:
            LOGGER.warning(
                "preflight.binary_not_found",
                tool=tool,
                binary=binary_name,
            )
            skipped.append(
                {
                    "tool": tool,
                    "reason": f"Required binary '{binary_name}' not found in PATH",
                }
            )

    LOGGER.info(
        "preflight.complete",
        runnable=len(runnable),
        skipped=len(skipped),
    )
    return runnable, skipped


# Version-command map for each scanner binary.
_VERSION_COMMANDS: dict[str, list[str]] = {
    "semgrep": ["semgrep", "--version"],
    "trivy": ["trivy", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "checkov": ["checkov", "--version"],
    "bandit": ["bandit", "--version"],
    "nuclei": ["nuclei", "-version"],
    "grype": ["grype", "version"],
    "syft": ["syft", "version"],
}


def scanner_health_check() -> list[dict[str, Any]]:
    """Run a health check on all known scanner binaries.

    Returns a list of dicts, one per scanner, with keys:
    - tool: scanner name
    - available: True if the binary/module is present
    - version: version string (or None)
    - error: error message if unavailable
    """
    results: list[dict[str, Any]] = []

    for tool, binary in REQUIRED_BINARIES.items():
        entry: dict[str, Any] = {"tool": tool, "available": False, "version": None, "error": None}

        if not command_exists(binary):
            entry["error"] = f"Binary '{binary}' not found in PATH"
            results.append(entry)
            continue

        entry["available"] = True

        # Try to get version
        version_cmd = _VERSION_COMMANDS.get(tool)
        if version_cmd:
            try:
                proc = subprocess.run(  # noqa: S603
                    version_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                version_str = (proc.stdout.strip() or proc.stderr.strip()).split("\n")[0]
                entry["version"] = version_str if version_str else None
            except Exception as exc:  # noqa: BLE001
                entry["version"] = None
                LOGGER.debug("health_check.version_failed", tool=tool, error=str(exc))

        results.append(entry)

    # ZAP is a Python package, not a binary
    zap_entry: dict[str, Any] = {"tool": "owasp_zap", "available": False, "version": None, "error": None}
    try:
        mod = importlib.import_module("zapv2")
        zap_entry["available"] = True
        zap_entry["version"] = getattr(mod, "__version__", None)
    except ImportError:
        zap_entry["error"] = "Python package 'python-owasp-zap-v2.4' is not installed"
    results.append(zap_entry)

    return results
