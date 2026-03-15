# -*- coding: utf-8 -*-
"""Scanner compatibility matrix and preflight checks."""

from __future__ import annotations
import importlib
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
        binary_name = REQUIRED_BINARIES.get(tool.replace("_fs", "").replace("_image", ""))
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
