# -*- coding: utf-8 -*-
"""Scanner compatibility matrix and preflight checks."""

from __future__ import annotations
import logging
from typing import Any

from orchestrator.scanners import command_exists

LOGGER = logging.getLogger(__name__)

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
    "zap": "zap-cli",
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
        "Discovered %d enabled scanners for target_type=%s: %s",
        len(compatible_scanners),
        target_type,
        ", ".join(compatible_scanners) or "none",
    )
    return compatible_scanners


def preflight_check(scanners: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Check for required binaries, returning runnable and skipped scanners."""
    runnable = []
    skipped = []
    for tool in scanners:
        # Trivy is a special case, as both trivy_fs and trivy_image use the same binary
        binary_name = REQUIRED_BINARIES.get(tool.replace("_fs", "").replace("_image", ""))
        if not binary_name:
            LOGGER.warning("Tool %s has no required binary defined, skipping preflight check.", tool)
            runnable.append(tool)
            continue

        if command_exists(binary_name):
            runnable.append(tool)
        else:
            LOGGER.warning(
                "Tool %s is enabled but its binary ('%s') was not found in PATH. Skipping.",
                tool,
                binary_name,
            )
            skipped.append(
                {
                    "tool": tool,
                    "reason": f"Required binary '{binary_name}' not found in PATH",
                }
            )

    LOGGER.info(
        "Preflight check complete. Runnable: %d, Skipped: %d",
        len(runnable),
        len(skipped),
    )
    return runnable, skipped
