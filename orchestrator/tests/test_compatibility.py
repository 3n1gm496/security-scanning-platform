"""Tests for orchestrator.compatibility — scanner compatibility matrix and preflight checks."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from orchestrator.compatibility import SCANNER_COMPATIBILITY, get_compatible_scanners, preflight_check
from orchestrator.models import TargetSpec

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(enabled: list[str]) -> dict:
    """Build a minimal settings dict with only the listed scanners enabled."""
    scanners = {}
    for name in ["semgrep", "bandit", "checkov", "gitleaks", "trivy", "syft", "nuclei", "grype", "owasp_zap"]:
        scanners[name] = {"enabled": name in enabled}
    return {"scanners": scanners}


# ---------------------------------------------------------------------------
# SCANNER_COMPATIBILITY matrix sanity checks
# ---------------------------------------------------------------------------


class TestCompatibilityMatrix:
    def test_filesystem_tools_not_in_image(self):
        """SAST tools must not be compatible with image targets."""
        for tool in ("semgrep", "bandit", "checkov", "gitleaks"):
            assert "image" not in SCANNER_COMPATIBILITY.get(
                tool, set()
            ), f"{tool} should not be compatible with 'image' targets"

    def test_trivy_image_only_for_image(self):
        assert SCANNER_COMPATIBILITY["trivy_image"] == {"image"}

    def test_trivy_fs_not_for_image(self):
        assert "image" not in SCANNER_COMPATIBILITY["trivy_fs"]

    def test_zap_only_for_url(self):
        assert SCANNER_COMPATIBILITY["zap"] == {"url"}

    def test_nuclei_supports_url(self):
        assert "url" in SCANNER_COMPATIBILITY["nuclei"]

    def test_grype_supports_image(self):
        assert "image" in SCANNER_COMPATIBILITY["grype"]

    def test_syft_supports_image(self):
        assert "image" in SCANNER_COMPATIBILITY["syft"]


# ---------------------------------------------------------------------------
# get_compatible_scanners
# ---------------------------------------------------------------------------


class TestGetCompatibleScanners:
    def test_git_target_returns_filesystem_tools(self):
        settings = _settings(["semgrep", "bandit", "checkov", "gitleaks", "trivy", "syft"])
        result = get_compatible_scanners("git", settings)
        assert "semgrep" in result
        assert "bandit" in result
        assert "gitleaks" in result
        assert "checkov" in result
        assert "trivy_fs" in result
        assert "syft" in result
        # trivy_image must NOT appear for git targets
        assert "trivy_image" not in result

    def test_image_target_returns_image_tools(self):
        settings = _settings(["trivy", "grype", "syft"])
        result = get_compatible_scanners("image", settings)
        assert "trivy_image" in result
        assert "grype" in result
        assert "syft" in result
        # Filesystem tools must NOT appear
        assert "trivy_fs" not in result
        assert "semgrep" not in result

    def test_url_target_returns_dast_tools(self):
        settings = _settings(["nuclei", "owasp_zap"])
        result = get_compatible_scanners("url", settings)
        assert "nuclei" in result
        assert "zap" in result
        # SAST tools must NOT appear
        assert "semgrep" not in result
        assert "bandit" not in result

    def test_disabled_scanner_excluded(self):
        settings = _settings(["semgrep"])  # only semgrep enabled
        result = get_compatible_scanners("git", settings)
        assert "semgrep" in result
        assert "bandit" not in result

    def test_trivy_expands_to_correct_variant(self):
        """trivy in settings.yaml must expand to trivy_fs for git/local and trivy_image for image."""
        settings = _settings(["trivy"])
        assert "trivy_fs" in get_compatible_scanners("git", settings)
        assert "trivy_image" not in get_compatible_scanners("git", settings)
        assert "trivy_image" in get_compatible_scanners("image", settings)
        assert "trivy_fs" not in get_compatible_scanners("image", settings)

    def test_url_target_excludes_filesystem_tools(self):
        settings = _settings(["semgrep", "bandit", "nuclei", "owasp_zap"])
        result = get_compatible_scanners("url", settings)
        assert "semgrep" not in result
        assert "bandit" not in result
        assert "nuclei" in result

    def test_empty_settings_returns_empty(self):
        result = get_compatible_scanners("git", {"scanners": {}})
        assert result == []


# ---------------------------------------------------------------------------
# preflight_check
# ---------------------------------------------------------------------------


class TestPreflightCheck:
    def test_all_binaries_present(self):
        """When all binaries exist, all tools are runnable and none are skipped."""
        with patch("orchestrator.compatibility.command_exists", return_value=True):
            runnable, skipped = preflight_check(["semgrep", "bandit", "trivy_fs"])
        assert set(runnable) == {"semgrep", "bandit", "trivy_fs"}
        assert skipped == []

    def test_missing_binary_causes_skip(self):
        """A tool whose binary is missing must appear in skipped, not runnable."""

        def _exists(binary: str) -> bool:
            return binary != "gitleaks"

        with patch("orchestrator.compatibility.command_exists", side_effect=_exists):
            runnable, skipped = preflight_check(["semgrep", "gitleaks"])

        assert "semgrep" in runnable
        assert "gitleaks" not in runnable
        assert len(skipped) == 1
        assert skipped[0]["tool"] == "gitleaks"
        assert "gitleaks" in skipped[0]["reason"]

    def test_trivy_fs_and_trivy_image_share_binary(self):
        """trivy_fs and trivy_image must both be runnable when the 'trivy' binary is present."""
        with patch("orchestrator.compatibility.command_exists", return_value=True):
            runnable, skipped = preflight_check(["trivy_fs", "trivy_image"])
        assert "trivy_fs" in runnable
        assert "trivy_image" in runnable
        assert skipped == []

    def test_only_explicit_trivy_variants_share_trivy_binary(self):
        """Binary lookup should use explicit aliases, not fragile suffix stripping."""

        seen = []

        def _exists(binary: str) -> bool:
            seen.append(binary)
            return False

        with patch("orchestrator.compatibility.command_exists", side_effect=_exists):
            runnable, skipped = preflight_check(["trivy_fs", "trivy_image", "nuclei"])

        assert runnable == []
        assert [item["tool"] for item in skipped] == ["trivy_fs", "trivy_image", "nuclei"]
        assert seen == ["trivy", "trivy", "nuclei"]

    def test_tool_without_required_binary_entry_is_runnable(self):
        """A tool with no entry in REQUIRED_BINARIES must not be blocked."""
        with patch("orchestrator.compatibility.command_exists", return_value=False):
            # 'unknown_tool' has no entry in REQUIRED_BINARIES
            runnable, skipped = preflight_check(["unknown_tool"])
        assert "unknown_tool" in runnable
        assert skipped == []

    def test_all_binaries_missing(self):
        with patch("orchestrator.compatibility.command_exists", return_value=False):
            runnable, skipped = preflight_check(["semgrep", "gitleaks", "trivy_fs"])
        assert runnable == []
        assert len(skipped) == 3

    def test_empty_input_returns_empty(self):
        runnable, skipped = preflight_check([])
        assert runnable == []
        assert skipped == []


# ---------------------------------------------------------------------------
# TargetSpec.from_dict — url type
# ---------------------------------------------------------------------------


class TestTargetSpecUrl:
    def test_url_type_accepted(self):
        spec = TargetSpec.from_dict({"type": "url", "url": "https://example.com"})
        assert spec.type == "url"
        assert spec.url == "https://example.com"

    def test_url_resolved_target(self):
        spec = TargetSpec.from_dict({"type": "url", "url": "https://example.com"})
        assert spec.resolved_target == "https://example.com"

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="Unsupported target type"):
            TargetSpec.from_dict({"type": "ftp", "url": "ftp://example.com"})

    def test_all_valid_types_accepted(self):
        valid_inputs = {
            "git": {"type": "git", "repo": "https://example.com/repo.git"},
            "local": {"type": "local", "path": "/tmp/project"},
            "image": {"type": "image", "image": "nginx:latest"},
            "url": {"type": "url", "url": "https://example.com"},
        }
        for t, payload in valid_inputs.items():
            spec = TargetSpec.from_dict(payload)
            assert spec.type == t

    def test_required_target_field_enforced_per_type(self):
        with pytest.raises(ValueError, match="requires a non-empty 'repo'"):
            TargetSpec.from_dict({"type": "git"})
        with pytest.raises(ValueError, match="requires a non-empty 'path'"):
            TargetSpec.from_dict({"type": "local"})
        with pytest.raises(ValueError, match="requires a non-empty 'image'"):
            TargetSpec.from_dict({"type": "image"})
        with pytest.raises(ValueError, match="requires a non-empty 'url'"):
            TargetSpec.from_dict({"type": "url"})
