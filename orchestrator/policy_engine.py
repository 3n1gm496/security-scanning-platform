"""
Advanced Policy Engine with custom rules, thresholds, and exemptions.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


class PolicyEngine:
    """Advanced policy evaluation engine."""

    def __init__(self, policies_config: dict[str, Any]):
        """Initialize policy engine with configuration.

        Args:
            policies_config: Loaded YAML config with policies and exemptions
        """
        self.policies = policies_config.get("policies", [])
        self.exemptions = policies_config.get("exemptions", [])
        self.default_policy = policies_config.get("default_policy", {})

    @classmethod
    def from_file(cls, policies_file: str) -> "PolicyEngine":
        """Load policy engine from YAML file."""
        with open(policies_file, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        return cls(config)

    def evaluate(
        self,
        findings: list[dict[str, Any]],
        target_name: str,
        target_type: str,
    ) -> dict[str, Any]:
        """Evaluate findings against policies.

        Args:
            findings: List of finding dicts
            target_name: Target name (e.g., "prod-api-server")
            target_type: Target type ("git", "local", "image")

        Returns:
            Dict with: status (PASS/BLOCK), matched_policy, violations, exempted_count
        """
        # Find matching policy
        matched_policy = self._find_matching_policy(target_name, target_type)

        if not matched_policy:
            matched_policy = self.default_policy

        # Apply exemptions first
        active_findings, exempted_count = self._apply_exemptions(findings, target_name)

        # Evaluate rules
        violations = []
        overall_status = "PASS"

        for rule in matched_policy.get("rules", []):
            violation = self._evaluate_rule(rule, active_findings)
            if violation:
                violations.append(violation)
                if violation["action"] == "block":
                    overall_status = "BLOCK"

        return {
            "status": overall_status,
            "policy_name": matched_policy.get("name", "default"),
            "policy_description": matched_policy.get("description", ""),
            "violations": violations,
            "active_findings_count": len(active_findings),
            "exempted_count": exempted_count,
            "total_findings_count": len(findings),
        }

    def _find_matching_policy(self, target_name: str, target_type: str) -> dict[str, Any] | None:
        """Find first matching policy based on target patterns."""
        for policy in self.policies:
            if not policy.get("enabled", True):
                continue

            # Check target_types
            target_types = policy.get("target_types", [])
            if target_types and target_type not in target_types:
                continue

            # Check target_patterns
            patterns = policy.get("target_patterns", [])
            if patterns:
                if any(fnmatch.fnmatch(target_name, pattern) for pattern in patterns):
                    return policy
            else:
                # No patterns = matches all
                return policy

        return None

    def _apply_exemptions(self, findings: list[dict[str, Any]], target_name: str) -> tuple[list[dict[str, Any]], int]:
        """Apply exemptions and return active findings + exempted count."""
        now = datetime.now(timezone.utc)
        active = []
        exempted_count = 0

        for finding in findings:
            is_exempted = False

            for exemption in self.exemptions:
                # Check if exemption expired
                expires_at = exemption.get("expires_at")
                if expires_at:
                    try:
                        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                        if now > expiry:
                            continue  # Expired exemption
                    except Exception:
                        continue  # Unparseable expiry — treat as expired (fail-safe)

                # Match by fingerprint
                if exemption.get("fingerprint") == finding.get("fingerprint"):
                    is_exempted = True
                    break

                # Match by CWE + target pattern — use word-boundary match to avoid
                # false positives (e.g. "CWE-22" must not match "CWE-220").
                if exemption.get("cwe") and exemption.get("target_pattern"):
                    pattern = r"(?<!\w)" + re.escape(str(exemption["cwe"])) + r"(?!\w)"
                    cwe_candidates: list[str] = []
                    explicit_cwe = finding.get("cwe")
                    if explicit_cwe:
                        cwe_candidates.append(str(explicit_cwe))

                    # Backward compatibility: some normalizers still store CWE IDs
                    # in the cve field. Only consider explicit CWE-like tokens.
                    legacy_cve = finding.get("cve")
                    if legacy_cve:
                        cwe_candidates.extend(re.findall(r"CWE-\d+", str(legacy_cve), flags=re.IGNORECASE))

                    cwe_match = any(re.search(pattern, candidate, flags=re.IGNORECASE) for candidate in cwe_candidates)
                    target_match = fnmatch.fnmatch(target_name, exemption["target_pattern"])
                    if cwe_match and target_match:
                        is_exempted = True
                        break

            if is_exempted:
                exempted_count += 1
            else:
                active.append(finding)

        return active, exempted_count

    def _evaluate_rule(self, rule: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Evaluate a single rule against findings."""
        rule_name = rule.get("name", "Unnamed Rule")
        action = rule.get("action", "warn")
        message = rule.get("message", "Policy violation")

        severities = rule.get("severities", [])
        categories = rule.get("categories", [])
        threshold = rule.get("threshold")

        # Filter findings matching this rule
        matching = []
        for finding in findings:
            sev_match = not severities or finding.get("severity", "").upper() in [s.upper() for s in severities]
            cat_match = not categories or finding.get("category", "").lower() in [c.lower() for c in categories]

            if sev_match and cat_match:
                matching.append(finding)

        # Check threshold
        if threshold is not None:
            if len(matching) <= threshold:
                return None  # Rule not violated
        else:
            if len(matching) == 0:
                return None  # No findings = no violation

        # Violation detected
        return {
            "rule_name": rule_name,
            "action": action,
            "message": message,
            "matching_findings_count": len(matching),
            "threshold": threshold,
            "matching_findings": matching[:10],  # Include up to 10 examples
        }


def load_policy_engine(policies_file: str = "/app/config/policies.yaml") -> PolicyEngine:
    """Load policy engine from file, with fallback to default."""
    if Path(policies_file).exists():
        return PolicyEngine.from_file(policies_file)

    # Fallback to simple default policy
    default_config = {
        "default_policy": {
            "name": "default-block-critical",
            "rules": [
                {"severities": ["CRITICAL"], "action": "block"},
                {"categories": ["secret"], "action": "block"},
            ],
        },
        "policies": [],
        "exemptions": [],
    }

    return PolicyEngine(default_config)
