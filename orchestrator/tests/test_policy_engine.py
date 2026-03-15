"""Unit tests for advanced policy engine."""

from orchestrator.policy_engine import PolicyEngine


def _engine_config():
    return {
        "default_policy": {
            "name": "default",
            "rules": [
                {
                    "name": "block-critical",
                    "severities": ["CRITICAL"],
                    "action": "block",
                    "threshold": 0,
                }
            ],
        },
        "policies": [
            {
                "name": "prod",
                "enabled": True,
                "target_types": ["git"],
                "target_patterns": ["prod-*"],
                "rules": [
                    {
                        "name": "no-high-in-prod",
                        "severities": ["HIGH"],
                        "action": "block",
                        "threshold": 0,
                    }
                ],
            }
        ],
        "exemptions": [
            {"fingerprint": "fp-exempt"},
            {"cwe": "CWE-79", "target_pattern": "dev-*"},
        ],
    }


def test_default_policy_passes_without_critical():
    engine = PolicyEngine(_engine_config())
    findings = [{"severity": "HIGH", "fingerprint": "fp1", "category": "sca"}]
    result = engine.evaluate(findings, target_name="repo-a", target_type="git")
    assert result["status"] == "PASS"
    assert result["policy_name"] == "default"


def test_default_policy_blocks_critical():
    engine = PolicyEngine(_engine_config())
    findings = [{"severity": "CRITICAL", "fingerprint": "fp1", "category": "sca"}]
    result = engine.evaluate(findings, target_name="repo-a", target_type="git")
    assert result["status"] == "BLOCK"
    assert len(result["violations"]) == 1


def test_prod_policy_matches_and_blocks_high():
    engine = PolicyEngine(_engine_config())
    findings = [{"severity": "HIGH", "fingerprint": "fp1", "category": "sca"}]
    result = engine.evaluate(findings, target_name="prod-api", target_type="git")
    assert result["policy_name"] == "prod"
    assert result["status"] == "BLOCK"


def test_exemption_by_fingerprint():
    engine = PolicyEngine(_engine_config())
    findings = [{"severity": "CRITICAL", "fingerprint": "fp-exempt", "category": "sca"}]
    result = engine.evaluate(findings, target_name="repo-a", target_type="git")
    assert result["status"] == "PASS"
    assert result["exempted_count"] == 1
    assert result["active_findings_count"] == 0


def test_exemption_by_cwe_and_target_pattern():
    engine = PolicyEngine(_engine_config())
    findings = [{"severity": "CRITICAL", "fingerprint": "fp1", "cve": "CWE-79"}]
    result = engine.evaluate(findings, target_name="dev-service", target_type="git")
    assert result["status"] == "PASS"
    assert result["exempted_count"] == 1


# ---------------------------------------------------------------------------
# Fix batch regression tests
# ---------------------------------------------------------------------------


class TestInvalidExpiryTreatedAsExpired:
    """An exemption with an unparseable expires_at must be treated as expired.

    Previously the bare `except: pass` left the exemption active, allowing
    findings to bypass policy checks silently.
    """

    def test_malformed_expiry_exemption_not_applied(self):
        config = {
            "default_policy": {
                "name": "default",
                "rules": [{"severities": ["CRITICAL"], "action": "block", "threshold": 0}],
            },
            "policies": [],
            "exemptions": [
                {
                    "fingerprint": "fp-bad-expiry",
                    "expires_at": "not-a-date",  # invalid ISO string
                }
            ],
        }
        engine = PolicyEngine(config)
        findings = [{"severity": "CRITICAL", "fingerprint": "fp-bad-expiry"}]
        result = engine.evaluate(findings, target_name="repo", target_type="git")
        # The exemption must NOT apply because the expiry is unparseable.
        assert result["status"] == "BLOCK"
        assert result["exempted_count"] == 0

    def test_valid_future_expiry_exemption_still_applied(self):
        config = {
            "default_policy": {
                "name": "default",
                "rules": [{"severities": ["CRITICAL"], "action": "block", "threshold": 0}],
            },
            "policies": [],
            "exemptions": [
                {
                    "fingerprint": "fp-future",
                    "expires_at": "2099-12-31T23:59:59+00:00",
                }
            ],
        }
        engine = PolicyEngine(config)
        findings = [{"severity": "CRITICAL", "fingerprint": "fp-future"}]
        result = engine.evaluate(findings, target_name="repo", target_type="git")
        assert result["status"] == "PASS"
        assert result["exempted_count"] == 1

    def test_expired_exemption_not_applied(self):
        config = {
            "default_policy": {
                "name": "default",
                "rules": [{"severities": ["CRITICAL"], "action": "block", "threshold": 0}],
            },
            "policies": [],
            "exemptions": [
                {
                    "fingerprint": "fp-past",
                    "expires_at": "2000-01-01T00:00:00+00:00",
                }
            ],
        }
        engine = PolicyEngine(config)
        findings = [{"severity": "CRITICAL", "fingerprint": "fp-past"}]
        result = engine.evaluate(findings, target_name="repo", target_type="git")
        assert result["status"] == "BLOCK"
        assert result["exempted_count"] == 0


class TestCweWordBoundaryMatch:
    """CWE exemption must use word-boundary matching to prevent false positives.

    E.g. exempting CWE-22 must not exempt a finding with CWE-220.
    """

    def _config_with_cwe(self, cwe: str) -> dict:
        return {
            "default_policy": {
                "name": "default",
                "rules": [{"severities": ["HIGH"], "action": "block", "threshold": 0}],
            },
            "policies": [],
            "exemptions": [{"cwe": cwe, "target_pattern": "dev-*"}],
        }

    def test_cwe_exact_match_is_exempt(self):
        engine = PolicyEngine(self._config_with_cwe("CWE-22"))
        findings = [{"severity": "HIGH", "fingerprint": "fp1", "cve": "CWE-22"}]
        result = engine.evaluate(findings, target_name="dev-svc", target_type="git")
        assert result["exempted_count"] == 1
        assert result["status"] == "PASS"

    def test_cwe_substring_is_not_exempt(self):
        """CWE-22 must NOT exempt a finding whose cve field contains CWE-220."""
        engine = PolicyEngine(self._config_with_cwe("CWE-22"))
        findings = [{"severity": "HIGH", "fingerprint": "fp2", "cve": "CWE-220"}]
        result = engine.evaluate(findings, target_name="dev-svc", target_type="git")
        assert result["exempted_count"] == 0
        assert result["status"] == "BLOCK"

    def test_cwe_prefix_is_not_exempt(self):
        """CWE-7 must NOT match CWE-79."""
        engine = PolicyEngine(self._config_with_cwe("CWE-7"))
        findings = [{"severity": "HIGH", "fingerprint": "fp3", "cve": "CWE-79"}]
        result = engine.evaluate(findings, target_name="dev-svc", target_type="git")
        assert result["exempted_count"] == 0
        assert result["status"] == "BLOCK"

    def test_cwe_match_in_comma_separated_list(self):
        """CWE-22 should match when it appears as one of multiple values."""
        engine = PolicyEngine(self._config_with_cwe("CWE-22"))
        findings = [{"severity": "HIGH", "fingerprint": "fp4", "cve": "CWE-22,CWE-35"}]
        result = engine.evaluate(findings, target_name="dev-svc", target_type="git")
        assert result["exempted_count"] == 1

    def test_plain_cve_identifier_does_not_match_cwe_exemption(self):
        """A CVE identifier must not accidentally satisfy a CWE exemption."""
        engine = PolicyEngine(self._config_with_cwe("CWE-22"))
        findings = [{"severity": "HIGH", "fingerprint": "fp5", "cve": "CVE-2024-12345"}]
        result = engine.evaluate(findings, target_name="dev-svc", target_type="git")
        assert result["exempted_count"] == 0
        assert result["status"] == "BLOCK"
