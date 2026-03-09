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
