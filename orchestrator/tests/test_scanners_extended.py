"""Extended scanner tests covering semgrep, trivy, gitleaks, checkov, syft with mocks."""

from __future__ import annotations

import json

import pytest

from orchestrator.scanners import (
    ScannerError,
    RateLimitError,
    run_semgrep,
    run_trivy_fs,
    run_trivy_image,
    run_gitleaks,
    run_checkov,
    run_syft,
    run_bandit,
    run_grype,
    ensure_json_file,
    load_json,
)

# ---------------------------------------------------------------------------
# ensure_json_file
# ---------------------------------------------------------------------------


def test_ensure_json_file_creates_file(tmp_path):
    output = tmp_path / "out.json"
    ensure_json_file(str(output), {"key": "value"})
    assert output.exists()
    data = json.loads(output.read_text())
    assert data == {"key": "value"}


def test_ensure_json_file_does_not_overwrite(tmp_path):
    output = tmp_path / "out.json"
    output.write_text('{"existing": true}', encoding="utf-8")
    ensure_json_file(str(output), {"key": "value"})
    data = json.loads(output.read_text())
    assert data == {"existing": True}


def test_ensure_json_file_creates_parent_dirs(tmp_path):
    output = tmp_path / "nested" / "dir" / "out.json"
    ensure_json_file(str(output), [])
    assert output.exists()


# ---------------------------------------------------------------------------
# load_json
# ---------------------------------------------------------------------------


def test_load_json_dict(tmp_path):
    f = tmp_path / "data.json"
    f.write_text('{"a": 1}', encoding="utf-8")
    result = load_json(str(f))
    assert result == {"a": 1}


def test_load_json_list(tmp_path):
    f = tmp_path / "data.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    result = load_json(str(f))
    assert result == [1, 2, 3]


# ---------------------------------------------------------------------------
# run_semgrep
# ---------------------------------------------------------------------------


def test_semgrep_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    output = tmp_path / "out.json"
    with pytest.raises(ScannerError, match="semgrep not found"):
        run_semgrep("/tmp", str(output), configs=["auto"])


def test_semgrep_success(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    semgrep_output = '{"results": [], "errors": []}'

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (0, semgrep_output, "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_semgrep("/tmp", str(output), configs=["auto"])
    assert res["exit_code"] == 0
    assert output.read_text() == semgrep_output


def test_semgrep_exit_code_1_is_ok(tmp_path, monkeypatch):
    """Exit code 1 means findings found but no error."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    findings_output = '{"results": [{"check_id": "test"}]}'

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (1, findings_output, "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_semgrep("/tmp", str(output), configs=["p/python"])
    assert res["exit_code"] == 1


def test_semgrep_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (2, "", "fatal error: invalid config")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="semgrep execution failed"):
        run_semgrep("/tmp", str(output), configs=["auto"])


def test_semgrep_rate_limit_raises(tmp_path, monkeypatch):
    """Rate limit errors should eventually raise after retries."""
    import tenacity

    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (429, "", "rate limit exceeded")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    # tenacity wraps the RateLimitError in a RetryError after exhausting attempts
    with pytest.raises((RateLimitError, ScannerError, tenacity.RetryError)):
        run_semgrep("/tmp", str(output), configs=["auto"])


def test_semgrep_includes_configs_in_command(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen_cmds = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen_cmds.append(cmd)
        return (0, '{"results": []}', "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_semgrep("/tmp", str(output), configs=["p/python", "p/security"])
    assert "--config" in seen_cmds[0]
    assert "p/python" in seen_cmds[0]
    assert "p/security" in seen_cmds[0]


# ---------------------------------------------------------------------------
# run_trivy_fs
# ---------------------------------------------------------------------------


def test_trivy_fs_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    output = tmp_path / "out.json"
    with pytest.raises(ScannerError, match="trivy not found"):
        run_trivy_fs("/tmp", str(output), severities=[])


def test_trivy_fs_success(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    trivy_output = '{"Results": []}'

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (0, trivy_output, "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_trivy_fs("/tmp", str(output), severities=["HIGH", "CRITICAL"])
    assert res["exit_code"] == 0
    assert output.read_text() == trivy_output


def test_trivy_fs_with_severities_and_ignore_unfixed(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen.append(cmd)
        return (0, '{"Results": []}', "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_trivy_fs("/tmp", str(output), severities=["CRITICAL"], ignore_unfixed=True)
    cmd = seen[0]
    assert "--severity" in cmd
    assert "CRITICAL" in cmd
    assert "--ignore-unfixed" in cmd


def test_trivy_fs_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (2, "", "fatal: cannot open target")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="trivy fs failed"):
        run_trivy_fs("/tmp", str(output), severities=[])


def test_trivy_fs_empty_output_fallback(tmp_path, monkeypatch):
    """Empty stdout should produce a valid JSON fallback."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_trivy_fs("/tmp", str(output), severities=[])
    data = json.loads(output.read_text())
    assert "Results" in data


# ---------------------------------------------------------------------------
# run_trivy_image
# ---------------------------------------------------------------------------


def test_trivy_image_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    output = tmp_path / "out.json"
    with pytest.raises(ScannerError, match="trivy not found"):
        run_trivy_image("nginx:latest", str(output), severities=[])


def test_trivy_image_success(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    trivy_output = '{"Results": [{"Target": "nginx:latest"}]}'

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (0, trivy_output, "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_trivy_image("nginx:latest", str(output), severities=["HIGH"])
    assert res["exit_code"] == 0
    assert "nginx" in output.read_text()


def test_trivy_image_with_ignore_unfixed(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen.append(cmd)
        return (0, '{"Results": []}', "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_trivy_image("nginx:latest", str(output), severities=[], ignore_unfixed=True)
    assert "--ignore-unfixed" in seen[0]


def test_trivy_image_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (2, "", "image not found")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="trivy image failed"):
        run_trivy_image("nonexistent:latest", str(output), severities=[])


# ---------------------------------------------------------------------------
# run_gitleaks
# ---------------------------------------------------------------------------


def test_gitleaks_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    output = tmp_path / "out.json"
    with pytest.raises(ScannerError, match="gitleaks not found"):
        run_gitleaks("/tmp", str(output))


def test_gitleaks_success_no_findings(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        # gitleaks exits 0 when no leaks found
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_gitleaks("/tmp", str(output))
    assert res["exit_code"] == 0
    # ensure_json_file should create the file with []
    assert json.loads(output.read_text()) == []


def test_gitleaks_exit_1_means_findings(tmp_path, monkeypatch):
    """Exit code 1 means leaks were found — not an error."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    # Simulate gitleaks writing the report file
    findings_data = [{"RuleID": "aws-key", "File": "config.py", "StartLine": 5}]

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        # Write the output file as gitleaks would
        output.write_text(json.dumps(findings_data), encoding="utf-8")
        return (1, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_gitleaks("/tmp", str(output))
    assert res["exit_code"] == 1
    assert json.loads(output.read_text()) == findings_data


def test_gitleaks_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (2, "", "fatal: invalid path")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="gitleaks failed"):
        run_gitleaks("/tmp", str(output))


def test_gitleaks_dir_mode(tmp_path, monkeypatch):
    """use_git_history=False should use 'dir' subcommand."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen.append(cmd)
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_gitleaks("/tmp", str(output), use_git_history=False)
    assert "dir" in seen[0]
    assert "git" not in seen[0][1]  # second element is the subcommand


def test_gitleaks_git_mode(tmp_path, monkeypatch):
    """use_git_history=True (default) should use 'git' subcommand."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen.append(cmd)
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_gitleaks("/tmp", str(output), use_git_history=True)
    assert seen[0][1] == "git"


# ---------------------------------------------------------------------------
# run_checkov
# ---------------------------------------------------------------------------


def test_checkov_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    output = tmp_path / "out.json"
    with pytest.raises(ScannerError, match="checkov not found"):
        run_checkov("/tmp", str(output))


def test_checkov_success(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    checkov_output = '{"results": {"failed_checks": [], "passed_checks": []}}'

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (0, checkov_output, "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_checkov("/tmp", str(output))
    assert res["exit_code"] == 0
    assert output.read_text() == checkov_output


def test_checkov_exit_1_is_ok(tmp_path, monkeypatch):
    """Exit code 1 means failed checks found — not a fatal error."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    checkov_output = '{"results": {"failed_checks": [{"check_id": "CKV_X_1"}]}}'

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (1, checkov_output, "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_checkov("/tmp", str(output))
    assert res["exit_code"] == 1


def test_checkov_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (2, "", "Error: invalid directory")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="checkov failed"):
        run_checkov("/tmp", str(output))


def test_checkov_empty_output_fallback(tmp_path, monkeypatch):
    """Empty stdout should produce a valid JSON fallback."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_checkov("/tmp", str(output))
    data = json.loads(output.read_text())
    assert "results" in data


def test_checkov_command_flags(tmp_path, monkeypatch):
    """Verify checkov is invoked with expected flags."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen.append(cmd)
        return (0, '{"results": {"failed_checks": []}}', "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_checkov("/tmp/mydir", str(output))
    cmd = seen[0]
    assert "checkov" in cmd[0]
    assert "-d" in cmd
    assert "/tmp/mydir" in cmd
    assert "-o" in cmd
    assert "json" in cmd
    assert "--quiet" in cmd


# ---------------------------------------------------------------------------
# run_syft
# ---------------------------------------------------------------------------


def test_syft_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    output = tmp_path / "out.json"
    with pytest.raises(ScannerError, match="syft not found"):
        run_syft("nginx:latest", str(output))


def test_syft_success(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    syft_output = '{"spdxVersion": "SPDX-2.3", "packages": []}'
    output.write_text(syft_output, encoding="utf-8")  # syft writes to file directly

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        # syft writes to the output file specified in the command
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_syft("nginx:latest", str(output))
    assert res["exit_code"] == 0


def test_syft_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (1, "", "image not found")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="syft failed"):
        run_syft("nonexistent:latest", str(output))


def test_syft_command_format(tmp_path, monkeypatch):
    """Verify syft is invoked with spdx-json output format."""
    output = tmp_path / "out.json"
    output.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}', encoding="utf-8")
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen.append(cmd)
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_syft("nginx:latest", str(output))
    cmd = seen[0]
    assert "syft" in cmd[0]
    assert "nginx:latest" in cmd
    assert any(f"spdx-json={output}" in arg for arg in cmd)


# ---------------------------------------------------------------------------
# run_bandit (extended)
# ---------------------------------------------------------------------------


def test_bandit_success_with_findings(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    bandit_data = {"results": [{"filename": "app.py", "issue_severity": "LOW"}]}

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        output.write_text(json.dumps(bandit_data), encoding="utf-8")
        return (1, "", "")  # exit 1 = findings found

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_bandit("/tmp", str(output))
    assert res["exit_code"] == 1
    data = json.loads(output.read_text())
    assert len(data["results"]) == 1


def test_bandit_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (2, "", "fatal: cannot scan")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="bandit execution failed"):
        run_bandit("/tmp", str(output))


def test_bandit_empty_output_fallback(tmp_path, monkeypatch):
    """When bandit produces no output file, fallback should be written."""
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        # bandit ran but produced no output file
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    run_bandit("/tmp", str(output))
    data = json.loads(output.read_text())
    assert "results" in data


# ---------------------------------------------------------------------------
# run_grype (extended)
# ---------------------------------------------------------------------------


def test_grype_success(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    grype_output = '{"matches": [{"artifact": {"name": "pkg"}, "vulnerability": {"id": "CVE-X"}}]}'

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (0, grype_output, "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    res = run_grype("nginx:latest", str(output))
    assert res["exit_code"] == 0
    data = json.loads(output.read_text())
    assert len(data["matches"]) == 1


def test_grype_fatal_error_raises(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        return (2, "", "fatal error")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)
    with pytest.raises(ScannerError, match="grype failed"):
        run_grype("nginx:latest", str(output))
