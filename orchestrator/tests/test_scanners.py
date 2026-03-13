import pytest
import json
from orchestrator.scanners import (
    run_bandit,
    run_nuclei,
    run_grype,
    run_owasp_zap,
    ScannerError,
    command_exists,
    clone_repo,
)

# monkeypatch command_exists to simulate missing binaries


@pytest.fixture(autouse=True)
def disable_commands(monkeypatch):
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    yield


def test_bandit_not_found(tmp_path, monkeypatch):
    # when binary missing, wrapper must raise ScannerError instead of silently succeeding
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    with pytest.raises(ScannerError, match="bandit not found"):
        run_bandit("/tmp", str(output))


def test_nuclei_not_found(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    with pytest.raises(ScannerError, match="nuclei not found"):
        run_nuclei("/tmp", str(output))


def test_nuclei_command_format_and_templates(tmp_path, monkeypatch):
    # verify that, when present, the nuclei CLI is invoked with the expected
    # flags and that template/severity/tags arguments are propagated correctly.
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: True)
    seen = []

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen.append(cmd)
        return (0, "[]", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)

    # without templates/severity/tags
    res = run_nuclei("/tmp", str(output))
    assert res["exit_code"] == 0
    assert seen, "run_command should have been called"
    assert "-json-export" in seen[0]
    assert "-target" in seen[0]
    assert str(output) in seen[0]

    # with templates specified
    seen.clear()
    res = run_nuclei("/tmp", str(output), templates=["foo.yaml", "bar/"])
    assert res["exit_code"] == 0
    assert "-t" in seen[0]
    assert "foo.yaml" in seen[0] and "bar/" in seen[0]

    # with severity and tags
    seen.clear()
    res = run_nuclei("/tmp", str(output), severity="critical,high", tags="xss,sqli")
    assert res["exit_code"] == 0
    assert "-s" in seen[0] and "critical,high" in seen[0]
    assert "-tags" in seen[0] and "xss,sqli" in seen[0]


def test_grype_not_found(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    with pytest.raises(ScannerError, match="grype not found"):
        run_grype("foo", str(output))


def test_zap_not_found(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    with pytest.raises(ScannerError, match="zap-cli not found"):
        run_owasp_zap("http://example.com", str(output))


def test_clone_repo_env_and_command(monkeypatch, tmp_path):
    # ensure clone_repo builds the expected git command and sets the
    # GIT_TERMINAL_PROMPT environment variable to disable interactivity.
    # Default depth=0 means full clone: --depth must NOT appear.
    seen = {}

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen["cmd"] = cmd
        seen["env"] = env or {}
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)

    dest = tmp_path / "repo"
    clone_repo("https://github.com/foo/bar.git", str(dest), ref="main")
    # Full clone (depth=0): --depth must be absent
    assert "--depth" not in seen["cmd"], "depth=0 must not add --depth to git clone"
    assert "--branch" in seen["cmd"] and "main" in seen["cmd"]
    assert seen["cmd"][-2:] == ["https://github.com/foo/bar.git", str(dest)]
    # verify environment variable
    assert seen["env"].get("GIT_TERMINAL_PROMPT") == "0"


def test_clone_repo_shallow_depth(monkeypatch, tmp_path):
    """When depth > 0, --depth N must be passed to git clone."""
    seen = {}

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen["cmd"] = cmd
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)

    dest = tmp_path / "repo"
    clone_repo("https://github.com/foo/bar.git", str(dest), depth=50)
    assert "--depth" in seen["cmd"]
    depth_idx = seen["cmd"].index("--depth")
    assert seen["cmd"][depth_idx + 1] == "50"


def test_clone_repo_full_history_no_depth_flag(monkeypatch, tmp_path):
    """Explicit depth=0 must produce a full clone (no --depth flag)."""
    seen = {}

    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        seen["cmd"] = cmd
        return (0, "", "")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)

    dest = tmp_path / "repo"
    clone_repo("https://github.com/foo/bar.git", str(dest), depth=0)
    assert "--depth" not in seen["cmd"]


def test_clone_repo_failure(monkeypatch, tmp_path):
    # simulate git prompting for credentials / returning non-zero
    def fake_run_command(cmd, cwd=None, timeout=None, env=None):
        # mimic git writing a username prompt to stderr and failing
        return (128, "", "Username for 'https://github.com': \nfatal: could not read Username\n")

    monkeypatch.setattr("orchestrator.scanners.run_command", fake_run_command)

    with pytest.raises(ScannerError) as excinfo:
        clone_repo("https://github.com/githubtraining/hellogitworld.git", str(tmp_path / "repo"))
    assert "git clone failed" in str(excinfo.value)


def test_clone_repo_rejects_file_scheme(tmp_path):
    """file:// URLs must be rejected to prevent SSRF / local file access."""
    with pytest.raises(ScannerError, match="Unsupported URL scheme"):
        clone_repo("file:///etc/passwd", str(tmp_path / "repo"))


def test_clone_repo_rejects_ssh_scheme(tmp_path):
    """ssh:// URLs must be rejected."""
    with pytest.raises(ScannerError, match="Unsupported URL scheme"):
        clone_repo("ssh://git@github.com/foo/bar.git", str(tmp_path / "repo"))


def test_clone_repo_rejects_git_scheme(tmp_path):
    """git:// URLs must be rejected (unencrypted protocol)."""
    with pytest.raises(ScannerError, match="Unsupported URL scheme"):
        clone_repo("git://github.com/foo/bar.git", str(tmp_path / "repo"))


def test_clone_repo_allows_https(monkeypatch, tmp_path):
    """https:// URLs must be accepted."""
    monkeypatch.setattr("orchestrator.scanners.run_command", lambda cmd, cwd=None, timeout=None, env=None: (0, "", ""))
    clone_repo("https://github.com/foo/bar.git", str(tmp_path / "repo"))


def test_clone_repo_allows_http(monkeypatch, tmp_path):
    """http:// URLs must be accepted (some internal repos use plain HTTP)."""
    monkeypatch.setattr("orchestrator.scanners.run_command", lambda cmd, cwd=None, timeout=None, env=None: (0, "", ""))
    clone_repo("http://internal.corp/foo/bar.git", str(tmp_path / "repo"))
