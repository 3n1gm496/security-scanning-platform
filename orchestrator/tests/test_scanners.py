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

    # without templates/severity/tags — should auto-inject SAST defaults for local target
    res = run_nuclei("/tmp", str(output), target_type="local")
    assert res["exit_code"] == 0
    assert seen, "run_command should have been called"
    assert "-json-export" in seen[0]
    assert "-target" in seen[0]
    assert str(output) in seen[0]
    # auto-inject: -t must be present with at least one default template
    assert "-t" in seen[0]
    assert any("http/" in t for t in seen[0])

    # URL target — should auto-inject DAST defaults (more templates than SAST)
    seen.clear()
    res = run_nuclei("https://example.com", str(output), target_type="url")
    assert res["exit_code"] == 0
    assert "-t" in seen[0]
    # DAST defaults include ssl/ and dns/ which are not in SAST defaults
    assert any("ssl/" in t or "dns/" in t for t in seen[0])

    # with explicit templates — should override auto-inject
    seen.clear()
    res = run_nuclei("/tmp", str(output), templates=["foo.yaml", "bar/"], target_type="url")
    assert res["exit_code"] == 0
    assert "-t" in seen[0]
    assert "foo.yaml" in seen[0] and "bar/" in seen[0]
    # explicit templates should NOT include auto-inject defaults
    assert "ssl/" not in seen[0]

    # with severity and tags
    seen.clear()
    res = run_nuclei("/tmp", str(output), severity="critical,high", tags="xss,sqli")
    assert res["exit_code"] == 0
    assert "-s" in seen[0] and "critical,high" in seen[0]
    assert "-tags" in seen[0] and "xss,sqli" in seen[0]

    # -duc (disable-update-check) must always be present
    seen.clear()
    run_nuclei("/tmp", str(output))
    assert "-duc" in seen[0]


def test_grype_not_found(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    monkeypatch.setattr("orchestrator.scanners.command_exists", lambda name: False)
    with pytest.raises(ScannerError, match="grype not found"):
        run_grype("foo", str(output))


def test_zap_missing_library(tmp_path, monkeypatch):
    """run_owasp_zap must raise ScannerError when python-owasp-zap-v2.4 is not installed."""
    output = tmp_path / "out.json"

    # Simulate missing zapv2 library by making the import fail
    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "zapv2":
            raise ImportError("No module named 'zapv2'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    with pytest.raises(ScannerError, match="python-owasp-zap-v2.4 is not installed"):
        run_owasp_zap("http://example.com", str(output))


def test_zap_full_scan_flow(tmp_path, monkeypatch):
    """run_owasp_zap must spider, active-scan and collect alerts via ZAP REST API."""
    import json as _json

    output = tmp_path / "out.json"

    # Build a minimal ZAPv2 mock
    class FakeSpider:
        def scan(self, url, apikey=""):
            return "1"

        def status(self, scan_id):
            return "100"

    class FakeAscan:
        def scan(self, url, apikey=""):
            return "2"

        def status(self, scan_id):
            return "100"

    class FakeCore:
        def alerts(self, baseurl=""):
            return [{"alert": "Missing X-Frame-Options", "risk": "Medium", "url": baseurl}]

    class FakeZAP:
        def __init__(self, **kwargs):
            self.spider = FakeSpider()
            self.ascan = FakeAscan()
            self.core = FakeCore()

    # Patch the zapv2 import inside scanners module
    import sys
    import types

    fake_module = types.ModuleType("zapv2")
    fake_module.ZAPv2 = FakeZAP
    monkeypatch.setitem(sys.modules, "zapv2", fake_module)

    res = run_owasp_zap("http://example.com", str(output))
    assert res["exit_code"] == 0
    alerts = _json.loads(output.read_text())
    assert len(alerts) == 1
    assert alerts[0]["alert"] == "Missing X-Frame-Options"


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
