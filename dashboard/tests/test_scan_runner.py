"""Unit tests for scan_runner.py."""

import sys
from pathlib import Path

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

import scan_runner as _scan_runner


def test_run_scan_respects_dashboard_db_path_env(monkeypatch, tmp_path):
    """The orchestrator subprocess must inherit the configured dashboard DB path."""
    db_path = tmp_path / "custom.db"
    reports_dir = tmp_path / "reports"
    workspaces_dir = tmp_path / "workspaces"
    cache_dir = tmp_path / "cache"

    monkeypatch.setenv("DASHBOARD_DB_PATH", str(db_path))
    monkeypatch.setenv("REPORTS_DIR", str(reports_dir))
    monkeypatch.setenv("WORKSPACE_DIR", str(workspaces_dir))
    monkeypatch.setenv("ORCH_CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(_scan_runner, "insert_running_scan", lambda *args, **kwargs: None)
    monkeypatch.setattr(_scan_runner, "publish_sync", lambda *args, **kwargs: None)

    seen = {}

    class FakeCompletedProcess:
        returncode = 0
        stdout = "{}"

    def fake_run(cmd, cwd=None, stdout=None, stderr=None, text=None, env=None, timeout=None):
        seen["cmd"] = cmd
        seen["cwd"] = cwd
        seen["env"] = env
        return FakeCompletedProcess()

    monkeypatch.setattr(_scan_runner.subprocess, "run", fake_run)

    result = _scan_runner.run_scan("git", "https://example.com/repo.git", "repo", str(tmp_path))

    assert result["status"] == "completed"
    assert seen["env"]["ORCH_DB_PATH"] == str(db_path)
    assert seen["env"]["DASHBOARD_DB_PATH"] == str(db_path)
    assert seen["env"]["REPORTS_DIR"] == str(reports_dir)
    assert seen["env"]["WORKSPACE_DIR"] == str(workspaces_dir)
    assert seen["env"]["ORCH_CACHE_DIR"] == str(cache_dir)
