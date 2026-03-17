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


def test_run_scan_returns_error_on_nonzero_exit_with_json(monkeypatch, tmp_path):
    monkeypatch.setattr(_scan_runner, "insert_running_scan", lambda *args, **kwargs: None)
    published = []
    failed_updates = []
    monkeypatch.setattr(_scan_runner, "publish_sync", lambda event, payload: published.append((event, payload)))
    monkeypatch.setattr(
        _scan_runner, "update_scan_failed", lambda scan_id, message: failed_updates.append((scan_id, message))
    )

    class FakeCompletedProcess:
        returncode = 4
        stdout = (
            '{"results":[{"scan_id":"scan-123","status":"FAILED","error_message":"Tool execution failed"}],'
            '"generated_at":"2026-03-17T00:00:00+00:00"}'
        )

    monkeypatch.setattr(_scan_runner.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())

    result = _scan_runner.run_scan("git", "https://example.com/repo.git", "repo", str(tmp_path), scan_id="scan-123")

    assert result["status"] == "error"
    assert result["returncode"] == 4
    assert result["message"] == "Tool execution failed"
    assert failed_updates == [("scan-123", "Tool execution failed")]
    assert published == [
        ("scan_started", {"scan_id": "scan-123", "target_name": "repo", "target_type": "git"}),
        ("scan_failed", {"scan_id": "scan-123", "target_name": "repo", "error": "Tool execution failed"}),
    ]


def test_run_scan_returns_blocked_on_policy_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(_scan_runner, "insert_running_scan", lambda *args, **kwargs: None)
    published = []
    monkeypatch.setattr(_scan_runner, "publish_sync", lambda event, payload: published.append((event, payload)))
    monkeypatch.setattr(_scan_runner, "update_scan_failed", lambda *args, **kwargs: None)

    class FakeCompletedProcess:
        returncode = 3
        stdout = (
            '{"results":[{"scan_id":"scan-456","status":"BLOCK","error_message":"Blocked by policy"}],'
            '"generated_at":"2026-03-17T00:00:00+00:00"}'
        )

    monkeypatch.setattr(_scan_runner.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())

    result = _scan_runner.run_scan("git", "https://example.com/repo.git", "repo", str(tmp_path), scan_id="scan-456")

    assert result["status"] == "blocked"
    assert result["returncode"] == 3
    assert result["message"] == "Blocked by policy"
    assert published == [
        ("scan_started", {"scan_id": "scan-456", "target_name": "repo", "target_type": "git"}),
        ("scan_failed", {"scan_id": "scan-456", "target_name": "repo", "error": "Blocked by policy"}),
    ]


def test_run_scan_records_scan_and_cache_metrics(monkeypatch, tmp_path):
    monkeypatch.setattr(_scan_runner, "insert_running_scan", lambda *args, **kwargs: None)
    monkeypatch.setattr(_scan_runner, "publish_sync", lambda *args, **kwargs: None)

    scan_metrics = []
    cache_metrics = []

    monkeypatch.setattr(
        _scan_runner,
        "record_scan_metric",
        lambda status, policy_status, duration_seconds=None: scan_metrics.append(
            (status, policy_status, duration_seconds)
        ),
    )
    monkeypatch.setattr(_scan_runner, "record_cache_operation", lambda result: cache_metrics.append(result))

    class FakeCompletedProcess:
        returncode = 0
        stdout = (
            '{"results":[{"scan_id":"scan-789","status":"COMPLETED_WITH_FINDINGS","policy_status":"PASS",'
            '"tools":[{"name":"semgrep","cache_hit":true},{"name":"bandit","cache_hit":false}]}]}'
        )

    monkeypatch.setattr(_scan_runner.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())

    result = _scan_runner.run_scan("git", "https://example.com/repo.git", "repo", str(tmp_path), scan_id="scan-789")

    assert result["status"] == "completed"
    assert cache_metrics == ["hit", "miss"]
    assert len(scan_metrics) == 1
    assert scan_metrics[0][0] == "COMPLETED_WITH_FINDINGS"
    assert scan_metrics[0][1] == "PASS"
    assert scan_metrics[0][2] is not None
