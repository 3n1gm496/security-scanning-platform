from __future__ import annotations

import os
import time
from pathlib import Path

from orchestrator.retention import apply_retention


def _touch_with_age(path: Path, age_days: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix:
        path.write_text("x", encoding="utf-8")
    else:
        path.mkdir(parents=True, exist_ok=True)
    ts = time.time() - age_days * 86400
    os.utime(path, (ts, ts))


def test_apply_retention_removes_expired_entries(tmp_path):
    reports_dir = tmp_path / "reports"
    workspaces_dir = tmp_path / "workspaces"
    cache_dir = tmp_path / "cache"

    old_report = reports_dir / "old-scan"
    new_report = reports_dir / "new-scan"
    old_workspace = workspaces_dir / "old-ws"
    old_cache_file = cache_dir / "old-cache.json"

    _touch_with_age(old_report, 30)
    _touch_with_age(new_report, 1)
    _touch_with_age(old_workspace, 10)
    _touch_with_age(old_cache_file, 20)

    settings = {
        "paths": {
            "reports_dir": str(reports_dir),
            "workspace_dir": str(workspaces_dir),
        },
        "cache": {
            "dir": str(cache_dir),
        },
        "retention": {
            "enabled": True,
            "reports_days": 14,
            "workspaces_days": 3,
            "cache_days": 7,
        },
    }

    result = apply_retention(settings)

    assert result["reports_removed"] == 1
    assert result["workspaces_removed"] == 1
    assert result["cache_removed"] == 1
    assert result["dry_run"] is False

    assert not old_report.exists()
    assert new_report.exists()
    assert not old_workspace.exists()
    assert not old_cache_file.exists()


def test_apply_retention_disabled(tmp_path):
    reports_dir = tmp_path / "reports"
    old_report = reports_dir / "old-scan"
    _touch_with_age(old_report, 30)

    settings = {
        "paths": {"reports_dir": str(reports_dir), "workspace_dir": str(tmp_path / "workspaces")},
        "cache": {"dir": str(tmp_path / "cache")},
        "retention": {"enabled": False},
    }

    result = apply_retention(settings)

    assert result == {"reports_removed": 0, "workspaces_removed": 0, "cache_removed": 0, "dry_run": False}
    assert old_report.exists()


def test_apply_retention_dry_run(tmp_path):
    reports_dir = tmp_path / "reports"
    old_report = reports_dir / "old-scan"
    _touch_with_age(old_report, 30)

    settings = {
        "paths": {
            "reports_dir": str(reports_dir),
            "workspace_dir": str(tmp_path / "workspaces"),
        },
        "cache": {"dir": str(tmp_path / "cache")},
        "retention": {
            "enabled": True,
            "reports_days": 14,
            "workspaces_days": 3,
            "cache_days": 7,
        },
    }

    result = apply_retention(settings, dry_run=True)

    assert result["reports_removed"] == 1
    assert result["workspaces_removed"] == 0
    assert result["cache_removed"] == 0
    assert result["dry_run"] is True
    assert old_report.exists()
