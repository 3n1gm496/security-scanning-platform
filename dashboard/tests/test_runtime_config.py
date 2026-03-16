from __future__ import annotations

from pathlib import Path
import sys

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

import runtime_config


def test_resolve_dashboard_db_path_prefers_env(monkeypatch):
    monkeypatch.setenv("DASHBOARD_DB_PATH", "/tmp/custom-dashboard.db")
    assert runtime_config.resolve_dashboard_db_path() == "/tmp/custom-dashboard.db"


def test_resolve_dashboard_db_path_falls_back_to_repo_data(monkeypatch):
    monkeypatch.delenv("DASHBOARD_DB_PATH", raising=False)
    monkeypatch.setattr(runtime_config, "_running_in_container", lambda: False)
    results = iter([False, True])
    monkeypatch.setattr(runtime_config, "_path_is_writable", lambda path: next(results))
    expected = str(Path(runtime_config.__file__).resolve().parent.parent / "data" / "security_scans.db")

    resolved = runtime_config.resolve_dashboard_db_path()

    assert resolved == expected
