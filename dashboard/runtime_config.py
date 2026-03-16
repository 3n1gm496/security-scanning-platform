from __future__ import annotations

import os
from pathlib import Path

DEFAULT_DASHBOARD_DB_PATH = "/data/security_scans.db"


def _running_in_container() -> bool:
    return Path("/.dockerenv").exists() or bool(os.getenv("KUBERNETES_SERVICE_HOST"))


def _path_is_writable(path: Path) -> bool:
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        probe = parent / ".ssp-write-probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def resolve_dashboard_db_path() -> str:
    configured = os.getenv("DASHBOARD_DB_PATH")
    if configured:
        return configured

    default_path = Path(DEFAULT_DASHBOARD_DB_PATH)
    if _running_in_container() or _path_is_writable(default_path):
        return str(default_path)

    repo_path = Path(__file__).resolve().parent.parent / "data" / "security_scans.db"
    if _path_is_writable(repo_path):
        return str(repo_path)

    return "/tmp/security_scans.db"


DASHBOARD_DB_PATH = resolve_dashboard_db_path()
os.environ.setdefault("DASHBOARD_DB_PATH", DASHBOARD_DB_PATH)
