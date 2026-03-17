from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import tarfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _copy_script(repo_root: Path, script_name: str, tmp_path: Path) -> Path:
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    src = repo_root / "scripts" / script_name
    dst = scripts_dir / script_name
    shutil.copy2(src, dst)
    dst.chmod(0o755)
    return dst


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_backup_script_uses_dashboard_db_path_and_writes_archive(tmp_path):
    _copy_script(PROJECT_ROOT, "backup.sh", tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.yaml").write_text("retention: {}\n", encoding="utf-8")

    db_dir = tmp_path / "custom-db"
    db_dir.mkdir()
    db_path = db_dir / "dashboard.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO scans(status) VALUES ('COMPLETED')")
    conn.commit()
    conn.close()

    backup_dir = tmp_path / "out"
    env = os.environ.copy()
    env["DASHBOARD_DB_PATH"] = str(db_path)
    env["BACKUP_DIR"] = str(backup_dir)

    subprocess.run(
        ["bash", str(tmp_path / "scripts" / "backup.sh")],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    archives = sorted(backup_dir.glob("ssp-backup-*.tar.gz"))
    assert archives, "backup archive not created"

    with tarfile.open(archives[0], "r:gz") as tar:
        names = tar.getnames()

    assert any(name.endswith("security_scans.db") for name in names)


def test_restore_script_restores_custom_db_path_reports_and_config_without_nesting(tmp_path):
    _copy_script(PROJECT_ROOT, "restore.sh", tmp_path)

    data_dir = tmp_path / "data"
    reports_dir = data_dir / "reports"
    reports_dir.mkdir(parents=True)
    (reports_dir / "stale.txt").write_text("stale", encoding="utf-8")

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "existing.yaml").write_text("old: true\n", encoding="utf-8")
    (config_dir / "stale.yaml").write_text("stale: true\n", encoding="utf-8")

    custom_db_dir = tmp_path / "custom"
    custom_db_dir.mkdir()
    custom_db_path = custom_db_dir / "restored.sqlite3"
    (custom_db_dir / "restored.sqlite3-wal").write_text("stale wal", encoding="utf-8")
    (custom_db_dir / "restored.sqlite3-shm").write_text("stale shm", encoding="utf-8")

    backup_root = tmp_path / "backup-src" / "ssp-backup-20260317T000000Z"
    backup_root.mkdir(parents=True)

    restored_db = backup_root / "security_scans.db"
    conn = sqlite3.connect(restored_db)
    conn.execute("CREATE TABLE marker (value TEXT)")
    conn.execute("INSERT INTO marker(value) VALUES ('restored')")
    conn.commit()
    conn.close()

    reports_payload_root = tmp_path / "reports-payload"
    (reports_payload_root / "reports").mkdir(parents=True)
    (reports_payload_root / "reports" / "fresh.txt").write_text("fresh", encoding="utf-8")
    with tarfile.open(backup_root / "reports.tar.gz", "w:gz") as tar:
        tar.add(reports_payload_root / "reports", arcname="reports")

    (backup_root / "config").mkdir()
    (backup_root / "config" / "app.yaml").write_text("new: true\n", encoding="utf-8")

    archive_path = tmp_path / "backup.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(backup_root, arcname=backup_root.name)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    _write_executable(
        bin_dir / "docker",
        "#!/usr/bin/env bash\n" 'printf \'%s\\n\' "$*" >> "$DOCKER_LOG"\n' "exit 0\n",
    )

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["DOCKER_LOG"] = str(docker_log)
    env["RESTORE_YES"] = "1"
    env["DASHBOARD_DB_PATH"] = str(custom_db_path)

    subprocess.run(
        ["bash", str(tmp_path / "scripts" / "restore.sh"), str(archive_path)],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert custom_db_path.exists()
    conn = sqlite3.connect(custom_db_path)
    value = conn.execute("SELECT value FROM marker").fetchone()[0]
    conn.close()
    assert value == "restored"

    assert (tmp_path / "data" / "reports" / "fresh.txt").exists()
    assert not (tmp_path / "data" / "reports" / "stale.txt").exists()

    assert (tmp_path / "config" / "app.yaml").exists()
    assert not (tmp_path / "config" / "config" / "app.yaml").exists()
    assert not (tmp_path / "config" / "stale.yaml").exists()
    assert not (custom_db_dir / "restored.sqlite3-wal").exists()
    assert not (custom_db_dir / "restored.sqlite3-shm").exists()


def test_ops_health_uses_api_health_and_ready_endpoints(tmp_path):
    _copy_script(PROJECT_ROOT, "ops.sh", tmp_path)
    (tmp_path / ".env").write_text("DASHBOARD_PORT=8080\n", encoding="utf-8")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl_log = tmp_path / "curl.log"

    _write_executable(
        bin_dir / "docker",
        "#!/usr/bin/env bash\n"
        'if [[ "$1" == compose && "$2" == version ]]; then exit 0; fi\n'
        'if [[ "$1" == compose && "$2" == ps ]]; then echo \'NAME STATUS\'; exit 0; fi\n'
        "exit 0\n",
    )
    _write_executable(
        bin_dir / "curl",
        "#!/usr/bin/env bash\n"
        'url="${@: -1}"\n'
        'printf \'%s\\n\' "$url" >> "$CURL_LOG"\n'
        'fmt=""\n'
        "while [[ $# -gt 0 ]]; do\n"
        '  if [[ "$1" == -w ]]; then fmt="$2"; shift 2; continue; fi\n'
        "  shift\n"
        "done\n"
        'if [[ "$url" == */api/health ]]; then\n'
        '  printf \'{"status":"healthy","uptime_seconds":1,"version":"dev"}\\n200\'\n'
        'elif [[ "$url" == */api/ready ]]; then\n'
        "  printf '200'\n"
        'elif [[ "$url" == */ ]]; then\n'
        "  printf '200'\n"
        "else\n"
        "  printf '000'\n"
        "fi\n",
    )

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CURL_LOG"] = str(curl_log)

    subprocess.run(
        ["bash", str(tmp_path / "scripts" / "ops.sh"), "health"],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    logged = curl_log.read_text(encoding="utf-8").splitlines()
    assert "http://localhost:8080/api/health" in logged
    assert "http://localhost:8080/api/ready" in logged
    assert "http://localhost:8080/health" not in logged
    assert "http://localhost:8080/ready" not in logged


def test_ops_retention_cleans_reports_workspaces_and_cache(tmp_path):
    _copy_script(PROJECT_ROOT, "ops.sh", tmp_path)

    old_paths = [
        tmp_path / "data" / "reports" / "old-report",
        tmp_path / "data" / "workspaces" / "old-workspace",
        tmp_path / "data" / "cache" / "trivy" / "old-cache",
    ]
    fresh_paths = [
        tmp_path / "data" / "reports" / "fresh-report",
        tmp_path / "data" / "workspaces" / "fresh-workspace",
        tmp_path / "data" / "cache" / "trivy" / "fresh-cache",
    ]

    for path in old_paths + fresh_paths:
        path.mkdir(parents=True, exist_ok=True)

    forty_days_ago = 40 * 86400
    for path in old_paths:
        os.utime(path, (path.stat().st_atime - forty_days_ago, path.stat().st_mtime - forty_days_ago))

    subprocess.run(
        ["bash", str(tmp_path / "scripts" / "ops.sh"), "retention", "--days", "30"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )

    for path in old_paths:
        assert not path.exists()
    for path in fresh_paths:
        assert path.exists()
