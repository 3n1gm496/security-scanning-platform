"""Phase 2 regression tests.

Covers:
- get_git_commit_sha (scanners.py)
- git_sha propagation into cache_context (main.py / build_cache_key)
- schema_migrations table created by init_db (storage.py)
- run_migrations idempotency and pending-migration logic (storage.py)
- INSERT ON CONFLICT DO UPDATE semantics in save_scan_result (storage.py)
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from orchestrator.cache import build_cache_key
from orchestrator.storage import _MIGRATIONS, _utc_now, init_db, run_migrations, save_scan_result
from orchestrator.models import ScanResult, TargetSpec, ToolExecutionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(scan_id: str = "test-scan-001", target_name: str = "repo") -> ScanResult:
    target = TargetSpec(name=target_name, type="git", repo="https://example.com/repo.git")
    return ScanResult(
        scan_id=scan_id,
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        target_name=target_name,
        target_type="git",
        target_value="https://example.com/repo.git",
        status="COMPLETED_CLEAN",
        policy_status="PASS",
        tools=[],
        findings=[],
        artifacts={},
        raw_report_dir="/tmp/raw",
        normalized_report_path="/tmp/norm.json",
        error_message=None,
    )


# ---------------------------------------------------------------------------
# get_git_commit_sha
# ---------------------------------------------------------------------------


def test_get_git_commit_sha_success():
    """Should return the SHA when git rev-parse succeeds."""
    from orchestrator.scanners import get_git_commit_sha

    fake_sha = "abc1234def5678" * 2  # 28 chars
    with patch("orchestrator.scanners.run_command", return_value=(0, fake_sha + "\n", "")) as mock_cmd:
        result = get_git_commit_sha("/some/repo")
    assert result == fake_sha
    mock_cmd.assert_called_once_with(["git", "-C", "/some/repo", "rev-parse", "HEAD"])


def test_get_git_commit_sha_nonzero_exit():
    """Should return None when git returns a non-zero exit code."""
    from orchestrator.scanners import get_git_commit_sha

    with patch("orchestrator.scanners.run_command", return_value=(128, "", "fatal: not a git repository")):
        result = get_git_commit_sha("/not/a/repo")
    assert result is None


def test_get_git_commit_sha_exception():
    """Should return None when run_command raises."""
    from orchestrator.scanners import get_git_commit_sha

    with patch("orchestrator.scanners.run_command", side_effect=FileNotFoundError("git not found")):
        result = get_git_commit_sha("/some/path")
    assert result is None


def test_get_git_commit_sha_empty_stdout():
    """Should return None when stdout is empty even on success."""
    from orchestrator.scanners import get_git_commit_sha

    with patch("orchestrator.scanners.run_command", return_value=(0, "   \n", "")):
        result = get_git_commit_sha("/some/repo")
    assert result is None


# ---------------------------------------------------------------------------
# Cache key changes with git SHA
# ---------------------------------------------------------------------------


def test_cache_key_changes_with_git_sha():
    """Two identical scans with different git SHAs must produce different cache keys."""
    k1 = build_cache_key("semgrep", "git", "https://example.com/repo.git", {"configs": ["p/default"], "git_sha": "aaa"})
    k2 = build_cache_key("semgrep", "git", "https://example.com/repo.git", {"configs": ["p/default"], "git_sha": "bbb"})
    assert k1 != k2


def test_cache_key_stable_with_same_sha():
    """Same SHA must produce the same key (deterministic)."""
    ctx = {"configs": ["p/default"], "git_sha": "deadbeefcafe1234"}
    assert build_cache_key("semgrep", "git", "https://x/r.git", ctx) == build_cache_key(
        "semgrep", "git", "https://x/r.git", ctx
    )


def test_cache_key_without_sha_differs_from_with_sha():
    """Absence of git_sha must differ from presence."""
    k_no_sha = build_cache_key("trivy_fs", "git", "https://x/r.git", {"mode": "sca"})
    k_with_sha = build_cache_key("trivy_fs", "git", "https://x/r.git", {"mode": "sca", "git_sha": "abc123"})
    assert k_no_sha != k_with_sha


# ---------------------------------------------------------------------------
# schema_migrations table (storage.py)
# ---------------------------------------------------------------------------


def test_init_db_creates_migrations_table(tmp_path):
    """init_db must create the schema_migrations table."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'")
    row = cur.fetchone()
    conn.close()
    assert row is not None, "schema_migrations table was not created"


def test_init_db_seeds_baseline_migration(tmp_path):
    """init_db must seed the v1 baseline migration row."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT version, description FROM schema_migrations WHERE version = 1").fetchone()
    conn.close()
    assert row is not None
    assert row["description"] == "baseline marker"


def test_run_migrations_idempotent(tmp_path):
    """run_migrations called twice must not duplicate rows."""
    db_path = str(tmp_path / "idem.db")
    init_db(db_path)
    run_migrations(db_path)  # second call
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
    conn.close()
    assert count == len(_MIGRATIONS)


def test_run_migrations_applies_pending(tmp_path):
    """A migration with version > current should be applied."""
    db_path = str(tmp_path / "pending.db")
    init_db(db_path)

    extra_migration = (99, "test-extra", "CREATE TABLE IF NOT EXISTS _test_phase2_extra (id INTEGER PRIMARY KEY);")
    patched = _MIGRATIONS + [extra_migration]

    with patch("orchestrator.storage._MIGRATIONS", patched):
        run_migrations(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # migration row recorded
    row = conn.execute("SELECT version FROM schema_migrations WHERE version = 99").fetchone()
    assert row is not None
    # table created by the migration SQL
    tbl = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='_test_phase2_extra'"
    ).fetchone()
    assert tbl is not None
    conn.close()


# ---------------------------------------------------------------------------
# INSERT ON CONFLICT DO UPDATE (save_scan_result)
# ---------------------------------------------------------------------------


def test_save_scan_result_upsert(tmp_path):
    """Saving the same scan_id twice must update counts, not raise IntegrityError."""
    db_path = str(tmp_path / "upsert.db")
    init_db(db_path)

    result = _make_result()
    save_scan_result(db_path, result)

    # Re-save with mutated status/policy_status — should not raise
    result.status = "COMPLETED_WITH_FINDINGS"
    result.policy_status = "BLOCK"
    save_scan_result(db_path, result)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT status, policy_status FROM scans WHERE id = ?", (result.scan_id,)).fetchone()
    conn.close()

    assert row["status"] == "COMPLETED_WITH_FINDINGS"
    assert row["policy_status"] == "BLOCK"


def test_save_scan_result_preserves_created_at_on_upsert(tmp_path):
    """ON CONFLICT DO UPDATE must not touch created_at (immutable audit field)."""
    db_path = str(tmp_path / "upsert2.db")
    init_db(db_path)

    result = _make_result()
    original_created_at = result.started_at
    save_scan_result(db_path, result)

    # Simulate a second save (e.g., retry after partial failure)
    result.finished_at = "2026-01-01T00:05:00+00:00"
    save_scan_result(db_path, result)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT created_at FROM scans WHERE id = ?", (result.scan_id,)).fetchone()
    conn.close()

    assert row["created_at"] == original_created_at
