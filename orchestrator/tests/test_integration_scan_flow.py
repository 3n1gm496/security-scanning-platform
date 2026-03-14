"""Integration tests for the full scan flow.

These tests exercise the orchestrator end-to-end with all external scanner
binaries mocked out, but with a real SQLite database and real file I/O.
They verify that:

1. ``run_single_scan`` completes for a local target and persists results to DB.
2. ``run_single_scan`` correctly sets ``COMPLETED_WITH_FINDINGS`` when findings
   are returned by a scanner.
3. ``run_single_scan`` sets ``PARTIAL_FAILED`` when a scanner raises an error.
4. ``run_targets_concurrently`` handles multiple targets in parallel.
5. The policy engine correctly returns ``BLOCK`` / ``PASS`` based on findings.
6. ``main()`` end-to-end: CLI → DB write → JSON stdout.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Ensure the project root is on sys.path so orchestrator package is importable.
_project_root = Path(__file__).parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from orchestrator.main import (  # noqa: E402
    evaluate_policy,
    run_single_scan,
    run_targets_concurrently,
    resolve_settings,
)
from orchestrator.models import TargetSpec  # noqa: E402
from orchestrator.storage import init_db  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _minimal_settings(tmp_path: Path) -> dict:
    """Return a minimal settings dict that points all paths to *tmp_path*."""
    db_path = str(tmp_path / "scans.db")
    init_db(db_path)
    return {
        "paths": {
            "db_path": db_path,
            "reports_dir": str(tmp_path / "reports"),
            "workspace_dir": str(tmp_path / "workspaces"),
        },
        "scanners": {
            "semgrep": {"enabled": False},
            "checkov": {"enabled": False},
            "gitleaks": {"enabled": False},
            "trivy": {"enabled": False},
            "bandit": {"enabled": False},
            "nuclei": {"enabled": False},
            "grype": {"enabled": False},
            "syft": {"enabled": False},
            "owasp_zap": {"enabled": False},
        },
        "policy": {
            "block_on_severities": ["CRITICAL"],
            "block_on_secret_categories": True,
            "policies_file": "/nonexistent/policies.yaml",
        },
        "execution": {"max_concurrent_targets": 2},
        "cache": {"enabled": False},
        "retention": {},
    }


def _local_target(tmp_path: Path, name: str = "test-target") -> TargetSpec:
    """Create a TargetSpec pointing to an existing local directory."""
    target_dir = tmp_path / "source"
    target_dir.mkdir(parents=True, exist_ok=True)
    return TargetSpec.from_dict(
        {
            "name": name,
            "type": "local",
            "path": str(target_dir),
            "enabled": True,
        }
    )


def _db_scan_count(db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    conn.close()
    return row[0]


def _db_findings_for_scan(db_path: str, scan_id: str) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Tests: run_single_scan — basic persistence
# ---------------------------------------------------------------------------


class TestRunSingleScanPersistence:
    """Verify that run_single_scan writes a scan record to the database."""

    def test_scan_creates_db_record(self, tmp_path):
        """A completed scan must create exactly one row in the scans table."""
        settings = _minimal_settings(tmp_path)
        target = _local_target(tmp_path)

        result = run_single_scan(target, settings)

        assert _db_scan_count(settings["paths"]["db_path"]) == 1
        assert result.scan_id is not None
        assert result.status in ("COMPLETED_CLEAN", "COMPLETED_WITH_FINDINGS", "PARTIAL_FAILED")

    def test_scan_record_has_correct_target_metadata(self, tmp_path):
        """The persisted scan record must reflect the target name and type."""
        settings = _minimal_settings(tmp_path)
        target = _local_target(tmp_path, name="my-service")

        result = run_single_scan(target, settings)

        conn = sqlite3.connect(settings["paths"]["db_path"])
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (result.scan_id,)).fetchone()
        conn.close()

        assert row is not None
        assert row["target_name"] == "my-service"
        assert row["target_type"] == "local"

    def test_scan_result_dict_is_serialisable(self, tmp_path):
        """ScanResult.to_dict() must be JSON-serialisable without errors."""
        settings = _minimal_settings(tmp_path)
        target = _local_target(tmp_path)

        result = run_single_scan(target, settings)
        payload = result.to_dict()

        # Must not raise
        serialised = json.dumps(payload)
        assert "scan_id" in json.loads(serialised)

    def test_scan_status_clean_when_no_findings(self, tmp_path):
        """With all scanners disabled, status must be COMPLETED_CLEAN."""
        settings = _minimal_settings(tmp_path)
        target = _local_target(tmp_path)

        result = run_single_scan(target, settings)

        assert result.status == "COMPLETED_CLEAN"
        assert result.findings == []


# ---------------------------------------------------------------------------
# Tests: run_single_scan — findings and policy
# ---------------------------------------------------------------------------


class TestRunSingleScanWithFindings:
    """Verify scan behaviour when a scanner returns findings."""

    def test_scan_status_with_findings(self, tmp_path, monkeypatch):
        """When a scanner returns findings, status must be COMPLETED_WITH_FINDINGS."""
        from orchestrator.models import Finding

        settings = _minimal_settings(tmp_path)
        # Enable bandit
        settings["scanners"]["bandit"]["enabled"] = True
        target = _local_target(tmp_path)

        fake_finding = Finding(
            scan_id="",
            timestamp="2026-01-01T00:00:00+00:00",
            target_type="local",
            target_name=target.name,
            tool="bandit",
            category="code",
            severity="HIGH",
            title="Test finding",
            description="A test finding",
        )

        # Mock run_bandit to produce a dummy JSON file and mock normalize_bandit
        def fake_run_bandit(path, output_path, *args, **kwargs):
            Path(output_path).write_text('{"results": []}')
            return {"exit_code": 0, "stderr": ""}

        def fake_normalize_bandit(raw, output_path, *args, **kwargs):
            return [fake_finding]

        monkeypatch.setattr("orchestrator.main.run_bandit", fake_run_bandit)
        monkeypatch.setattr("orchestrator.main.normalize_bandit", fake_normalize_bandit)

        result = run_single_scan(target, settings)

        assert result.status == "COMPLETED_WITH_FINDINGS"
        assert len(result.findings) == 1
        assert result.findings[0].tool == "bandit"

    def test_findings_persisted_to_db(self, tmp_path, monkeypatch):
        """Findings returned by a scanner must be written to the findings table.

        The normalizer closure in run_single_scan already embeds the scan_id
        (generated with uuid4) into each Finding before calling save_scan_result.
        We verify persistence by checking both the in-memory result and the
        findings count in the DB via the scans.findings_count column.
        """
        from orchestrator.models import Finding

        settings = _minimal_settings(tmp_path)
        settings["scanners"]["bandit"]["enabled"] = True
        target = _local_target(tmp_path)

        def fake_run_bandit(path, output_path, *args, **kwargs):
            Path(output_path).write_text('{"results": []}')
            return {"exit_code": 0, "stderr": ""}

        def fake_normalize_bandit(raw, output_path, *args, **kwargs):
            # scan_id is baked into the closure lambda in main.py;
            # we retrieve it from the already-running ScanResult via the
            # injected_scan_id container that capturing_save will fill.
            # At this point scan_id is not yet available, so we return a
            # placeholder; the scan_id will be fixed up before DB write
            # by the real save_scan_result which uses result.findings directly.
            # Instead, we rely on the normalizer lambda signature:
            # lambda raw_payload, output_path: normalize_bandit(scan_id, target, raw, path)
            # The scan_id is already in the closure — we just need to match it.
            # We use a sentinel and fix it in capturing_save.
            return [
                Finding(
                    scan_id="__PLACEHOLDER__",
                    timestamp="2026-01-01T00:00:00+00:00",
                    target_type="local",
                    target_name=target.name,
                    tool="bandit",
                    category="code",
                    severity="MEDIUM",
                    title="SQL injection risk",
                    description="Possible SQL injection",
                )
            ]

        from orchestrator import storage as _storage

        original_save = _storage.save_scan_result

        def capturing_save(db_path, result):
            # Fix up placeholder scan_id before the real save
            for f in result.findings:
                if f.scan_id == "__PLACEHOLDER__":
                    f.scan_id = result.scan_id
            original_save(db_path, result)

        monkeypatch.setattr("orchestrator.main.run_bandit", fake_run_bandit)
        monkeypatch.setattr("orchestrator.main.normalize_bandit", fake_normalize_bandit)
        monkeypatch.setattr("orchestrator.main.save_scan_result", capturing_save)

        result = run_single_scan(target, settings)

        # Verify in-memory result
        assert len(result.findings) == 1
        assert result.findings[0].tool == "bandit"
        assert result.findings[0].severity == "MEDIUM"

        # Verify DB persistence via the scans table findings_count column
        conn = sqlite3.connect(settings["paths"]["db_path"])
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT findings_count FROM scans WHERE id = ?", (result.scan_id,)).fetchone()
        conn.close()
        assert row is not None
        assert row["findings_count"] == 1


# ---------------------------------------------------------------------------
# Tests: run_single_scan — error handling
# ---------------------------------------------------------------------------


class TestRunSingleScanErrorHandling:
    """Verify graceful degradation when a scanner fails."""

    def test_scanner_exception_sets_partial_failed(self, tmp_path, monkeypatch):
        """When a scanner raises an exception, status must be PARTIAL_FAILED."""
        settings = _minimal_settings(tmp_path)
        settings["scanners"]["bandit"]["enabled"] = True
        target = _local_target(tmp_path)

        def failing_run_bandit(path, output_path, *args, **kwargs):
            raise RuntimeError("bandit binary crashed")

        monkeypatch.setattr("orchestrator.main.run_bandit", failing_run_bandit)

        result = run_single_scan(target, settings)

        assert result.status == "PARTIAL_FAILED"
        assert result.error_message is not None
        # Scan must still be persisted even on partial failure
        assert _db_scan_count(settings["paths"]["db_path"]) == 1

    def test_missing_local_path_raises(self, tmp_path):
        """A local target pointing to a non-existent path must raise FileNotFoundError."""
        settings = _minimal_settings(tmp_path)
        target = TargetSpec.from_dict(
            {
                "name": "missing",
                "type": "local",
                "path": str(tmp_path / "does_not_exist"),
                "enabled": True,
            }
        )
        with pytest.raises(FileNotFoundError):
            run_single_scan(target, settings)


# ---------------------------------------------------------------------------
# Tests: run_targets_concurrently
# ---------------------------------------------------------------------------


class TestRunTargetsConcurrently:
    """Verify parallel scan execution."""

    def test_multiple_targets_all_persisted(self, tmp_path):
        """All targets must produce a DB record when run concurrently."""
        settings = _minimal_settings(tmp_path)
        targets = [_local_target(tmp_path, name=f"svc-{i}") for i in range(3)]

        results, exit_code = run_targets_concurrently(
            targets=targets,
            settings=settings,
            fail_on_policy_block=False,
        )

        assert len(results) == 3
        assert _db_scan_count(settings["paths"]["db_path"]) == 3
        assert exit_code == 0

    def test_exit_code_4_on_failed_target(self, tmp_path, monkeypatch):
        """exit_code must be 4 when at least one target scan fails."""
        settings = _minimal_settings(tmp_path)
        settings["scanners"]["bandit"]["enabled"] = True
        targets = [_local_target(tmp_path, name="failing-svc")]

        def failing_run_bandit(path, output_path, *args, **kwargs):
            raise RuntimeError("crash")

        monkeypatch.setattr("orchestrator.main.run_bandit", failing_run_bandit)

        results, exit_code = run_targets_concurrently(
            targets=targets,
            settings=settings,
            fail_on_policy_block=False,
        )

        assert exit_code == 4


# ---------------------------------------------------------------------------
# Tests: evaluate_policy
# ---------------------------------------------------------------------------


class TestEvaluatePolicy:
    """Verify the policy evaluation logic (fallback path)."""

    def _settings(self) -> dict:
        return {
            "policy": {
                "block_on_severities": ["CRITICAL"],
                "block_on_secret_categories": True,
                "policies_file": "/nonexistent/policies.yaml",
            }
        }

    def test_pass_when_no_findings(self):
        assert evaluate_policy([], self._settings()) == "PASS"

    def test_pass_with_low_severity(self):
        findings = [{"severity": "LOW", "category": "code"}]
        assert evaluate_policy(findings, self._settings()) == "PASS"

    def test_block_on_critical_severity(self):
        findings = [{"severity": "CRITICAL", "category": "code"}]
        assert evaluate_policy(findings, self._settings()) == "BLOCK"

    def test_block_on_secret_category(self):
        findings = [{"severity": "LOW", "category": "secret"}]
        assert evaluate_policy(findings, self._settings()) == "BLOCK"

    def test_pass_when_block_on_secret_disabled(self):
        settings = {
            "policy": {
                "block_on_severities": [],
                "block_on_secret_categories": False,
                "policies_file": "/nonexistent/policies.yaml",
            }
        }
        findings = [{"severity": "LOW", "category": "secret"}]
        assert evaluate_policy(findings, settings) == "PASS"

    def test_block_severity_is_case_insensitive(self):
        findings = [{"severity": "critical", "category": "code"}]
        assert evaluate_policy(findings, self._settings()) == "BLOCK"


# ---------------------------------------------------------------------------
# Tests: main() CLI end-to-end
# ---------------------------------------------------------------------------


class TestMainCLI:
    """Verify the main() entry point writes to DB and emits JSON to stdout."""

    def test_main_local_target_exits_zero(self, tmp_path, monkeypatch, capsys):
        """main() must exit 0 for a clean local scan and emit valid JSON."""
        db_path = str(tmp_path / "scans.db")
        settings_path = tmp_path / "settings.yaml"
        settings_path.write_text(f"""
paths:
  db_path: {db_path}
  reports_dir: {tmp_path}/reports
  workspace_dir: {tmp_path}/workspaces
scanners:
  semgrep: {{enabled: false}}
  checkov: {{enabled: false}}
  gitleaks: {{enabled: false}}
  trivy: {{enabled: false}}
  bandit: {{enabled: false}}
  nuclei: {{enabled: false}}
  grype: {{enabled: false}}
  syft: {{enabled: false}}
  owasp_zap: {{enabled: false}}
policy:
  block_on_severities: [CRITICAL]
  block_on_secret_categories: true
execution:
  max_concurrent_targets: 1
cache:
  enabled: false
retention: {{}}
""")
        target_dir = tmp_path / "source"
        target_dir.mkdir()

        test_argv = [
            "orchestrator",
            "--target-type",
            "local",
            "--target",
            str(target_dir),
            "--target-name",
            "cli-test",
            "--settings",
            str(settings_path),
        ]
        monkeypatch.setattr(sys, "argv", test_argv)

        from orchestrator.main import main

        exit_code = main()

        assert exit_code == 0

        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert "results" in payload
        assert len(payload["results"]) == 1
        assert payload["results"][0]["target_name"] == "cli-test"

        # Verify DB was written
        assert _db_scan_count(db_path) == 1
