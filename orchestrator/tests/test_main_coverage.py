"""Additional unit tests for orchestrator/main.py to improve coverage.

Targets the following uncovered paths:
- resolve_targets with --targets-file
- prepare_target for image and unsupported types
- run_single_scan for image target type (all scanners disabled)
- run_single_scan for unsupported target type (raises ValueError)
- run_targets_concurrently: exit_code=3 on BLOCK with fail_on_policy_block
- main(): --retention-only flag, --json-output, --fail-on-policy-block,
  invalid arguments (exit 2)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_project_root = Path(__file__).parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from orchestrator.main import (  # noqa: E402
    build_arg_parser,
    prepare_target,
    resolve_targets,
    run_single_scan,
    run_targets_concurrently,
)
from orchestrator.models import TargetSpec  # noqa: E402
from orchestrator.storage import init_db  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_settings(tmp_path: Path) -> dict:
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


# ---------------------------------------------------------------------------
# Tests: resolve_targets
# ---------------------------------------------------------------------------


class TestResolveTargets:
    """Verify resolve_targets parses CLI args and targets-file correctly."""

    def test_single_local_target(self, tmp_path):
        args = SimpleNamespace(
            targets_file=None,
            target=str(tmp_path),
            target_type="local",
            target_name="my-svc",
            ref=None,
        )
        targets = resolve_targets(args)
        assert len(targets) == 1
        assert targets[0].name == "my-svc"
        assert targets[0].type == "local"

    def test_single_target_name_defaults_to_target(self, tmp_path):
        args = SimpleNamespace(
            targets_file=None,
            target=str(tmp_path),
            target_type="local",
            target_name=None,
            ref=None,
        )
        targets = resolve_targets(args)
        assert targets[0].name == str(tmp_path)

    def test_image_target(self):
        args = SimpleNamespace(
            targets_file=None,
            target="nginx:latest",
            target_type="image",
            target_name="nginx",
            ref=None,
        )
        targets = resolve_targets(args)
        assert len(targets) == 1
        assert targets[0].type == "image"
        assert targets[0].image == "nginx:latest"

    def test_targets_file(self, tmp_path):
        targets_yaml = tmp_path / "targets.yaml"
        target_dir = tmp_path / "src"
        target_dir.mkdir()
        targets_yaml.write_text(f"""
targets:
  - name: svc-a
    type: local
    path: {target_dir}
    enabled: true
  - name: svc-b
    type: local
    path: {target_dir}
    enabled: false
""")
        args = SimpleNamespace(
            targets_file=str(targets_yaml),
            target=None,
            target_type=None,
            target_name=None,
            ref=None,
        )
        targets = resolve_targets(args)
        # Only enabled targets should be returned
        assert len(targets) == 1
        assert targets[0].name == "svc-a"

    def test_missing_target_raises(self):
        args = SimpleNamespace(
            targets_file=None,
            target=None,
            target_type=None,
            target_name=None,
            ref=None,
        )
        with pytest.raises(ValueError, match="required"):
            resolve_targets(args)


# ---------------------------------------------------------------------------
# Tests: prepare_target
# ---------------------------------------------------------------------------


class TestPrepareTarget:
    """Verify prepare_target returns correct (input, value, git_sha) tuples."""

    def test_local_target_returns_path(self, tmp_path):
        settings = _minimal_settings(tmp_path)
        target_dir = tmp_path / "src"
        target_dir.mkdir()
        target = TargetSpec.from_dict({"name": "t", "type": "local", "path": str(target_dir), "enabled": True})
        inp, val, git_sha = prepare_target(target, settings, "scan-1")
        assert inp == str(target_dir)
        assert val == str(target_dir)
        # No .git directory → sha should be None (or a string if git happens to work)
        assert git_sha is None or isinstance(git_sha, str)

    def test_local_target_missing_path_raises(self, tmp_path):
        settings = _minimal_settings(tmp_path)
        target = TargetSpec.from_dict(
            {
                "name": "t",
                "type": "local",
                "path": str(tmp_path / "missing"),
                "enabled": True,
            }
        )
        with pytest.raises(FileNotFoundError):
            prepare_target(target, settings, "scan-1")

    def test_image_target_returns_image_ref(self, tmp_path):
        settings = _minimal_settings(tmp_path)
        target = TargetSpec.from_dict({"name": "t", "type": "image", "image": "nginx:latest", "enabled": True})
        inp, val, git_sha = prepare_target(target, settings, "scan-1")
        assert inp == "nginx:latest"
        assert val == "nginx:latest"
        assert git_sha is None

    def test_unsupported_type_raises(self, tmp_path):
        settings = _minimal_settings(tmp_path)
        target = TargetSpec.from_dict({"name": "t", "type": "local", "path": str(tmp_path), "enabled": True})
        # Manually override type to unsupported value
        target = TargetSpec(
            name="t",
            type="ftp",
            enabled=True,
        )
        with pytest.raises(ValueError, match="Unsupported"):
            prepare_target(target, settings, "scan-1")


# ---------------------------------------------------------------------------
# Tests: run_single_scan — image target
# ---------------------------------------------------------------------------


class TestRunSingleScanImageTarget:
    """Verify run_single_scan handles image targets (all scanners disabled)."""

    def test_image_target_completes_clean(self, tmp_path):
        """An image target with all scanners disabled must complete cleanly."""
        settings = _minimal_settings(tmp_path)
        target = TargetSpec.from_dict({"name": "nginx", "type": "image", "image": "nginx:latest", "enabled": True})
        result = run_single_scan(target, settings)
        assert result.status == "COMPLETED_CLEAN"
        assert result.target_type == "image"
        assert result.target_value == "nginx:latest"

    def test_unsupported_target_type_raises(self, tmp_path):
        """run_single_scan must raise ValueError for unsupported target types."""
        settings = _minimal_settings(tmp_path)
        target = TargetSpec(name="t", type="ftp", enabled=True)
        with pytest.raises(ValueError, match="Unsupported"):
            run_single_scan(target, settings)


# ---------------------------------------------------------------------------
# Tests: run_targets_concurrently — policy block exit code
# ---------------------------------------------------------------------------


class TestRunTargetsConcurrentlyPolicyBlock:
    """Verify exit_code=3 when fail_on_policy_block is True and a target blocks."""

    def test_exit_code_3_on_policy_block(self, tmp_path, monkeypatch):
        """exit_code must be 3 when a target has BLOCK policy status."""
        settings = _minimal_settings(tmp_path)
        settings["scanners"]["bandit"]["enabled"] = True
        target = TargetSpec.from_dict(
            {
                "name": "blocked-svc",
                "type": "local",
                "path": str(tmp_path / "src"),
                "enabled": True,
            }
        )
        (tmp_path / "src").mkdir()

        from orchestrator.models import Finding

        def fake_run_bandit(path, output_path, *args, **kwargs):
            Path(output_path).write_text('{"results": []}')
            return {"exit_code": 0, "stderr": ""}

        def fake_normalize_bandit(sid, tgt, raw, output_path, *args, **kwargs):
            return [
                Finding(
                    scan_id=sid,
                    timestamp="2026-01-01T00:00:00+00:00",
                    target_type="local",
                    target_name=tgt.name,
                    tool="bandit",
                    category="code",
                    severity="CRITICAL",
                    title="Critical issue",
                    description="A critical issue",
                )
            ]

        monkeypatch.setattr("orchestrator.main.run_bandit", fake_run_bandit)
        monkeypatch.setattr("orchestrator.main.normalize_bandit", fake_normalize_bandit)
        # Bypass the preflight binary check so the mocked bandit is actually invoked
        monkeypatch.setattr(
            "orchestrator.main.preflight_check",
            lambda tools: (tools, []),
        )

        results, exit_code = run_targets_concurrently(
            targets=[target],
            settings=settings,
            fail_on_policy_block=True,
        )

        assert exit_code == 3

    def test_failed_scan_is_persisted_when_target_raises(self, tmp_path, monkeypatch):
        settings = _minimal_settings(tmp_path)
        target_dir = tmp_path / "src"
        target_dir.mkdir()
        target = TargetSpec.from_dict(
            {
                "name": "broken-svc",
                "type": "local",
                "path": str(target_dir),
                "enabled": True,
            }
        )

        monkeypatch.setattr("orchestrator.main.run_single_scan", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

        results, exit_code = run_targets_concurrently(
            targets=[target],
            settings=settings,
            fail_on_policy_block=False,
            scan_id_override="11111111-1111-1111-1111-111111111111",
        )

        assert exit_code == 4
        assert results[0]["status"] == "FAILED"

        import sqlite3

        conn = sqlite3.connect(settings["paths"]["db_path"])
        row = conn.execute(
            "SELECT status, error_message FROM scans WHERE id = ?",
            ("11111111-1111-1111-1111-111111111111",),
        ).fetchone()
        conn.close()
        assert row[0] == "FAILED"
        assert "boom" in row[1]

    def test_scan_timeout_is_persisted_as_failed(self, tmp_path, monkeypatch):
        settings = _minimal_settings(tmp_path)
        settings["execution"]["scan_timeout_seconds"] = 1
        target_dir = tmp_path / "src"
        target_dir.mkdir()
        target = TargetSpec.from_dict(
            {
                "name": "slow-svc",
                "type": "local",
                "path": str(target_dir),
                "enabled": True,
            }
        )

        def fake_as_completed(_futures, timeout=None):
            from concurrent.futures import TimeoutError as FuturesTimeoutError

            raise FuturesTimeoutError()

        monkeypatch.setattr("orchestrator.main.as_completed", fake_as_completed)

        results, exit_code = run_targets_concurrently(
            targets=[target],
            settings=settings,
            fail_on_policy_block=False,
            scan_id_override="22222222-2222-2222-2222-222222222222",
        )

        assert exit_code == 4
        assert results[0]["status"] == "FAILED"
        assert "timeout" in results[0]["error_message"].lower()


# ---------------------------------------------------------------------------
# Tests: main() CLI — additional flags
# ---------------------------------------------------------------------------


class TestMainCLIAdditionalFlags:
    """Verify main() handles --retention-only, --json-output, invalid args."""

    def _write_settings(self, tmp_path: Path) -> str:
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
        return str(settings_path)

    def test_retention_only_exits_zero(self, tmp_path, monkeypatch, capsys):
        """--retention-only must exit 0 and print retention JSON."""
        settings_path = self._write_settings(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            ["orchestrator", "--retention-only", "--settings", settings_path],
        )
        from orchestrator.main import main

        exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert "retention" in payload

    def test_json_output_writes_file(self, tmp_path, monkeypatch, capsys):
        """--json-output must write the results JSON to the specified file."""
        settings_path = self._write_settings(tmp_path)
        target_dir = tmp_path / "src"
        target_dir.mkdir()
        output_file = tmp_path / "output.json"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "orchestrator",
                "--target-type",
                "local",
                "--target",
                str(target_dir),
                "--settings",
                settings_path,
                "--json-output",
                str(output_file),
            ],
        )
        from orchestrator.main import main

        exit_code = main()
        assert exit_code == 0
        assert output_file.exists()
        payload = json.loads(output_file.read_text())
        assert "results" in payload

    def test_invalid_args_exits_2(self, tmp_path, monkeypatch):
        """Missing --target and --target-type must cause main() to return 2."""
        settings_path = self._write_settings(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            ["orchestrator", "--settings", settings_path],
        )
        from orchestrator.main import main

        exit_code = main()
        assert exit_code == 2


# ---------------------------------------------------------------------------
# Tests: build_arg_parser
# ---------------------------------------------------------------------------


class TestBuildArgParser:
    """Verify the argument parser is correctly configured."""

    def test_parser_has_expected_arguments(self):
        parser = build_arg_parser()
        # Parse with minimal args to verify defaults
        args = parser.parse_args(["--target-type", "local", "--target", "/tmp"])
        assert args.target_type == "local"
        assert args.target == "/tmp"
        assert args.fail_on_policy_block is False
        assert args.retention_only is False
        assert args.json_output is None

    def test_fail_on_policy_block_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--target-type", "local", "--target", "/tmp", "--fail-on-policy-block"])
        assert args.fail_on_policy_block is True

    def test_retention_only_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--retention-only"])
        assert args.retention_only is True
