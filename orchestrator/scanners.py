from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ScannerError(RuntimeError):
    pass


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(command: list[str], cwd: str | None = None, timeout: int = 3600, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    LOGGER.info("Executing command: %s", " ".join(command))
    process = subprocess.run(
        command,
        cwd=cwd,
        env=env or os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return process.returncode, process.stdout, process.stderr


def ensure_json_file(path: str | Path, default_payload: dict | list) -> None:
    output = Path(path)
    if output.exists():
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(default_payload, handle, indent=2)


def clone_repo(repo_url: str, destination: str, ref: str | None = None) -> str:
    """Clone a Git repository into the workspace.

    The container may have no credentials configured, and we don't want the
    scan to hang waiting for user input if the remote prompts for a username or
    password.  Git honours the ``GIT_TERMINAL_PROMPT`` environment variable;
    setting it to ``0`` causes it to error out immediately instead of asking.

    We also pass ``--quiet`` and disable any credential helpers via
    ``-c credential.helper=`` to reduce the amount of output that can leak
    into logs when the clone fails for authentication reasons.
    """
    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone", "--depth", "1", "--quiet", "-c", "credential.helper="]
    if ref:
        command.extend(["--branch", ref])
    command.extend([repo_url, destination])

    # disable interactive credential prompting inside containers
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    code, stdout, stderr = run_command(command, timeout=1800, env=env)
    if code != 0:
        # include git output so caller can log reason; the "Username for" line may
        # appear in stderr even though prompting is disabled.
        raise ScannerError(f"git clone failed: {stderr or stdout}")
    return destination


def run_semgrep(target_path: str, output_path: str, configs: list[str]) -> dict[str, Any]:
    if not command_exists("semgrep"):
        raise ScannerError("semgrep not found in PATH")
    command = ["semgrep", "scan", "--json", "--quiet"]
    for config in configs:
        command.extend(["--config", config])
    command.append(target_path)
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"semgrep execution failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or '{"results": []}', encoding="utf-8")
    return {
        "exit_code": code,
        "stdout_path": output_path,
        "stderr": stderr,
    }


def run_trivy_fs(target_path: str, output_path: str, severities: list[str], ignore_unfixed: bool = False) -> dict[str, Any]:
    if not command_exists("trivy"):
        raise ScannerError("trivy not found in PATH")
    command = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--quiet",
    ]
    if severities:
        command.extend(["--severity", ",".join(severities)])
    if ignore_unfixed:
        command.append("--ignore-unfixed")
    command.append(target_path)
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"trivy fs failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or '{"Results": []}', encoding="utf-8")
    return {
        "exit_code": code,
        "stdout_path": output_path,
        "stderr": stderr,
    }


def run_trivy_image(image_ref: str, output_path: str, severities: list[str], ignore_unfixed: bool = False) -> dict[str, Any]:
    if not command_exists("trivy"):
        raise ScannerError("trivy not found in PATH")
    command = [
        "trivy",
        "image",
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--quiet",
    ]
    if severities:
        command.extend(["--severity", ",".join(severities)])
    if ignore_unfixed:
        command.append("--ignore-unfixed")
    command.append(image_ref)
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"trivy image failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or '{"Results": []}', encoding="utf-8")
    return {
        "exit_code": code,
        "stdout_path": output_path,
        "stderr": stderr,
    }


def run_gitleaks(target_path: str, output_path: str, use_git_history: bool = True) -> dict[str, Any]:
    if not command_exists("gitleaks"):
        raise ScannerError("gitleaks not found in PATH")
    subcommand = "git" if use_git_history else "dir"
    command = [
        "gitleaks",
        subcommand,
        target_path,
        "--report-format",
        "json",
        "--report-path",
        output_path,
        "--no-banner",
        "--no-color",
        "--exit-code",
        "1",
        "--log-level",
        "error",
    ]
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"gitleaks failed: {stderr or stdout}")
    ensure_json_file(output_path, [])
    return {
        "exit_code": code,
        "stdout_path": output_path,
        "stderr": stderr,
    }


def run_checkov(target_path: str, output_path: str) -> dict[str, Any]:
    if not command_exists("checkov"):
        raise ScannerError("checkov not found in PATH")
    command = [
        "checkov",
        "-d",
        target_path,
        "-o",
        "json",
        "--quiet",
        "--skip-framework",
        "secrets",
        "sca_package",
        "sca_image",
    ]
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"checkov failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or '{"results":{"failed_checks":[],"passed_checks":[]}}', encoding="utf-8")
    return {
        "exit_code": code,
        "stdout_path": output_path,
        "stderr": stderr,
    }


def run_syft(target_value: str, output_path: str) -> dict[str, Any]:
    if not command_exists("syft"):
        raise ScannerError("syft not found in PATH")
    command = ["syft", target_value, f"-o", f"spdx-json={output_path}"]
    code, stdout, stderr = run_command(command, timeout=3600)
    if code != 0:
        raise ScannerError(f"syft failed: {stderr or stdout}")
    ensure_json_file(output_path, {"spdxVersion": "SPDX-2.3", "packages": []})
    return {
        "exit_code": code,
        "stdout_path": output_path,
        "stderr": stderr,
    }


# ---------------------------------------------------------------------------
# new scanners
# ---------------------------------------------------------------------------

def run_bandit(target_path: str, output_path: str) -> dict[str, Any]:
    """Run Bandit SAST for Python projects.
    Output is written in JSON format to ``output_path``.
    """
    if not command_exists("bandit"):
        LOGGER.warning("bandit not in PATH, skipping scan and returning empty results")
        # create empty output for consistency
        Path(output_path).write_text("{\"results\": []}", encoding="utf-8")
        return {"exit_code": 0, "stdout_path": output_path, "stderr": ""}
    command = ["bandit", "-f", "json", "-r", target_path]
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"bandit execution failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or "{\"results\": []}", encoding="utf-8")
    return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}


def run_nuclei(target_path: str, output_path: str, templates: list[str] | None = None, severity: str | None = None, tags: str | None = None) -> dict[str, Any]:
    """Run *nuclei* templates against a filesystem/URL.

    The CLI changed between major versions; modern releases (v2+) no longer support a
    ``-json`` flag.  Instead results must be asked for with ``-json-export`` (or the
    shorthand ``-je``) and we explicitly pass ``-target``.

    Severity and tags can be used to filter templates for faster scans:
    - severity: comma-separated list (e.g. "critical,high") to limit results
    - tags: comma-separated list (e.g. "xss,sqli,auth") to include only specific types

    If the binary is missing we fall back to a no-op scan that still produces a
    syntactically valid JSON file.
    """
    if not command_exists("nuclei"):
        LOGGER.warning("nuclei not in PATH, skipping scan and returning empty results")
        ensure_json_file(output_path, [])
        return {"exit_code": 0, "stdout_path": output_path, "stderr": ""}

    # build command using the current CLI flags from nuclei v2+
    command = ["nuclei", "-json-export", output_path, "-target", target_path]
    if templates:
        command.extend(["-t"] + templates)
    if severity:
        command.extend(["-s", severity])
    if tags:
        command.extend(["-tags", tags])

    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"nuclei failed: {stderr or stdout}")

    # ensure a file exists even if nuclei produced nothing
    ensure_json_file(output_path, [])
    return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}


def run_grype(target_value: str, output_path: str) -> dict[str, Any]:
    if not command_exists("grype"):
        LOGGER.warning("grype not found in PATH, skipping scan and returning empty results")
        Path(output_path).write_text("{\"matches\": []}", encoding="utf-8")
        return {"exit_code": 0, "stdout_path": output_path, "stderr": ""}
    command = ["grype", target_value, "-o", "json", "-q"]
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"grype failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or "{\"matches\": []}", encoding="utf-8")
    return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}


def run_owasp_zap(target_url: str, output_path: str) -> dict[str, Any]:
    """Simple wrapper that expects the ZAP CLI executable.
    It launches a quick scan against the provided URL.
    """
    if not command_exists("zap-cli"):
        LOGGER.warning("zap-cli not found in PATH, skipping scan and returning empty array")
        Path(output_path).write_text("[]", encoding="utf-8")
        return {"exit_code": 0, "stdout_path": output_path, "stderr": ""}
    command = ["zap-cli", "quick-scan", "--json", target_url]
    code, stdout, stderr = run_command(command, timeout=7200)
    # zap-cli writes JSON to stdout
    if code not in (0, 1):
        raise ScannerError(f"owasp zap scan failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or "[]", encoding="utf-8")
    return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}


def load_json(path: str) -> dict[str, Any] | list[Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
