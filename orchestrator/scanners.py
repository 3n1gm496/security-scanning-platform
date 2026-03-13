from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

LOGGER = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ScannerError(RuntimeError):
    pass


class RateLimitError(ScannerError):
    """Raised when API rate limit is hit."""

    pass


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(
    command: list[str], cwd: str | None = None, timeout: int = 3600, env: dict[str, str] | None = None
) -> tuple[int, str, str]:
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


def get_git_commit_sha(repo_path: str) -> str | None:
    """Return the HEAD commit SHA of a cloned repository, or None if unavailable."""
    try:
        rc, stdout, _ = run_command(["git", "-C", repo_path, "rev-parse", "HEAD"])
        if rc == 0:
            sha = stdout.strip()
            return sha if sha else None
    except Exception:  # noqa: BLE001
        pass
    return None


def clone_repo(repo_url: str, destination: str, ref: str | None = None, depth: int = 0) -> str:
    """Clone a Git repository into the workspace.

    The container may have no credentials configured, and we don't want the
    scan to hang waiting for user input if the remote prompts for a username or
    password.  Git honours the ``GIT_TERMINAL_PROMPT`` environment variable;
    setting it to ``0`` causes it to error out immediately instead of asking.

    We also pass ``--quiet`` and disable any credential helpers via
    ``-c credential.helper=`` to reduce the amount of output that can leak
    into logs when the clone fails for authentication reasons.

    Args:
        repo_url: Remote repository URL.
        destination: Local path to clone into.
        ref: Optional branch/tag/ref to check out.
        depth: Clone depth. ``0`` (default) performs a full clone, which is
               required for accurate git-history secret scanning (gitleaks).
               Positive values produce a shallow clone — faster but blind to
               secrets or vulnerabilities introduced in older commits.
               Set via ``execution.git_clone_depth`` in settings.yaml.
    """
    # Validate URL scheme to prevent SSRF via file://, ssh://, etc.
    _ALLOWED_SCHEMES = {"https", "http"}
    parsed = urlparse(repo_url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ScannerError(
            f"Unsupported URL scheme '{parsed.scheme}' for git clone — "
            f"only {', '.join(sorted(_ALLOWED_SCHEMES))} are allowed"
        )

    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone", "--quiet", "-c", "credential.helper="]
    if depth and depth > 0:
        command.extend(["--depth", str(depth)])
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
        raise ScannerError("semgrep not found in PATH — install it or disable the scanner in settings.yaml")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        retry=retry_if_exception_type(RateLimitError),
        before_sleep=before_sleep_log(LOGGER, logging.WARNING),
    )
    def _run_with_retry():
        command = ["semgrep", "scan", "--json", "--quiet"]
        for config in configs:
            command.extend(["--config", config])
        command.append(target_path)
        code, stdout, stderr = run_command(command, timeout=3600)

        # Detect rate limiting
        if "rate limit" in stderr.lower() or code == 429:
            raise RateLimitError(f"Semgrep rate limit hit: {stderr}")

        if code not in (0, 1):
            raise ScannerError(f"semgrep execution failed: {stderr or stdout}")

        Path(output_path).write_text(stdout or '{"results": []}', encoding="utf-8")
        return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}

    return _run_with_retry()


def run_trivy_fs(
    target_path: str, output_path: str, severities: list[str], ignore_unfixed: bool = False
) -> dict[str, Any]:
    if not command_exists("trivy"):
        raise ScannerError("trivy not found in PATH — install it or disable the scanner in settings.yaml")
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


def run_trivy_image(
    image_ref: str, output_path: str, severities: list[str], ignore_unfixed: bool = False
) -> dict[str, Any]:
    if not command_exists("trivy"):
        raise ScannerError("trivy not found in PATH — install it or disable the scanner in settings.yaml")
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
        raise ScannerError("gitleaks not found in PATH — install it or disable the scanner in settings.yaml")
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
        raise ScannerError("checkov not found in PATH — install it or disable the scanner in settings.yaml")
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
        raise ScannerError("syft not found in PATH — install it or disable the scanner in settings.yaml")
    command = ["syft", target_value, "-o", f"spdx-json={output_path}"]
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
        raise ScannerError("bandit not found in PATH — install it or disable the scanner in settings.yaml")
    # Use -o to write directly to file: avoids progress bar / rich output
    # polluting stdout which would break JSON parsing.
    command = ["bandit", "-f", "json", "-o", output_path, "-r", target_path]
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"bandit execution failed: {stderr or stdout}")
    # Ensure output file exists even if bandit produced no findings
    if not Path(output_path).exists() or Path(output_path).stat().st_size == 0:
        Path(output_path).write_text('{"results": [], "errors": []}', encoding="utf-8")
    return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}


# Default DAST templates used when scanning a URL target and no explicit templates are configured.
# These cover the most impactful HTTP security checks without requiring a full template update.
_NUCLEI_DAST_DEFAULT_TEMPLATES: list[str] = [
    "http/misconfiguration/",
    "http/exposures/",
    "http/technologies/",
    "http/cves/",
    "http/vulnerabilities/",
    "http/exposed-panels/",
    "http/default-logins/",
    "ssl/",
    "dns/",
]

# Default SAST/filesystem templates used when scanning a git/local target.
_NUCLEI_SAST_DEFAULT_TEMPLATES: list[str] = [
    "http/misconfiguration/",
    "http/exposures/",
    "http/cves/",
    "http/vulnerabilities/",
]


def run_nuclei(
    target_path: str,
    output_path: str,
    templates: list[str] | None = None,
    severity: str | None = None,
    tags: str | None = None,
    target_type: str = "local",
) -> dict[str, Any]:
    """Run *nuclei* templates against a filesystem/URL target.

    The CLI changed between major versions; modern releases (v2+) no longer support a
    ``-json`` flag.  Instead results must be asked for with ``-json-export`` (or the
    shorthand ``-je``) and we explicitly pass ``-target``.

    Template selection logic:
    - If ``templates`` is explicitly provided (non-empty list), use those.
    - If ``target_type == 'url'`` and no templates are configured, inject the full
      DAST template set (``_NUCLEI_DAST_DEFAULT_TEMPLATES``) for maximum coverage.
    - If ``target_type`` is filesystem-based and no templates are configured, inject
      the SAST template set (``_NUCLEI_SAST_DEFAULT_TEMPLATES``).

    Severity and tags can be used to filter templates for faster scans:
    - severity: comma-separated list (e.g. "critical,high") to limit results
    - tags: comma-separated list (e.g. "xss,sqli,auth") to include only specific types
    """
    if not command_exists("nuclei"):
        raise ScannerError("nuclei not found in PATH — install it or disable the scanner in settings.yaml")

    # Resolve effective template list
    effective_templates: list[str] = []
    if templates:
        effective_templates = list(templates)
    elif target_type == "url":
        effective_templates = _NUCLEI_DAST_DEFAULT_TEMPLATES
        LOGGER.info(
            "nuclei: no templates configured for URL target — injecting default DAST templates: %s",
            effective_templates,
        )
    else:
        effective_templates = _NUCLEI_SAST_DEFAULT_TEMPLATES
        LOGGER.info(
            "nuclei: no templates configured for %s target — injecting default SAST templates: %s",
            target_type,
            effective_templates,
        )

    # Build command using the current CLI flags from nuclei v2+
    command = ["nuclei", "-json-export", output_path, "-target", target_path]
    command.extend(["-t"] + effective_templates)
    if severity:
        command.extend(["-s", severity])
    if tags:
        command.extend(["-tags", tags])
    # Disable automatic update checks in CI/automated environments to avoid delays
    # (nuclei v3 flag: -duc / -disable-update-check)
    command.extend(["-duc"])
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"nuclei failed: {stderr or stdout}")
    # ensure a file exists even if nuclei produced nothing
    ensure_json_file(output_path, [])
    return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}


def run_grype(target_value: str, output_path: str) -> dict[str, Any]:
    if not command_exists("grype"):
        raise ScannerError("grype not found in PATH — install it or disable the scanner in settings.yaml")
    command = ["grype", target_value, "-o", "json", "-q"]
    code, stdout, stderr = run_command(command, timeout=3600)
    if code not in (0, 1):
        raise ScannerError(f"grype failed: {stderr or stdout}")
    Path(output_path).write_text(stdout or '{"matches": []}', encoding="utf-8")
    return {"exit_code": code, "stdout_path": output_path, "stderr": stderr}


def run_owasp_zap(
    target_url: str,
    output_path: str,
    zap_api_url: str = "http://localhost:8080",
    zap_api_key: str = "",
    spider_timeout: int = 120,
    scan_timeout: int = 600,
) -> dict[str, Any]:
    """Run an OWASP ZAP active scan against a URL target via the ZAP REST API.

    This implementation uses the ``python-owasp-zap-v2.4`` client library to
    communicate with a running ZAP instance (e.g. the ``owasp/zap2docker-stable``
    Docker image).  The scan flow is:

    1. Spider the target URL to discover pages.
    2. Run an active scan against all discovered URLs.
    3. Retrieve all alerts and write them to ``output_path`` as a JSON list.

    ZAP must be reachable at ``zap_api_url`` before calling this function.
    The recommended way to start ZAP is via Docker Compose:

        docker run -d -u zap -p 8080:8080 owasp/zap2docker-stable \\
            zap.sh -daemon -host 0.0.0.0 -port 8080 \\
            -config api.addrs.addr.name=.* \\
            -config api.addrs.addr.regex=true \\
            -config api.key=<your-api-key>
    """
    try:
        from zapv2 import ZAPv2  # type: ignore[import]
    except ImportError as exc:
        raise ScannerError("python-owasp-zap-v2.4 is not installed — run: pip install python-owasp-zap-v2.4") from exc

    LOGGER.info("Connecting to ZAP at %s", zap_api_url)
    zap = ZAPv2(apikey=zap_api_key, proxies={"http": zap_api_url, "https": zap_api_url})

    # --- Spider phase ---
    LOGGER.info("ZAP spider starting for %s", target_url)
    spider_id = zap.spider.scan(target_url, apikey=zap_api_key)
    import time

    deadline = time.monotonic() + spider_timeout
    while int(zap.spider.status(spider_id)) < 100:
        if time.monotonic() > deadline:
            LOGGER.warning("ZAP spider timed out after %ds — proceeding with partial results", spider_timeout)
            break
        time.sleep(2)
    LOGGER.info("ZAP spider complete")

    # --- Active scan phase ---
    LOGGER.info("ZAP active scan starting for %s", target_url)
    scan_id = zap.ascan.scan(target_url, apikey=zap_api_key)
    deadline = time.monotonic() + scan_timeout
    while int(zap.ascan.status(scan_id)) < 100:
        if time.monotonic() > deadline:
            LOGGER.warning("ZAP active scan timed out after %ds — proceeding with partial results", scan_timeout)
            break
        time.sleep(5)
    LOGGER.info("ZAP active scan complete")

    # --- Collect alerts ---
    alerts = zap.core.alerts(baseurl=target_url)
    LOGGER.info("ZAP found %d alerts for %s", len(alerts), target_url)
    Path(output_path).write_text(json.dumps(alerts, ensure_ascii=False), encoding="utf-8")
    return {"exit_code": 0, "stdout_path": output_path, "stderr": ""}


def load_json(path: str) -> dict[str, Any] | list[Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
