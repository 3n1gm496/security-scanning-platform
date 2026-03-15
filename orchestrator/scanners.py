from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

# ---------------------------------------------------------------------------
# SSRF protection for git clone URLs
# ---------------------------------------------------------------------------
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if addr falls within a blocked network range."""
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            return True
    # IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) bypass pure IPv6 checks.
    # Extract the mapped IPv4 address and re-check against the IPv4 blocklist.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        for net in _BLOCKED_NETWORKS:
            if addr.ipv4_mapped in net:
                return True
    return False


def _check_ssrf(hostname: str) -> None:
    """Raise ScannerError if hostname resolves to a private/reserved IP."""
    # Literal IP check
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_blocked_ip(addr):
            raise ScannerError(f"Clone target resolves to blocked IP range: {addr}")
        return
    except ValueError:
        pass  # Not a literal IP — resolve via DNS

    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for _family, _type, _proto, _canonname, sockaddr in results:
            addr = ipaddress.ip_address(sockaddr[0])
            if _is_blocked_ip(addr):
                raise ScannerError(f"Clone target '{hostname}' resolves to blocked IP range: {addr}")
    except socket.gaierror as exc:
        raise ScannerError(f"DNS resolution failed for '{hostname}': {exc}") from exc


def _redact_url_credentials(token: str) -> str:
    """Redact userinfo (credentials) from URLs in command tokens for safe logging."""
    if "://" not in token:
        return token
    try:
        parsed = urlparse(token)
        if parsed.username or parsed.password:
            # Replace userinfo with ***
            netloc = f"***@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        pass
    return token


_SAFE_ENV_KEYS = {
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TMP",
    "TEMP",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "TRIVY_CACHE_DIR",
    "XDG_CACHE_HOME",
    "ZAP_API_URL",
    "ZAP_API_KEY",
}


def _scanner_subprocess_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal subprocess environment to avoid leaking unrelated secrets."""
    env = {key: value for key, value in os.environ.items() if key in _SAFE_ENV_KEYS}
    env.setdefault("PATH", os.environ.get("PATH", ""))
    if "HOME" in os.environ:
        env.setdefault("HOME", os.environ["HOME"])
    env.setdefault("LANG", os.environ.get("LANG", "C.UTF-8"))
    if extra:
        env.update(extra)
    return env


from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

LOGGER = logging.getLogger(__name__)


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
    LOGGER.info("Executing command: %s", " ".join(_redact_url_credentials(t) for t in command))
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env or os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        # Kill the entire process group (child + its descendants)
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            process.kill()
        process.wait()
        raise


def ensure_json_file(path: str | Path, default_payload: dict | list) -> None:
    output = Path(path)
    if output.exists() and output.stat().st_size > 0:
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

    # Validate that the hostname does not resolve to a private/reserved IP range.
    if parsed.hostname:
        _check_ssrf(parsed.hostname)

    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone", "--quiet", "-c", "credential.helper="]
    if depth and depth > 0:
        command.extend(["--depth", str(depth)])
    if ref:
        command.extend(["--branch", ref])
    command.extend([repo_url, destination])

    # disable interactive credential prompting inside containers
    env = _scanner_subprocess_env({"GIT_TERMINAL_PROMPT": "0"})

    code, stdout, stderr = run_command(command, timeout=1800, env=env)
    if code != 0:
        # include git output so caller can log reason; the "Username for" line may
        # appear in stderr even though prompting is disabled.
        raise ScannerError(f"git clone failed: {_redact_url_credentials(stderr or stdout)}")
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
        code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())

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
    code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())
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
    code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())
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
    code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())
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
    code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())
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
    code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())
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
    code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())
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


def _check_url_ssrf(url: str) -> None:
    """Validate a URL target against SSRF attacks."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ScannerError(f"Unsupported URL scheme '{parsed.scheme}' — only http/https are allowed")
    if parsed.hostname:
        _check_ssrf(parsed.hostname)


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
    if target_type == "url":
        _check_url_ssrf(target_path)

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
    for tmpl in effective_templates:
        command.extend(["-t", tmpl])
    if severity:
        command.extend(["-s", severity])
    if tags:
        command.extend(["-tags", tags])
    # Disable automatic update checks in CI/automated environments to avoid delays
    # (nuclei v3 flag: -duc / -disable-update-check)
    command.extend(["-duc"])
    code, stdout, stderr = run_command(command, timeout=3600, env=_scanner_subprocess_env())
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
    zap_api_url: str = "http://localhost:8090",
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
    _check_url_ssrf(target_url)

    try:
        from zapv2 import ZAPv2  # type: ignore[import]
    except ImportError as exc:
        raise ScannerError("python-owasp-zap-v2.4 is not installed — run: pip install python-owasp-zap-v2.4") from exc

    import time

    LOGGER.info("Connecting to ZAP at %s (api_key=%s)", zap_api_url, "***" if zap_api_key else "<empty>")
    zap = ZAPv2(apikey=zap_api_key, proxies={"http": zap_api_url, "https": zap_api_url})

    # Verify ZAP is reachable before starting the scan
    try:
        version = zap.core.version
        LOGGER.info("ZAP version: %s", version)
    except Exception as exc:
        raise ScannerError(f"Cannot connect to ZAP at {zap_api_url} — is ZAP running? Error: {exc}") from exc

    # --- Open URL in ZAP first (seed the site tree) ---
    LOGGER.info("ZAP: opening target URL %s", target_url)
    zap.urlopen(target_url)
    time.sleep(2)

    # --- Spider phase ---
    LOGGER.info("ZAP spider starting for %s", target_url)
    spider_id = zap.spider.scan(target_url, apikey=zap_api_key)
    LOGGER.info("ZAP spider ID: %s", spider_id)

    # spider.scan() returns the scan ID as a string; non-numeric = error
    try:
        int(spider_id)
    except (ValueError, TypeError):
        raise ScannerError(f"ZAP spider failed to start: {spider_id}")

    deadline = time.monotonic() + spider_timeout
    while True:
        status_val = zap.spider.status(spider_id)
        LOGGER.debug("ZAP spider progress: %s%%", status_val)
        try:
            if int(status_val) >= 100:
                break
        except (ValueError, TypeError):
            LOGGER.warning("ZAP spider returned unexpected status: %s", status_val)
            break
        if time.monotonic() > deadline:
            LOGGER.warning("ZAP spider timed out after %ds — proceeding with partial results", spider_timeout)
            zap.spider.stop(spider_id, apikey=zap_api_key)
            break
        time.sleep(2)

    spider_results = zap.spider.results(spider_id)
    LOGGER.info(
        "ZAP spider complete — discovered %d URLs", len(spider_results) if isinstance(spider_results, list) else 0
    )

    # --- Passive scan wait (let ZAP process spidered pages) ---
    pscan_deadline = time.monotonic() + 30
    while True:
        try:
            records = int(zap.pscan.records_to_scan)
        except (ValueError, TypeError):
            break
        if records <= 0:
            break
        if time.monotonic() > pscan_deadline:
            LOGGER.info("ZAP passive scan still has %s records — proceeding", records)
            break
        time.sleep(1)

    # --- Active scan phase ---
    LOGGER.info("ZAP active scan starting for %s", target_url)
    scan_id_str = zap.ascan.scan(target_url, apikey=zap_api_key)
    LOGGER.info("ZAP active scan ID: %s", scan_id_str)

    try:
        int(scan_id_str)
    except (ValueError, TypeError):
        raise ScannerError(f"ZAP active scan failed to start: {scan_id_str}")

    deadline = time.monotonic() + scan_timeout
    while True:
        status_val = zap.ascan.status(scan_id_str)
        LOGGER.debug("ZAP active scan progress: %s%%", status_val)
        try:
            if int(status_val) >= 100:
                break
        except (ValueError, TypeError):
            LOGGER.warning("ZAP active scan returned unexpected status: %s", status_val)
            break
        if time.monotonic() > deadline:
            LOGGER.warning("ZAP active scan timed out after %ds — proceeding with partial results", scan_timeout)
            zap.ascan.stop(scan_id_str, apikey=zap_api_key)
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
