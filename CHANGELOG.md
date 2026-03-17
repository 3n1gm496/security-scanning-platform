# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project uses
[Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Changed

- **SOC command center UI**: the dashboard frontend was redesigned into a dark-first, command-center-oriented interface with refined shell, dashboard, scans, findings, analytics, compare, settings, modals, login, light theme, and mobile navigation.
- **Live refresh and chart lifecycle**: scan polling, analytics refresh, and chart motion were stabilized so the UI updates more quietly and reliably during active scan activity.
- **Browser smoke coverage**: the end-to-end smoke flow now covers login, dashboard, scans, findings, analytics, compare, settings, modals, light theme, and mobile navigation, with screenshots written to `artifacts/browser-smoke/`.
- **Accessibility and interaction coverage**: the command-center UI now has keyboard-sortable tables, keyboard-openable detail rows, stronger modal focus management, clearer analytics empty states, and smoke validation for keyboard activation and `Escape` modal close.
- **Documentation refresh**: the README and operational docs were realigned with the current UI, CI behavior, runtime configuration, and verification workflow.
- **Architecture and product docs**: added dedicated architecture, API, deployment, operations, and security-model documentation, and updated the Mermaid architecture source to reflect the current system shape.

### Fixed

- **Dashboard chart lifecycle edge case**: theme/resizing flows no longer trigger the Chart.js recursion/runtime errors discovered by the expanded browser smoke path.
- **Audit follow-up fixes across UI workflows**: findings export parity, scan comparison fallback matching, notifications field/link alignment, legacy scans/findings parity, and command-center UI consistency fixes were rolled into the current baseline.
- **Metrics, reporting, and backend parity**: Prometheus counters/gauges are now wired to real dashboard activity, scan trend charts count legacy terminal statuses correctly, SARIF/HTML exports preserve `target_name` metadata, and notification URL fallbacks now point to the actual dashboard port.
- **Operations runtime parity**: backup/restore now respect custom report paths, preserve compatibility with historical report archives, choose container-side PostgreSQL tooling correctly for Compose-hosted `postgres`, and keep Compose DB path wiring consistent between dashboard and orchestrator.
- **Backend notification and analytics parity**: scan completion/failure now emits the runtime webhook events already modeled by the product, notification preferences drive automatic scan summary and high/critical finding emails, and analytics/breakdown queries normalize blank target/tool labels instead of leaking empty values into the UI.
- **Technical debt cleanup**: removed the unused standalone `dashboard/metrics.py` collector and its orphaned tests so Prometheus behavior now has a single runtime path in `dashboard/monitoring.py`.

## [1.5.1] — 2026-03-11

Release with targeted fixes: WSL2/Docker Desktop compatibility, dashboard UI/UX bugs.

### Fixed

- **`docker-compose.yml`**: removed `network_mode: host` and `network: host` from `dashboard` and `orchestrator` service builds. These caused "connection refused" errors on WSL2 and Docker Desktop (Windows/Mac), where `network: host` is not supported. The port is now correctly exposed via standard port mapping (`${DASHBOARD_PORT:-8080}:8080`).
- **`docker-compose.ci.yml`** (new): dedicated override file for CI/sandbox environments that don't support `iptables raw`. Use only in CI: `docker compose -f docker-compose.yml -f docker-compose.ci.yml up -d`.
- **Dashboard — "Remediation Progress" chart always empty**: the JS code was looking for `pagination.total` but the `/api/findings/paginated` API returns `pagination.count`. The chart now correctly shows counts by status.
- **Dashboard — Scan comparison showed no results**: the `runCompare()` function was not correctly mapping the `/api/scans/{id}/compare` API response (structure `diff.new_count` vs `summary.new`). Normalization is now correct.
- **Dashboard — Notification email field pre-populated with username**: the `user_email` field in Settings → Notifications showed `"admin"` (internal identifier) instead of being empty. The JS now ignores the value if it doesn't contain `@`.

## [1.5.0] — 2026-03-10

This release focuses on **radically improving the quality and reliability of the orchestrator** through a massive increase in test coverage, going from 72% to over 86%. 100 new tests were added, bringing the total to 359.

### Added

- **Added 100 new tests for the orchestrator**:
  - **`test_normalizers_extended.py`**: 34 new tests for normalization functions (`normalize_trivy`, `normalize_gitleaks`, `normalize_checkov`) and helper functions (`_severity`, `_fingerprint`, `_rel_path`).
  - **`test_scanners_extended.py`**: 41 new tests for scanner wrappers (`run_semgrep`, `run_trivy_fs`, `run_trivy_image`, `run_gitleaks`, `run_checkov`, `run_syft`), using mocks to simulate command execution and handle exit codes.
  - **`test_db_adapter.py`**: 25 new tests for the `db_adapter` module, validating connection and cursor wrapper classes in SQLite mode.
- **Updated architecture diagram**: Created a new Mermaid flow diagram to more clearly represent component interactions.

### Changed

- **Orchestrator Test Coverage**: Increased orchestrator module test coverage from **72.13%** to **86.76%**.
- **Total Tests**: The total number of tests for the entire project is now **359** (194 for the dashboard + 165 for the orchestrator).

### Removed

- **Deprecated Endpoints**: Removed `/api/findings/by-status` and `/api/findings/stats-by-status` endpoints that had been replaced by cursor-based pagination.

### Fixed

- **Test `test_semgrep_rate_limit_raises`**: Fixed the test to correctly handle the `tenacity.RetryError` exception raised after retry attempts fail, ensuring test robustness.

---

## [1.4.0] — 2026-03-10

This release is the result of a thorough complete audit of the codebase, focused on security, code quality, test coverage, and edge cases. 5 critical security bugs and 6 code quality issues were fixed.

### Security (S)

- **S1 — Added Subresource Integrity (SRI) for CDNs**: Added `integrity` hashes to `<script>` tags for Vue.js and Chart.js, preventing loading of compromised resources (XSS).
- **S2 — Added `Permissions-Policy` header**: Restricts access to sensitive browser features (e.g. `geolocation=()`, `microphone=()`), reducing the attack surface.
- **S3 — Email encoding in unsubscribe link**: The user email is now encoded with `urllib.parse.quote_plus` before being inserted in the link, preventing issues with special characters.
- **S4 — `sort_by` validation in `BasePaginator`**: Added a whitelist of valid columns to prevent SQL injection in `ORDER BY`.
- **S5 — Session cookie `HttpOnly`**: The session cookie is now `HttpOnly` by default, preventing JavaScript access (XSS).

### Code Quality (Q)

- **Q1 — Workspace cleanup in orchestrator**: Added a `try...finally` block in `prepare_target` to ensure the temporary working directory is always removed, even in case of errors during git clone.
- **Q2 — Silent catch in `evaluate_policy`**: Added a `warning` log when the policy file is not found, instead of failing silently.
- **Q3 — Global timeout for `fetch`**: Added a 30-second timeout to all `fetch` calls in the frontend via `AbortController`, preventing requests blocked indefinitely.
- **Q4 — Silent catches in frontend**: Fixed 3 silent `catch` blocks in `app.js` by adding `console.debug` to log errors in debug mode.
- **Q5 — Test coverage gaps**: Added 15 new tests in `test_coverage_gaps.py` to cover untested areas of `db.py`, `finding_management.py`, and uncovered endpoints of `app.py`.
- **Q6 — Unpinned test dependencies**: Added `requirements-test.in` to the orchestrator to also pin test dependencies.

---

## [1.3.0] — 2026-03-10

This release fixes **11 bugs** discovered during a thorough complete audit of the codebase (backend, frontend, orchestrator, Docker, CI). The container is now self-contained with all scanners installed.

### Fixed

- **B1 — `AttributeError` at runtime in `api_update_finding_status`**: the `status` Form parameter collided with the `fastapi.status` module imported in the same scope. Renamed to `status_value`.
- **B2 — `scan_id` declared as `int` instead of `str` (UUID)**: the database uses UUID as TEXT; the wrong type caused zero results for any scan filter. Fixed in `app.py` (export and paginate routes) and in `pagination.py`.
- **B3 — "Findings" button in scan list didn't work**: `viewScanFindings()` was setting `findingsFilter.search` instead of `findingsFilter.scan_id`; the `/api/findings/paginated` endpoint didn't accept the `scan_id` parameter. Both fixed.
- **B4 — `triggerScan()` sent JSON instead of `FormData`**: the backend uses `Form(...)` for all parameters; the frontend was sending `Content-Type: application/json` causing 422 Unprocessable Entity.
- **B5 — "New Scan" modal didn't close** after successful trigger. Added `this.showScanModal = false` in the success callback.
- **B6 — `findingsSort` not defined in `data()`**: `sortTable()` was silently failing with `TypeError`. Added `findingsSort: { column: 'id', order: 'ASC' }` in `data()`.
- **B7 — Default `enabled=True` for scanners not present in `settings.yaml`**: uninstalled scanners were being called and failing. Changed default to `False` in `orchestrator/main.py`.
- **B8 — `unzip` missing in Docker slim image**: the nuclei installation layer failed with `unzip: not found`. Added `unzip` to apt dependencies.
- **B9 — Docker container didn't include scanner binaries**: all scans resulted in `PARTIAL_FAILED`. The Dockerfile now installs gitleaks v8.30.0, trivy v0.69.3, syft v1.42.2, grype v0.109.1, nuclei v3.7.1 (pinned versions) and semgrep + checkov via pip.
- **B10 — `settings.yaml` with all scanners disabled**: restored with `enabled: true` for all scanners; `owasp_zap` remains `false` by default with an explanatory comment about prerequisites.
- **B11 — CI workflow used `context: ./dashboard`**: the updated Dockerfile copies `orchestrator/` from the project root; the build context was updated to `.` (root).

### Added

- `scan_id` badge in the Findings page filter bar: shows the truncated UUID with an ✕ button to remove the filter; visible only when the scan filter is active.
- CSS for `.filter-scan-id`, `.scan-id-badge`, `.btn-icon-sm`.

---

## [1.2.0] — 2026-03-10

This release completes the frontend and API endpoint modernization, aligning pagination, fixing notification preferences, and improving Docker compatibility in sandbox environments.

### Added

- **Status filter in findings pagination**: Added `status` parameter to the `GET /api/findings/paginated` route and to `FindingsPaginator` to filter results by triage status (`open`, `resolved`, `in_progress`, etc.).
- **Integration test for status filter**: Added `test_findings_paginator_with_status_filter` to validate the new filter.
- **Integration test for notification preferences**: Added `test_notification_preferences_api_flow` for an E2E test of saving and retrieving preferences.

### Changed

- **Frontend pagination alignment**: The `loadFindings()` function in `app.js` now exclusively uses the `/api/findings/paginated` endpoint for all filters, ensuring consistent cursor-based pagination.
- **Cursor extraction fix**: `loadFindings()` and `loadScans()` now correctly extract `result.pagination.next_cursor` instead of `result.next_cursor`, aligning with the backend response structure.
- **Notification endpoint fix**: The notification preferences endpoint was corrected from `/api/settings/notifications` to `/api/notifications/preferences` in `app.js`.
- **Notification field alignment**: Field names in the notification form (`app.html`) and Vue model (`app.js`) were aligned with the backend schema (`notify_critical` → `critical_alerts`, etc.).

### Fixed

- **Docker sandbox compatibility**: Enabled `network_mode: "host"` in `docker-compose.yml` for the `dashboard` service, resolving the network creation error in environments without `iptables raw` support.

---

## [1.1.0] — 2026-03-09

This release consolidates the results of the **technical due diligence** conducted on the codebase.
All changes were introduced through Pull Requests with green CI before merge.

### Security (P0)

#### fix(security): path traversal on `/api/scan/trigger` — PR #1

- Added input validation and sanitization for `target`, `name`, and `target_type` in the `/api/scan/trigger` dashboard endpoint.
- Local paths are now resolved with `os.path.realpath` and verified against the configured `WORKSPACE_DIR`: any attempt to escape the working directory returns `HTTP 400`.
- Target names are sanitized with a safe character whitelist.
- Added 12 dedicated tests in `dashboard/tests/test_scan_trigger.py`.
- Also fixed: `orchestrator/requirements.txt` (added `tenacity`), `orchestrator/Dockerfile` and `docker-compose.yml` aligned to the `./orchestrator` build context used by CI.

#### feat(security): robust rate limiting on login and API — PR #2

- The in-memory rate limiter now also protects the `/login` endpoint (separate limit: 10 requests/minute per IP).
- Added periodic cleanup of the `defaultdict(deque)` dictionary via `threading.Timer` to prevent memory leaks with many distinct IPs.
- Also fixed all pre-existing `flake8` warnings in `charting.py`, `finding_management.py`, `notifications.py`, and `remediation.py`.
- Added 8 dedicated tests in `dashboard/tests/test_rate_limiting.py`.

#### feat(security): password hashing with bcrypt — PR #3

- Password verification now supports bcrypt hashes in the `DASHBOARD_PASSWORD` env var (format `$2b$...`).
- Backward compatibility guaranteed: if the variable contains a plaintext password, it's compared with `secrets.compare_digest` and a deprecation warning is logged.
- Added `bcrypt>=4.0.0` to `dashboard/requirements.txt`.
- Added 10 dedicated tests in `dashboard/tests/test_password_hashing.py`.

### Architecture (P1)

#### feat(arch): bounded thread pool for async scans + security headers — PR #4

- Replaced unlimited `threading.Thread` with `concurrent.futures.ThreadPoolExecutor` with configurable maximum size via `MAX_SCAN_WORKERS` (default: 4).
- Added missing security headers in middleware:
  - `Content-Security-Policy` (default-src 'self'; script-src 'self' 'unsafe-inline')
  - `Strict-Transport-Security` (max-age=31536000; includeSubDomains)
- Added 6 dedicated tests in `dashboard/tests/test_scan_thread_pool.py`.

#### refactor(db): centralized SQLite connections and datetime fix — PR #5

- `finding_management.py`, `rbac.py`, and `webhooks.py` now use `get_connection()` from `db.py` instead of calling `sqlite3.connect()` directly.
- `get_connection()` always sets `row_factory = sqlite3.Row`, ensuring uniform column name access throughout the codebase.
- Fixed the bug in `webhooks.py`: `hmac.new()` → `hmac.new()` (was already correct, verified that `hmac.new` is a valid alias in Python 3.11).
- Replaced `datetime.utcnow()` (deprecated in Python 3.12) with `datetime.now(timezone.utc)` in `monitoring.py` and `charting.py`.

### Developer Experience (P2)

#### feat(dx): dependency pinning with pip-tools + improved ops.sh — PR #6

- Introduced **pip-tools** for dependency management:
  - `dashboard/requirements.in` and `orchestrator/requirements.in` as source files
  - `dashboard/requirements-test.in` and `orchestrator/requirements-test.in` for test dependencies
  - `requirements.txt` files are now generated with `pip-compile` and contain pinned versions of all transitive dependencies
- `scripts/ops.sh` — new commands added:
  - `test [dashboard|orchestrator]` — run pytest with coverage
  - `lint [--fix]` — flake8 + black check (with `--fix` applies black)
  - `deps-compile` — regenerate all `requirements.txt` with pip-compile
  - `api-key create|list|revoke` — API key management from CLI
  - Improved `health`: also checks `/health` and `/ready` endpoints with curl

### CI/CD

#### feat(ci): GitLab Enterprise CI/CD pipeline — PR #7

- Added `.gitlab-ci.yml` with a complete pipeline in 6 stages:
  - `lint`: flake8 + black check (parallel for orchestrator and dashboard)
  - `test`: pytest with JUnit report and Cobertura coverage (native GitLab)
  - `security`: Bandit SAST with JSON artifacts
  - `build`: Docker build + push to GitLab Container Registry with layer caching and OCI labels (`org.opencontainers.image.*`)
  - `scan-self`: self-scanning of the repository through the platform itself; fails the pipeline if the policy returns `BLOCK` (configurable)
  - `deploy`: SSH-based with `docker compose pull && up`; automatic staging on `develop`, production with manual approval on `main`
  - `nightly:scan`: scheduled nightly scanning (only `schedule`)
- Added `templates/gitlab-scan-template.yml`: reusable template for other repositories in the GitLab group via `include:`.
- Added `docs/gitlab-integration.md`: complete guide with prerequisites, variable setup, server configuration, GitLab Ultimate SAST, nightly scans, and troubleshooting.

### Documentation

#### docs: README and CHANGELOG update — PR #8

- `README.md`:
  - Added GitHub Actions CI badge.
  - Features section updated with new security features.
  - `ops.sh` section updated with new commands (`test`, `lint`, `deps-compile`, `api-key`).
  - Development section updated with instructions for testing, linting, and pinned dependency management.
  - Added link to `docs/gitlab-integration.md` in the documentation section.
- Created `CHANGELOG.md` (this file).

---

## [1.0.0] — 2025-01-01

Initial release of the platform.

### Added

- Python 3.11 orchestrator with support for 10+ OSS scanners (Semgrep, Bandit, Nuclei, Trivy, Grype, Gitleaks, Checkov, Syft, OWASP ZAP).
- FastAPI dashboard with authentication, RBAC, finding management, email notifications, webhooks, CSV/JSON export, Prometheus metrics.
- Docker Compose and systemd service/timer deployment.
- `scripts/ops.sh` as unified entry point for all operations.
- GitHub Actions CI with test, lint, SAST, and docker build.
- Azure DevOps integration (`azure-pipelines.yml.example`).
- Demo app and `init_demo.sh` script.

---

[Unreleased]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/3n1gm496/security-scanning-platform/releases/tag/v1.0.0
