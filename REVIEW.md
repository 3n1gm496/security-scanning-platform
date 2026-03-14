# Repository Review

**Repository:** `3n1gm496/security-scanning-platform`
**Reviewer:** Senior Security Engineer / Staff Architect (automated review via Claude)
**Review Date:** 2026-03-14
**Branch:** `claude/complete-claude-md-tasks-sV7d1`
**Commit:** `f91f284`
**Previous Review:** 2026-03-11 on branch `claude/security-platform-review-MqdAz`

---

## 1. Executive Summary

The platform has undergone **significant hardening** since the March 11 review. All six
critical/high-severity findings from the previous review (#1–#6) have been properly addressed:
WAL mode enabled, dashboard runs non-root, OPERATOR privilege escalation fixed, healthchecks
added, git clone depth configurable, and SSRF protection implemented with DNS-rebinding
mitigation.

Prometheus metrics are now integrated (`prometheus_client` in requirements, `/metrics`
endpoint serving OpenMetrics format). The migration system is in place with a
`schema_migrations` table and idempotent `run_migrations()`. The orchestrator and dashboard
are production-viable for single-server deployments.

**However, new findings emerged in this review:**

- **Export injection vulnerabilities** (CSV injection, HTML/XSS injection, PDF markup injection)
  are the most impactful new findings. These affect all export formats and have no sanitization.
- **Schema duplication persists** with new divergence (DEFAULT value mismatches between
  orchestrator and dashboard schemas).
- **PostgreSQL `INSERT OR REPLACE` adaptation** remains unimplemented — PostgreSQL deployments
  will crash on notification preference writes.
- **No CSRF token protection** on form-based mutation endpoints (mitigated by SameSite=Lax).

The platform is **safe for internal use behind a firewall** with the current fixes. It is
**not safe for Internet exposure** until export injection vulnerabilities are resolved, as
any authenticated user can trigger XSS via HTML export download.

---

## 2. Validation of Existing Review

### #1 — SQLite WAL mode not enabled
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/db_adapter.py:63-64` and `orchestrator/db_adapter.py:42-43` both
  execute `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` in `_sqlite_connect()`.
  Tests exist in `test_db_adapter.py`.
- **What changed:** Two-line fix in both adapters, exactly as recommended.

### #2 — Dashboard container runs as root
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/Dockerfile:9-10` creates `dashuser` (UID 1000), line 77 transfers
  ownership, line 80 sets `USER dashuser`. Matches orchestrator's `scanuser` pattern.
- **What changed:** Non-root user added with proper directory ownership.

### #3 — OPERATOR role has API_KEY_MANAGE permission
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/rbac.py:51-58` — `API_KEY_MANAGE` removed from OPERATOR role with
  explicit comment explaining the privilege escalation risk. `dashboard/app.py:520-529` adds
  a role-ceiling check (`_ROLE_RANK` dictionary) preventing any user from creating keys with
  roles above their own.
- **What changed:** Permission removed + role-ceiling enforcement added. Double protection.

### #4 — Docker Compose: no healthcheck on dashboard
- **Status:** `FULLY FIXED`
- **Evidence:** `docker-compose.yml:118-123` — healthcheck configured with `curl -f
  http://localhost:8080/api/health`, 30s interval, 10s timeout, 3 retries, 40s start period.
  All four services (postgres, zap, orchestrator, dashboard) now have healthchecks.
- **What changed:** Healthcheck added exactly as recommended.

### #5 — Shallow git clone defeats gitleaks history scanning
- **Status:** `FULLY FIXED`
- **Evidence:** `orchestrator/scanners.py:79` — `clone_repo()` accepts `depth: int = 0`
  (full clone by default). Lines 112-113: `--depth` flag only added when `depth > 0`.
  `orchestrator/main.py:108-110` reads `ORCH_GIT_CLONE_DEPTH` env var, defaults to `0`.
  Tests in `test_scanners.py:188-237` verify both full and shallow clone paths.
- **What changed:** Configurable depth with secure default (full clone).

### #6 — Webhook SSRF — no URL validation
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/webhooks.py:32-93` — comprehensive `validate_webhook_url()` with:
  - Blocked networks: RFC 1918, loopback, link-local, AWS IMDS, RFC 6598, IPv6 ULA/link-local
  - DNS resolution check with rebinding mitigation
  - Scheme restriction to http/https
  - Called in `create_webhook()` (line 154) before storing
- **What changed:** Full SSRF validation with DNS-rebinding mitigation, exceeding original
  recommendation.

### #7 — Schema duplication + no migration system
- **Status:** `PARTIALLY FIXED`
- **Evidence:**
  - Migration system added: both `orchestrator/storage.py:70-108` and `dashboard/db.py:364-397`
    have `schema_migrations` table and `run_migrations()` / `_run_migrations()` with baseline
    migration. Tests exist in `orchestrator/tests/test_phase2.py:121-171`.
  - **Schema still duplicated:** `orchestrator/storage.py:18-75` and `dashboard/db.py:314-369`
    define SCHEMA_SQL independently.
  - **New divergence introduced:** Dashboard adds `DEFAULT ''` / `DEFAULT '{}'` / `DEFAULT '[]'`
    on `raw_report_dir`, `normalized_report_path`, `artifacts_json`, `tools_json` — orchestrator
    does not. This causes schema drift.
  - **`INSERT OR REPLACE` PostgreSQL adaptation still missing:** Both `adapt_schema()` functions
    only handle `AUTOINCREMENT → SERIAL`. `dashboard/notifications.py:292` uses
    `INSERT OR REPLACE INTO notification_preferences` which will crash on PostgreSQL.
- **What changed:** Migration infrastructure added (good), but root cause (duplication) remains.

### #8 — Cache key ignores git commit hash
- **Status:** `FULLY FIXED`
- **Evidence:** `orchestrator/scanners.py:67-76` — `get_git_commit_sha()` resolves HEAD SHA
  after clone. `orchestrator/main.py:257-259` injects `git_sha` into cache context via
  `_git_ctx`. All tool cache calls include `**_git_ctx` spread. Tests in
  `test_phase2.py:94-113` and `test_main_coverage.py:162-173`.
- **What changed:** Git SHA included in cache key, preventing stale results.

### #9 — No Prometheus metrics
- **Status:** `FULLY FIXED`
- **Evidence:** `prometheus-client==0.24.1` in `dashboard/requirements.txt:69`.
  `dashboard/monitoring.py:11` imports Counter, Gauge, Histogram from prometheus_client.
  `dashboard/metrics.py:12` also uses prometheus_client. `dashboard/app.py:1539` exposes
  `/metrics` endpoint. Rate-limited paths exclude `/metrics` (line 216).
- **What changed:** Full Prometheus integration with counters, gauges, histograms.

### #10 — `app.py` god-class (62 KB+)
- **Status:** `PARTIALLY FIXED`
- **Evidence:** `dashboard/app.py` is now 1551 lines (down from original). Significant
  extraction has occurred: `rbac.py`, `webhooks.py`, `finding_management.py`, `pagination.py`,
  `remediation.py`, `analytics.py`, `monitoring.py`, `metrics.py`, `export.py`, `auth.py`,
  `db.py`, `db_adapter.py`, `notifications.py`. However, all route definitions still live in
  `app.py` — no `APIRouter` decomposition yet.
- **What changed:** Business logic extracted to modules; route registration not yet decomposed.

---

## 3. New Findings

### CSV Injection in Export
- **Severity:** `HIGH`
- **Category:** `SECURITY`
- **Confidence:** `HIGH`
- **Affected files:** `dashboard/export.py:29-49`, `dashboard/app.py:695-722`
- **Why it matters:** Finding values (title, description, message, file path) are written
  directly to CSV via `csv.DictWriter.writerow()` without sanitization. If a scanner produces
  a finding whose message starts with `=`, `+`, `-`, `@`, `\t`, or `\r`, opening the exported
  CSV in Excel/LibreOffice will execute the formula. An attacker who controls a scanned
  repository could craft filenames or code comments that produce these findings, leading to
  code execution on the security analyst's workstation.
- **Proof / reasoning:** `export.py:47` — `writer.writerow(finding)` passes raw dict values.
  No `html.escape`, no formula prefix stripping. Same pattern in `app.py:695-722` (streaming
  CSV). Example payload: a file named `=cmd|'/C calc'!A1` in a scanned repo would appear
  as a finding with that path, executing `calc.exe` when the CSV is opened.
- **Minimal fix:** Sanitize all string values before CSV write:
  ```python
  def _sanitize_csv_value(val):
      if isinstance(val, str) and val and val[0] in ('=', '+', '-', '@', '\t', '\r'):
          return "'" + val
      return val
  ```
  Apply to every value in every row before `writerow()`.
- **Recommended regression test:** Test that `export_to_csv([{"message": "=1+1"}])` produces
  a CSV where the cell value starts with `'=` (escaped) rather than `=`.

### HTML/XSS Injection in HTML Export
- **Severity:** `HIGH`
- **Category:** `SECURITY`
- **Confidence:** `HIGH`
- **Affected files:** `dashboard/export.py:266-340`
- **Why it matters:** Finding fields (`title`, `tool`, `target`, `description`, `category`,
  `cve_id`, `cwe_id`) are interpolated directly into HTML via f-strings without any escaping.
  `html.escape` is not imported or used anywhere in `export.py`. An attacker controlling a
  scanned repo can craft finding messages containing `<script>` tags or event handlers. When
  a security analyst downloads and opens the HTML report, JavaScript executes in their browser.
- **Proof / reasoning:** `export.py:329` — `<div class="finding-title">{title}</div>` where
  `title = finding.get("message", ...)`. A finding with message
  `<img src=x onerror=alert(document.cookie)>` would execute JavaScript. No CSP headers on
  the HTML export either.
- **Minimal fix:** Import `html.escape` and wrap all interpolated values:
  ```python
  from html import escape
  title = escape(finding.get("message", finding.get("description", "Unknown issue")))
  tool = escape(finding.get("tool", "unknown"))
  # ... etc for all fields
  ```
- **Recommended regression test:** Test that `export_to_html([{"message": "<script>alert(1)</script>"}])`
  contains `&lt;script&gt;` in the output, not literal `<script>`.

### PDF Markup Injection
- **Severity:** `MEDIUM`
- **Category:** `SECURITY`
- **Confidence:** `MEDIUM`
- **Affected files:** `dashboard/export.py:548-554`
- **Why it matters:** ReportLab's `Paragraph` class uses XML-like markup. Unescaped `<` and `>`
  characters in finding fields (title, file, tool) can break PDF generation or inject unexpected
  formatting. While this is not directly exploitable for code execution, it causes DoS
  (report generation crashes) and potential content manipulation.
- **Proof / reasoning:** `export.py:548` — `f"<b>{idx}. {title}</b><br/>"` where `title`
  may contain `</b>` or `<para>` tags that ReportLab will interpret.
- **Minimal fix:** Use `xml.sax.saxutils.escape()` on all interpolated values in PDF paragraphs.
- **Recommended regression test:** Test that `export_to_pdf([{"message": "</b><i>injected</i>"}])`
  does not crash and produces valid PDF output.

### Schema Divergence Between Orchestrator and Dashboard
- **Severity:** `MEDIUM`
- **Category:** `CORRECTNESS`
- **Confidence:** `HIGH`
- **Affected files:** `orchestrator/storage.py:18-75`, `dashboard/db.py:314-369`
- **Why it matters:** The dashboard schema adds `DEFAULT ''` and `DEFAULT '{}'` on four columns
  (`raw_report_dir`, `normalized_report_path`, `artifacts_json`, `tools_json`) that the
  orchestrator schema defines as bare `NOT NULL`. If the dashboard initializes the DB first and
  the orchestrator inserts data without these fields, behavior differs. More critically, this
  divergence will grow over time without a single source of truth.
- **Proof / reasoning:** Direct comparison of SCHEMA_SQL strings in both files shows four
  DEFAULT value mismatches. The schemas are maintained independently with no shared module.
- **Minimal fix:** Extract schema to a shared `common/schema.py` or have one component import
  from the other. Synchronize DEFAULT values.
- **Recommended regression test:** Test that both components produce byte-identical schemas on
  a fresh database (compare `sqlite_master` output).

### PostgreSQL INSERT OR REPLACE Not Adapted
- **Severity:** `MEDIUM`
- **Category:** `BUG`
- **Confidence:** `HIGH`
- **Affected files:** `dashboard/db_adapter.py:247-265`, `orchestrator/db_adapter.py:187-198`,
  `dashboard/notifications.py:292`
- **Why it matters:** Both `adapt_schema()` functions only transform `AUTOINCREMENT → SERIAL`.
  The docstring in `dashboard/db_adapter.py:253` claims to handle `INSERT OR REPLACE → INSERT
  ... ON CONFLICT DO UPDATE` but the implementation does not. `notifications.py:292` uses
  `INSERT OR REPLACE INTO notification_preferences` which will crash on PostgreSQL with a
  syntax error.
- **Proof / reasoning:** Reading `adapt_schema()` in both files — only one `re.sub` call for
  AUTOINCREMENT exists. No transformation for `INSERT OR REPLACE`. PostgreSQL does not support
  this SQLite-specific syntax.
- **Minimal fix:** Add regex transformation in `adapt_schema()`, or rewrite the notification
  query to use standard `INSERT ... ON CONFLICT DO UPDATE SET ...` syntax (which works on both
  SQLite 3.24+ and PostgreSQL).
- **Recommended regression test:** Test `adapt_schema("INSERT OR REPLACE INTO foo ...")` returns
  valid PostgreSQL syntax.

### No CSRF Token Protection
- **Severity:** `LOW`
- **Category:** `SECURITY`
- **Confidence:** `MEDIUM`
- **Affected files:** `dashboard/app.py` (all POST/PATCH/DELETE endpoints)
- **Why it matters:** No CSRF middleware is configured. Mutation endpoints like
  `POST /api/scan/trigger`, `POST /api/keys`, `POST /api/webhooks` accept form-encoded data.
  Without CSRF tokens, a malicious website could submit a form on behalf of an authenticated
  user whose browser holds a valid session cookie.
- **Proof / reasoning:** No import of any CSRF library. No CSRF token generation or validation
  in any middleware or endpoint. Session cookie uses `SameSite=Lax` which provides significant
  mitigation (blocks cross-origin POST from third-party sites in modern browsers), reducing
  practical exploitability.
- **Minimal fix:** Given `SameSite=Lax` is already set and the dashboard is typically accessed
  by a single admin user, the residual risk is low. For defense-in-depth, add CSRF middleware
  (e.g., `fastapi-csrf-protect` or custom `X-CSRF-Token` header validation).
- **Recommended regression test:** Test that a POST request without a valid CSRF token (from a
  different origin) returns 403.

---

## 4. Highest-ROI Improvements

| Priority | Title | Why | Effort | Risk if Ignored |
|----------|-------|-----|--------|-----------------|
| 1 | HTML escape all export outputs | XSS via HTML/PDF export download. Attacker controls scanned repo content. | 1h | HIGH — analyst workstation compromise |
| 2 | CSV injection sanitization | Formula execution when CSV opened in Excel. Same attack vector. | 30min | HIGH — code execution on analyst machine |
| 3 | Fix INSERT OR REPLACE for PostgreSQL | PostgreSQL deployments crash on notification preference writes. | 1h | MEDIUM — blocks PostgreSQL adoption |
| 4 | Deduplicate SCHEMA_SQL | Schema drift already introduced (DEFAULT mismatches). Will compound. | 2h | MEDIUM — silent data inconsistencies |
| 5 | Synchronize DEFAULT values | Four columns have different defaults between orchestrator/dashboard. | 30min | MEDIUM — insertion failures under edge cases |
| 6 | PDF markup escaping | ReportLab crashes on findings with XML-like characters in message. | 30min | LOW — DoS on report generation |
| 7 | CSRF middleware | Defense-in-depth for form-based mutations. SameSite=Lax mitigates most risk. | 2h | LOW — mitigated by SameSite=Lax |
| 8 | APIRouter decomposition of app.py | 1551 lines still in one file. All routes defined here. DX friction. | 1 day | LOW — maintainability only |
| 9 | Startup warning for insecure defaults | Warn if SESSION_SECRET is placeholder or HTTPS_ONLY not set. | 30min | LOW — operational oversight |
| 10 | Structured logging adoption | `structlog` is a dependency but unused. JSON logs needed for prod. | 3h | LOW — observability gap |

---

## 5. Testing Gaps

The following security-sensitive behaviors lack dedicated test coverage:

1. **CSV injection** — No test in `test_export.py` verifies formula character sanitization.
   All test data uses benign values.

2. **HTML/XSS in exports** — No test verifies that HTML-special characters in findings are
   escaped in HTML export output.

3. **PDF markup injection** — No test verifies that ReportLab Paragraph-breaking characters
   in finding fields are handled safely.

4. **CSRF** — No test verifies that cross-origin form submissions are rejected.

5. **PostgreSQL INSERT OR REPLACE** — No test exercises `adapt_schema()` against
   `INSERT OR REPLACE` SQL statements. The docstring claims the transformation exists but
   the code does not implement it.

6. **Schema consistency** — No test verifies that `orchestrator/storage.py` and
   `dashboard/db.py` produce identical schemas.

7. **Rate limiting bypass** — Tests verify rate limiting works, but no test checks for
   bypass via `X-Forwarded-For` header spoofing or IPv4/IPv6 address variation.

8. **Session fixation** — No test verifies that session ID is regenerated after login.

9. **Concurrent SQLite access** — WAL mode is tested for enablement, but no integration test
   simulates concurrent writer + reader to verify no `OperationalError`.

10. **Webhook DNS rebinding over time** — Tests verify initial DNS resolution check, but no
    test verifies that re-resolution at trigger time prevents TOCTOU DNS rebinding.

---

## 6. Suggested Patch Plan

### Today (< 4 hours)
- [ ] Add `html.escape()` to all interpolated values in `export.py` HTML export
- [ ] Add CSV injection sanitization (prefix-strip formula characters) in `export.py` and
      streaming CSV in `app.py`
- [ ] Add `xml.sax.saxutils.escape()` to PDF Paragraph values in `export.py`
- [ ] Add regression tests for all three export injection types
- [ ] Synchronize DEFAULT values between orchestrator and dashboard SCHEMA_SQL

### This week
- [ ] Fix `adapt_schema()` to handle `INSERT OR REPLACE` → `INSERT ... ON CONFLICT DO UPDATE`
- [ ] Deduplicate SCHEMA_SQL into a shared module importable by both components
- [ ] Add startup warning when `SESSION_SECRET` is the default placeholder
- [ ] Add startup warning when `DASHBOARD_HTTPS_ONLY` is not set and secret looks custom
- [ ] Add test for schema consistency between orchestrator and dashboard

### Next sprint
- [ ] Add CSRF middleware for form-based mutation endpoints
- [ ] Decompose `app.py` routes into FastAPI `APIRouter` modules
- [ ] Adopt `structlog` for structured JSON logging
- [ ] Add integration test for concurrent SQLite read/write under WAL mode
- [ ] Add rate limiting bypass test (X-Forwarded-For spoofing)

---

## 7. Overall Verdict

**Is this safe for personal use?**
Yes. The platform is well-built with solid auth, proper password hashing (bcrypt), rate
limiting, and now comprehensive SSRF protection. All critical findings from the prior review
are fixed.

**Is this safe for internal company use?**
Yes, with caveats. The export injection vulnerabilities mean that a scanned repository
controlled by a malicious actor could produce findings that execute code when an analyst opens
the CSV in Excel or views the HTML report. In an internal setting where all scanned repos are
trusted, this risk is acceptable. Fix the export sanitization before scanning untrusted repos.

**Is this safe for Internet exposure?**
Not yet. The export injection vulnerabilities (CSV, HTML/XSS, PDF) must be fixed first. The
`INSERT OR REPLACE` PostgreSQL bug would crash notification writes. CSRF protection should be
added for defense-in-depth. After these fixes, the platform would be suitable for Internet
exposure behind TLS with `DASHBOARD_HTTPS_ONLY=1`.

**What must be fixed before production?**
1. HTML/XSS escaping in all export outputs (export.py)
2. CSV injection sanitization (export.py, app.py streaming CSV)
3. PostgreSQL `INSERT OR REPLACE` adaptation (if PostgreSQL is used)
4. Schema DEFAULT value synchronization

---

*This review covers code as of commit `f91f284` on branch `claude/complete-claude-md-tasks-sV7d1`.*
