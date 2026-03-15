# Repository Review

**Repository:** `3n1gm496/security-scanning-platform`
**Reviewer:** Senior Security Engineer / Staff Architect (automated review via Claude)
**Review Date:** 2026-03-15
**Branch:** `copilot/unknown-repository-path`
**Previous Reviews:** 2026-03-14 (`claude/complete-claude-md-tasks-sV7d1`), 2026-03-11 (`claude/security-platform-review-MqdAz`)

---

## 1. Executive Summary

The platform has reached a **mature security baseline**. All ten original findings from the
March 11 review and all six "new findings" from the March 14 review have been fully or
substantially resolved. In particular:

- CSV injection, HTML/XSS injection, and PDF markup injection in exports are **all fixed**
  (`html_escape`, `xml_escape`, `_sanitize_csv_value` now applied throughout `export.py`).
- Schema duplication is **fully resolved** — both orchestrator and dashboard now import from
  `common/schema.py` as the single source of truth.
- CSRF protection is **implemented** via `CSRFMiddleware` with API-key exemption.
- `app.py` god-class is **resolved** — all routes decomposed into `dashboard/routers/`.

**Three new, concrete issues remain as of this review:**

1. **Rate-limiting bypass via X-Forwarded-For spoofing** — any unauthenticated client can
   bypass brute-force and API rate limits by forging the `X-Forwarded-For` header.
2. **`INSERT OR IGNORE` syntax breaks PostgreSQL** — `scan_runner.py:36` uses SQLite-only
   syntax that will raise a syntax error on any PostgreSQL deployment, breaking all scan
   triggering.
3. **Audit log CSV export has no injection sanitization** — `audit_routes.py` exports raw
   values (including attacker-influenced IP addresses and key names) without formula escaping.

The platform is **safe for internal use** behind a firewall or VPN. **Internet exposure
remains inadvisable** until the X-Forwarded-For bypass is fixed (it allows brute-forcing
the login from any IP). PostgreSQL deployments are non-functional for triggered scans until
the `INSERT OR IGNORE` issue is resolved.

---

## 2. Architecture Summary

- **Orchestrator** (`orchestrator/`): Python CLI run as subprocess by the dashboard. Clones
  repos, runs scanners (semgrep, trivy, gitleaks, checkov, syft, bandit, nuclei, grype, ZAP),
  normalizes results, stores findings to SQLite/PostgreSQL.
- **Dashboard** (`dashboard/`): FastAPI + Starlette app. Session + API-key auth, RBAC
  (admin/operator/viewer), SQLite or PostgreSQL backend, Prometheus metrics, CSRF middleware,
  webhooks, exports, analytics, email notifications.
- **Common** (`common/`): Single-source schema (`common/schema.py`).
- **Storage**: SQLite (default, WAL mode enabled), PostgreSQL (optional via `DATABASE_URL`).
- **Docker**: Non-root containers (`dashuser`, `scanuser`), health checks on all services,
  separated `frontend`/`backend` networks.

---

## 3. Validation of Existing Review

### From March 11 Review (Original Top-10)

#### #1 — SQLite WAL mode not enabled
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/db_adapter.py` and `orchestrator/db_adapter.py` both execute
  `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` in `_sqlite_connect()`.

#### #2 — Dashboard container runs as root
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/Dockerfile` creates `dashuser` (UID 1000), sets `USER dashuser`.
  Orchestrator similarly uses `scanuser`.

#### #3 — OPERATOR role has API_KEY_MANAGE permission
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/rbac.py:52-58` — `API_KEY_MANAGE` removed from OPERATOR role with
  explicit comment. `dashboard/routers/api_keys.py:33-39` enforces a role-ceiling check
  (`_ROLE_RANK`) preventing any principal from creating keys above their own role.

#### #4 — No healthcheck on dashboard
- **Status:** `FULLY FIXED`
- **Evidence:** All four services (postgres, zap, orchestrator, dashboard) have `healthcheck`
  blocks in `docker-compose.yml`. Dashboard: `curl -f http://localhost:8080/api/health`,
  30 s interval.

#### #5 — Shallow git clone defeats gitleaks
- **Status:** `FULLY FIXED`
- **Evidence:** `orchestrator/scanners.py` — `clone_repo()` defaults to `depth=0` (full
  clone). Configurable via `ORCH_GIT_CLONE_DEPTH` with secure default.

#### #6 — Webhook SSRF
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/webhooks.py:35-93` — `validate_webhook_url()` blocks RFC 1918,
  loopback, link-local, IMDS ranges, with IPv4-mapped IPv6 check and DNS rebinding
  mitigation. Validated at both creation and delivery time.

#### #7 — Schema duplication + no migration system
- **Status:** `FULLY FIXED`
- **Evidence:** Both `orchestrator/storage.py:13` and `dashboard/db.py:15` import
  `SCHEMA_SQL, MIGRATIONS` from `common/schema.py`. Migration runner applies versioned
  migrations idempotently in both components.

#### #8 — Cache key ignores git SHA
- **Status:** `FULLY FIXED`
- **Evidence:** `orchestrator/scanners.py` — `get_git_commit_sha()` resolves HEAD after
  clone. SHA injected into cache context, preventing stale-cache hits on new commits.

#### #9 — No Prometheus metrics
- **Status:** `FULLY FIXED`
- **Evidence:** `prometheus-client` in requirements. `dashboard/monitoring.py` exposes
  Counters/Gauges/Histograms. `/metrics` endpoint requires authentication.

#### #10 — `app.py` god-class
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/routers/` — eight separate APIRouter modules (`auth_routes`,
  `api_keys`, `webhook_routes`, `export_routes`, `analytics_routes`, `scan_routes`,
  `finding_routes`, `notification_routes`, `audit_routes`). `app.py` is now a thin
  orchestration layer.

---

### From March 14 Review (New Findings)

#### CSV Injection in Export
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/export.py:19-32` — `_sanitize_csv_value()` prefixes formula
  characters with `'`. Applied to all rows in `export_to_csv()` and the streaming CSV
  path in `export_routes.py`.

#### HTML/XSS Injection in HTML Export
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/export.py:9` imports `html_escape`. All interpolated finding
  fields (`title`, `tool`, `target`, `category`, `cve_id`, `cwe_id`, `cvss_score`,
  `description`) are wrapped with `html_escape()` at lines 330-336.

#### PDF Markup Injection
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/export.py:12` imports `xml_escape`. Applied to all ReportLab
  `Paragraph` interpolations: `title`, `tool`, `category`, `file`, `description`
  (lines 567-585).

#### Schema Divergence Between Orchestrator and Dashboard
- **Status:** `FULLY FIXED`
- **Evidence:** `common/schema.py` is the single source of truth. Both components import
  `SCHEMA_SQL` and `MIGRATIONS` from it. No independent schema definitions remain.

#### PostgreSQL INSERT OR REPLACE Not Adapted
- **Status:** `PARTIALLY FIXED`
- **Evidence:**
  - `dashboard/notifications.py:302-309` — fixed: now uses portable
    `INSERT INTO ... ON CONFLICT(user_email) DO UPDATE SET ...` syntax.
  - `dashboard/scan_runner.py:36` — **NOT FIXED**: still uses `INSERT OR IGNORE INTO scans`
    which is SQLite-specific and will fail on PostgreSQL (see new finding [N2]).

#### No CSRF Token Protection
- **Status:** `FULLY FIXED`
- **Evidence:** `dashboard/csrf.py` — `CSRFMiddleware` validates `X-CSRF-Token` header on
  all mutating requests. API-key-authenticated requests are exempt (verified via
  `verify_api_key()`). Exempt paths include `/login`, health/readiness probes, SSE endpoint.

#### app.py Route Decomposition
- **Status:** `FULLY FIXED`
- **Evidence:** All routes live in `dashboard/routers/`. `app.py` registers nine routers
  and defines only page routes and simple top-level endpoints.

---

## 4. New Findings

### [N1] Rate-Limiting Bypass via X-Forwarded-For Spoofing

- **Severity:** `HIGH`
- **Category:** `SECURITY`
- **Confidence:** `HIGH`
- **Affected files:** `dashboard/app.py:257-263`
- **Why it matters:** The login brute-force limit (10 attempts per 60 s) and the API rate
  limit (180 req/60 s) are keyed on the client IP returned by `_client_key()`. This function
  unconditionally trusts the `X-Forwarded-For` header without any trusted-proxy allowlist.
  Any HTTP client can forge `X-Forwarded-For: 192.0.2.1` to obtain a fresh rate-limit
  bucket, bypassing both the login brute-force guard and the API throttle entirely.
- **Proof / reasoning:**
  ```python
  # app.py:257-263
  def _client_key(request: Request) -> str:
      forwarded_for = request.headers.get("x-forwarded-for")
      if forwarded_for:
          return forwarded_for.split(",")[0].strip()  # trusts any header unconditionally
      ...
  ```
  An attacker exhausts 10 login attempts under IP A, then retries with
  `X-Forwarded-For: B` to get 10 more — indefinitely. The brute-force protection is
  effectively bypassed against any remote adversary.
- **Minimal fix:** Only trust `X-Forwarded-For` when the request arrives from a known
  reverse proxy IP. Recommended approach: use Uvicorn's `--forwarded-allow-ips` flag in
  production, and document this requirement in `.env.example`. Alternatively, add a
  `TRUSTED_PROXY_CIDR` env var and validate against it in `_client_key()`.
- **Recommended regression test:** Test that sending `X-Forwarded-For: 10.0.0.99` from an
  untrusted connecting IP does NOT produce a different rate-limit bucket than the real IP.

---

### [N2] `INSERT OR IGNORE` Syntax Breaks All PostgreSQL Scan Triggers

- **Severity:** `HIGH`
- **Category:** `BUG`
- **Confidence:** `HIGH`
- **Affected files:** `dashboard/scan_runner.py:36`
- **Why it matters:** When `DATABASE_URL` is set (PostgreSQL mode), every call to
  `trigger_scan` raises a `psycopg2.errors.SyntaxError` because PostgreSQL does not support
  `INSERT OR IGNORE INTO`. The error is silently swallowed by the `except Exception` block in
  `insert_running_scan()`, so the HTTP response still returns 200 — but no RUNNING scan row
  is created, and subsequent scan result storage may fail or produce orphaned findings.
- **Proof / reasoning:** `scan_runner.py:36` executes `INSERT OR IGNORE INTO scans (...)`.
  The `_ConnectionWrapper.execute()` path calls `_adapt_sql()` which only converts `?` to
  `%s`; it does **not** transform SQLite keyword syntax. PostgreSQL receives
  `INSERT OR IGNORE INTO scans ...` verbatim and rejects it with
  `ERROR: syntax error at or near "OR"`.
- **Minimal fix:** Replace the SQLite-only syntax with the portable upsert idiom:
  ```sql
  INSERT INTO scans (...) VALUES (...)
  ON CONFLICT(id) DO NOTHING
  ```
  `ON CONFLICT(id) DO NOTHING` is supported by both SQLite 3.24+ and PostgreSQL 9.5+.
- **Recommended regression test:** Test `insert_running_scan()` with `is_postgres()` returning
  True (or against a real PostgreSQL backend) and verify it completes without raising.

---

### [N3] Audit Log CSV Export Missing Injection Sanitization

- **Severity:** `MEDIUM`
- **Category:** `SECURITY`
- **Confidence:** `HIGH`
- **Affected files:** `dashboard/routers/audit_routes.py:70-83`
- **Why it matters:** The audit log contains attacker-influenced fields: `ip_address` (taken
  from `X-Forwarded-For` without validation), `api_key_prefix` (first 12 chars of a
  submitted key), and `resource` (includes caller-controlled scan targets and key names).
  When an admin exports the audit log as CSV and opens it in Excel or LibreOffice Calc, any
  cell beginning with `=`, `+`, `-`, or `@` is interpreted as a formula, potentially
  executing commands on the analyst's workstation (DDE injection / formula injection).
- **Proof / reasoning:** An attacker sends login requests with
  `X-Forwarded-For: =cmd|calc!A1`. The failed-login audit entry stores this as `ip_address`.
  `audit_routes.py:78-82` writes rows with `w.writerow(row)` — no `_sanitize_csv_row` call.
  The exports module already defines `_sanitize_csv_row` for this exact purpose.
- **Minimal fix:**
  ```python
  from export import _sanitize_csv_row
  # In export_audit_log():
  for row in rows:
      w.writerow(_sanitize_csv_row(row))
  ```
- **Recommended regression test:** Assert that `export_audit_log(format="csv")` for an audit
  entry with `ip_address="=cmd|calc!A1"` produces a CSV where the value is prefixed with `'`.

---

### [N4] `adapt_schema()` Docstring Overstates INSERT OR REPLACE Transformation

- **Severity:** `LOW`
- **Category:** `CORRECTNESS`
- **Confidence:** `HIGH`
- **Affected files:** `dashboard/db_adapter.py:394-411`
- **Why it matters:** The docstring claims `INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE`,
  but the implementation only strips `OR REPLACE`, producing bare `INSERT INTO`. On conflict
  this would raise a unique-constraint violation rather than updating. This is currently
  harmless (function is only called on DDL, not DML), but the misleading comment risks future
  misuse.
- **Minimal fix:** Correct the docstring to describe the actual behavior, or remove the
  `INSERT OR REPLACE` regex entirely and document that callers must use portable syntax.

---

### [N5] SMTP STARTTLS Without Explicit TLS Certificate Verification

- **Severity:** `LOW`
- **Category:** `SECURITY`
- **Confidence:** `MEDIUM`
- **Affected files:** `dashboard/notifications.py:265`
- **Why it matters:** `server.starttls()` is called without an explicit `ssl.SSLContext`.
  While Python 3.10+ creates a verifying context by default, this is a fragile reliance on
  implicit behavior. An environment running Python 3.9 or a downgraded TLS negotiation
  could expose SMTP credentials over an unverified connection.
- **Minimal fix:**
  ```python
  import ssl
  ctx = ssl.create_default_context()
  server.starttls(context=ctx)
  ```

---

## 5. Highest-ROI Improvements

| Priority | Title | Why | Effort | Risk if Ignored |
|----------|-------|-----|--------|-----------------|
| 1 | Fix X-Forwarded-For rate-limit bypass (N1) | Login brute force trivially bypassed. Blocks safe Internet exposure. | 30 min | HIGH — auth bypass from any IP |
| 2 | Fix INSERT OR IGNORE for PostgreSQL (N2) | All scan triggers silently fail on PostgreSQL. | 15 min | HIGH — PostgreSQL non-functional |
| 3 | CSV injection sanitization in audit export (N3) | Attacker-influenced fields can execute code on analyst workstation. | 15 min | MEDIUM — analyst machine compromise |
| 4 | Fix adapt_schema() docstring (N4) | Misleading comment risks future PostgreSQL adaptation bugs. | 10 min | LOW — currently dead code |
| 5 | Explicit SMTP TLS verification (N5) | SMTP creds potentially exposed on Python < 3.10 or downgraded TLS. | 5 min | LOW — mitigated on Python 3.11 |
| 6 | Document Uvicorn --forwarded-allow-ips in .env.example | Ops teams need to know how to configure proxy trust for rate limiting. | 20 min | LOW — ops guidance |
| 7 | Length-cap `name` and `target` in scan trigger | No max-length validation; unbounded input stored in DB. | 10 min | LOW — DoS / log flooding |
| 8 | Auto-prune webhook delivery log on startup | Webhook delivery rows grow unbounded unless admin manually calls purge. | 1 h | LOW — disk growth |
| 9 | Explicit CORS allow_headers allowlist | Wildcard `allow_headers=["*"]` is permissive; explicit list is safer. | 5 min | LOW |
| 10 | Content-Security-Policy in exported HTML | Defense-in-depth for HTML report downloads. | 10 min | LOW |

---

## 6. Testing Gaps

1. **X-Forwarded-For rate-limit bypass** — No test verifies that a forged
   `X-Forwarded-For` header does NOT bypass rate limiting from an untrusted connecting IP.

2. **PostgreSQL INSERT OR IGNORE** — No test exercises `insert_running_scan()` against a
   PostgreSQL backend. The bug is invisible in SQLite-only test environments.

3. **Audit log CSV injection** — No test verifies formula escaping on audit log CSV export.

4. **`adapt_schema()` INSERT OR REPLACE** — No test verifies the actual (incomplete) behavior
   vs. the documented behavior of the transformation.

5. **Role-ceiling on key deletion** — Tests verify creation ceiling, but no test explicitly
   verifies that an operator cannot delete an admin key (currently blocked by the
   `API_KEY_MANAGE` permission requirement, but worth an explicit regression test).

6. **SMTP TLS certificate verification** — No test asserts that `starttls()` is called with
   an explicit, verifying SSL context.

---

## 7. Suggested Patch Plan

### Today (< 1 hour total)
- **Fix N2**: Replace `INSERT OR IGNORE INTO scans` with `INSERT INTO ... ON CONFLICT(id) DO NOTHING`
  in `dashboard/scan_runner.py:36`.
- **Fix N3**: Import `_sanitize_csv_row` into `audit_routes.py` and apply to all CSV rows.
- **Fix N4**: Correct `adapt_schema()` docstring to accurately describe actual behavior.

### This Week
- **Fix N1**: Add `TRUSTED_PROXY_CIDR` env var support to `_client_key()` and document
  Uvicorn's `--forwarded-allow-ips` in `README.md` / `.env.example`.
- **Fix N5**: Pass explicit `ssl.create_default_context()` to `server.starttls()`.
- Add regression tests for N2 (PostgreSQL-mode scan trigger), N3 (audit CSV injection),
  and N1 (rate-limit with spoofed header).

### Next Sprint
- Bounded webhook delivery log (auto-prune on startup after configurable retention days).
- `name` and `target` max-length validation in scan trigger endpoint.
- Tighten CORS `allow_headers` to an explicit allowlist.
- Add `Content-Security-Policy` meta tag to HTML exports.

---

## 8. Overall Verdict

| Question | Answer |
|----------|--------|
| Safe for personal use? | **Yes** |
| Safe for internal company use (behind firewall/VPN)? | **Yes** — fix N2 before using PostgreSQL backend |
| Safe for Internet exposure? | **No** — N1 allows brute-forcing login from any IP; fix before exposing publicly |
| What must be fixed before production (internet-facing)? | N1 (rate-limit bypass), N2 (PostgreSQL scan trigger), N3 (audit CSV injection) |

The platform is substantially better than at the start of the review cycle. Security
fundamentals (CSRF, SSRF, export injection, RBAC, non-root containers, WAL mode, Prometheus,
schema management) are all addressed. The remaining issues are localized, fixable in under
an hour combined, and do not represent architectural flaws.
