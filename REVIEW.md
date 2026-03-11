# Senior Staff Engineer / Security Architect Review

**Repository:** `3n1gm496/security-scanning-platform`
**Reviewer:** Staff Engineer / Security Architect (automated review via Claude)
**Review Date:** 2026-03-11
**Branch:** `claude/security-platform-review-MqdAz`

---

## A. Executive Summary

This is a well-structured, genuinely useful platform that delivers on its promise of being lightweight,
self-hostable, and CI-agnostic. The component separation (orchestrator CLI vs. dashboard FastAPI) is
clean, the PostgreSQL migration path is pragmatic, and the test coverage at 86%+ on the orchestrator
is impressive for a project at this stage. The scanner normalisation layer is mature.

However, several issues range from **immediately exploitable** to **silently incorrect**, and one
architectural pattern — the `app.py` god-class — is already eroding maintainability. The items below
are prioritised by *impact × urgency*, not theoretical risk. Every finding is grounded in specific
lines of code.

**Do right now (1-2 days):** items 1–4 are either security-critical or prevent production crashes,
and each takes under 30 minutes to fix.
**Do this week:** items 5–8 close correctness gaps and operability holes that will bite in production.
**Plan for next sprint:** items 9–10 are architectural but incremental.

SQLite is **still appropriate** for single-server deployments handling up to ~50 scans/day with a
few concurrent users on the dashboard. The PostgreSQL migration path already exists and is tested.
The one place SQLite **needs help today** is WAL mode (see item 1).

---

## B. Top 10 Prioritized Improvements Table

| # | Title | Severity | Impact | Effort | Urgency |
|---|-------|----------|--------|--------|---------|
| 1 | SQLite WAL mode not enabled | BUG | HIGH – prod crashes under concurrent load | TRIVIAL (2 lines) | **MUST FIX NOW** |
| 2 | Dashboard container runs as root | SECURITY | HIGH – full container compromise if exploited | TRIVIAL (4 lines) | **MUST FIX NOW** |
| 3 | OPERATOR role has `API_KEY_MANAGE` permission | SECURITY | CRITICAL – privilege escalation to ADMIN | TRIVIAL (1 line) | **MUST FIX NOW** |
| 4 | Docker Compose: no healthcheck on dashboard | OPS | MEDIUM – blind container restarts | TRIVIAL (6 lines) | **MUST FIX NOW** |
| 5 | Shallow git clone defeats gitleaks history scan | SECURITY | HIGH – historical secrets not found | LOW | **SHOULD FIX SOON** |
| 6 | Webhook SSRF – no URL validation | SECURITY | HIGH – internal network probing | LOW | **SHOULD FIX SOON** |
| 7 | Schema duplication + no migration system | ARCHITECTURE | HIGH – silent data loss on schema drift | MEDIUM | **SHOULD FIX SOON** |
| 8 | Cache key ignores git commit hash | CORRECTNESS | HIGH – stale scan results mask new vulns | LOW | **SHOULD FIX SOON** |
| 9 | No Prometheus metrics (observability gap) | OPS | MEDIUM – no monitoring integration | MEDIUM | Nice to have |
| 10 | `app.py` god-class (62 KB+) | MAINTAINABILITY | MEDIUM – DX is degrading fast | MEDIUM | Nice to have |

---

## C. Detailed Recommendations

---

### #1 — SQLite WAL mode not enabled

**Problem:**
Neither `orchestrator/db_adapter.py` nor `dashboard/db_adapter.py` sets `PRAGMA journal_mode=WAL`
after opening a SQLite connection. The default journal mode is DELETE (rollback journal), which uses
exclusive file locks for writes. The orchestrator and dashboard share the **same SQLite file** via a
Docker volume mount. When the orchestrator writes findings while the dashboard is simultaneously
serving read queries, SQLite issues `OperationalError: database is locked`. This is a production-
reliability bug that worsens as scan frequency grows.

**Why it matters:**
DELETE journal mode means any writer blocks all readers and vice versa. WAL mode allows one writer
and multiple concurrent readers simultaneously — exactly the access pattern here. The fix is two
lines per adapter.

**Proposed solution:**
In both `dashboard/db_adapter.py` and `orchestrator/db_adapter.py`, after opening a SQLite
connection, execute:

```python
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA synchronous=NORMAL")  # WAL + NORMAL is safe and faster than FULL
```

`synchronous=NORMAL` is safe with WAL — a power-loss can only lose the most recent committed
transaction, which the orchestrator will re-run. Do not use `synchronous=OFF`.

**Affected files:**
- `dashboard/db_adapter.py:52` (`_sqlite_connect`)
- `orchestrator/db_adapter.py:32` (`_sqlite_connect`)

**Migration / compatibility:**
WAL mode persists in the database file. An existing database is converted silently on first
connection. No data migration needed. No compatibility concerns with psycopg2 path (PRAGMAs
are SQLite-only and run inside the `if db_path != ":memory:"` block).

**Tests to add/update:**
- `test_db_adapter.py`: assert `PRAGMA journal_mode` returns `wal` after `_sqlite_connect()`
- Integration test: simulate concurrent writer + reader and assert no `OperationalError`

---

### #2 — Dashboard container runs as root

**Problem:**
`dashboard/Dockerfile` has no `USER` directive. The uvicorn process runs as UID 0 (root) inside
the container. The orchestrator correctly uses a non-root `scanuser` (UID 1000). This
inconsistency means: if an attacker exploits an RCE in the FastAPI app (e.g., via a Jinja2 SSTI,
path traversal, or a future dependency vulnerability), they gain root access to the container,
full read/write on all mounted volumes including the scan database, and a much easier pivot to
the host if the Docker socket is inadvertently exposed.

**Why it matters:**
Defence in depth: containers should never run as root. This is a trivially cheap control that
eliminates an entire privilege escalation step.

**Proposed solution:**
Add a non-root user to `dashboard/Dockerfile`, mirroring the orchestrator pattern:

```dockerfile
RUN groupadd -g 1000 dashuser && \
    useradd -u 1000 -g dashuser -m -s /bin/bash dashuser

# After all pip installs and file copies...
RUN chown -R dashuser:dashuser /app /data /config || true
USER dashuser
```

The `/data` and `/config` directories are mounted from the host, so UID ownership must match
what the host volume uses. Add `user: "1000:1000"` to the dashboard service in `docker-compose.yml`
or ensure the volume's owning UID matches.

**Affected files:**
- `dashboard/Dockerfile`
- `docker-compose.yml` (add `user:` field or document volume permissions)

**Migration / compatibility:**
Operators who rely on root access inside the container for debugging will need to use
`docker exec -u root`. No functional change.

**Tests to add/update:**
- CI smoke test: `docker inspect security-dashboard --format '{{.Config.User}}'` asserts non-empty.

---

### #3 — OPERATOR role has `API_KEY_MANAGE` permission (privilege escalation)

**Problem:**
In `dashboard/rbac.py:50-55`, `Role.OPERATOR` includes `Permission.API_KEY_MANAGE`. The
`create_api_key()` function accepts any `role: Role` parameter with **no upper-bound check** —
an OPERATOR can call `POST /api/keys` and create a new key with `role=admin`, then use that key
to perform any admin action. This is a textbook privilege escalation via broken access control
(OWASP A01:2021).

```python
# rbac.py — current (vulnerable)
Role.OPERATOR: [
    Permission.SCAN_READ,
    Permission.SCAN_WRITE,
    Permission.FINDING_READ,
    Permission.FINDING_WRITE,
    Permission.API_KEY_MANAGE,   # <-- OPERATOR can create ADMIN keys
],
```

**Why it matters:**
In a multi-tenant or enterprise environment where OPERATORs are CI pipelines or junior engineers,
this allows any OPERATOR to permanently escalate to full ADMIN access. The audit log records the
action, but nothing prevents it.

**Proposed solution:**
1. Remove `API_KEY_MANAGE` from the OPERATOR role.
2. In the `POST /api/keys` handler in `app.py`, add a role-ceiling check: an OPERATOR cannot
   create a key with a role higher than their own.

```python
# rbac.py — fixed
Role.OPERATOR: [
    Permission.SCAN_READ,
    Permission.SCAN_WRITE,
    Permission.FINDING_READ,
    Permission.FINDING_WRITE,
    # API_KEY_MANAGE removed — only ADMIN may manage keys
],
```

**Affected files:**
- `dashboard/rbac.py:50-55`
- `dashboard/app.py` (API key creation endpoint — add role ceiling assertion)

**Migration / compatibility:**
Existing OPERATORs lose the ability to manage API keys. If operators legitimately need to rotate
CI keys, add a scoped `Permission.API_KEY_ROTATE_OWN` that allows rotating only keys they created.

**Tests to add/update:**
- `test_rbac.py`: assert OPERATOR cannot create ADMIN-role key via the API endpoint
- `test_rbac.py`: assert OPERATOR cannot call `/api/keys` at all (403)

---

### #4 — Docker Compose: no healthcheck on dashboard service

**Problem:**
`docker-compose.yml` defines no `healthcheck` for the `dashboard` service despite the platform
having a working `/api/health` endpoint. The IMPROVEMENTS.md even documents the correct config
but it was never applied. Without a healthcheck:
- Docker cannot distinguish a crashed/deadlocked process from a healthy one.
- `depends_on: condition: service_healthy` cannot be used by any dependent services.
- Orchestration systems (systemd, Kubernetes, Nomad) have no liveness signal.
- `docker compose ps` shows "Up" even when the app has deadlocked.

**Why it matters:**
Healthchecks are the minimum required for any production service. The endpoint already exists.

**Proposed solution:**
Add to the `dashboard` service in `docker-compose.yml`:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

Also add `curl` to the dashboard Dockerfile's apt-get block (already present — confirmed in
`dashboard/Dockerfile:9`).

**Affected files:**
- `docker-compose.yml`

**Migration / compatibility:** None.

**Tests to add/update:**
- CI: add a step that runs `docker compose up -d && sleep 45 && docker compose ps` and asserts
  `(healthy)` status.

---

### #5 — Shallow git clone defeats gitleaks history scanning

**Problem:**
`orchestrator/scanners.py:79` always passes `--depth 1` to `git clone`. In `orchestrator/main.py:396`,
gitleaks is configured to run with `use_git_history=True` when a `.git` directory is present.
With depth=1, gitleaks's `git` mode only sees **one commit** — the HEAD. Any secret that was
committed and subsequently deleted (the most common pattern for accidentally committed credentials)
is **completely invisible**. This is a critical gap in the platform's primary value proposition.

```python
# scanners.py — current (broken for history scanning)
command = ["git", "clone", "--depth", "1", "--quiet", ...]
```

**Why it matters:**
According to GitGuardian's State of Secrets Sprawl, over 85% of exposed secrets in git history
were removed in a subsequent commit. The platform's users believe they are scanning history — they
are not.

**Proposed solution:**
Add a `git_clone_depth` setting (default: `0` = full clone, configurable to a positive integer
for shallow clones). When gitleaks is enabled and the target is a git repo, default to full clone
or at minimum a larger depth (e.g., 50-commit window). Full clone is safe given the workspace
retention policy (workspaces deleted after 3 days by default).

```yaml
# settings.yaml — proposed addition
execution:
  git_clone_depth: 0   # 0 = full history (recommended for secret scanning)
                        # Positive integer = shallow clone (faster, less storage, misses history)
```

```python
# scanners.py — fixed
depth_arg = [] if depth == 0 else ["--depth", str(depth)]
command = ["git", "clone"] + depth_arg + ["--quiet", "-c", "credential.helper="]
```

**Affected files:**
- `orchestrator/scanners.py:79` (`clone_repo`)
- `orchestrator/main.py:69` (`resolve_settings` — add `git_clone_depth` default)
- `config/settings.yaml`

**Migration / compatibility:**
Existing deployments with limited disk space should set `git_clone_depth: 50` to balance
coverage vs. storage. Full clone with depth=0 is the secure default.

**Tests to add/update:**
- `test_scanners.py`: assert `clone_repo` command does NOT contain `--depth` when depth=0
- `test_scanners.py`: assert `clone_repo` command contains `--depth 50` when depth=50

---

### #6 — Webhook SSRF — no URL validation

**Problem:**
`dashboard/webhooks.py:70-89`, the `create_webhook()` function accepts any URL string without
validation. The `trigger_webhook()` function then makes an outbound HTTP POST to that URL. An
authenticated OPERATOR (or ADMIN) can register a webhook pointing to `http://169.254.169.254/`
(AWS IMDSv1), `http://10.0.0.1/admin`, or any other internal endpoint, causing the server to
act as a proxy for SSRF attacks against internal infrastructure.

Given that:
- The `OPERATOR` role was (until fix #3) able to create webhooks
- Enterprise environments frequently have internal metadata services and admin APIs

This is a real exploitable vulnerability.

**Why it matters:**
SSRF via webhook is one of the most common ways cloud-hosted services are compromised. The
`trigger_webhook` function makes outbound requests with a 10-second timeout on every matched event,
providing a reliable SSRF oracle.

**Proposed solution:**
Add URL validation before storing or triggering a webhook:

```python
import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"https", "http"}  # In prod, consider restricting to https only
BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / IMDS
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def validate_webhook_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Webhook URL must use HTTP/HTTPS, got: {parsed.scheme}")
    try:
        addr = ipaddress.ip_address(parsed.hostname)
        for net in BLOCKED_NETS:
            if addr in net:
                raise ValueError(f"Webhook URL targets a private/reserved address: {addr}")
    except ValueError as e:
        if "private" in str(e) or "reserved" in str(e):
            raise
        # Hostname is a domain name — DNS-rebinding not mitigated here (acceptable
        # for v1; add DNS pre-resolution check for high-security environments)
```

**Affected files:**
- `dashboard/webhooks.py` (add `validate_webhook_url`, call in `create_webhook`)
- `dashboard/app.py` (webhook creation endpoint)

**Migration / compatibility:**
Existing webhooks pointing to internal addresses will fail validation on next update. Document
in CHANGELOG.

**Tests to add/update:**
- `test_webhooks.py`: assert `create_webhook` raises for `http://169.254.169.254/`
- `test_webhooks.py`: assert `create_webhook` raises for `http://10.0.0.1/`
- `test_webhooks.py`: assert valid public HTTPS URL passes

---

### #7 — Schema duplication + no migration system

**Problem:**
`SCHEMA_SQL` is defined identically in **both** `orchestrator/storage.py:13-64` and
`dashboard/db.py:278-327`. Additionally, the dashboard's `db_adapter.py` `adapt_schema` function
only handles `AUTOINCREMENT → SERIAL` — it does not handle `INSERT OR REPLACE → INSERT ... ON CONFLICT`
(PostgreSQL incompatibility left in production code).

When the schema needs a new column (e.g., `triage_status` on findings, or `scan_duration_seconds`
on scans), the developer must update both files synchronously, update the PostgreSQL DDL adaptation,
and manually alter any existing databases. There is no `schema_migrations` table, no version tracking,
and no `ALTER TABLE` scripts. Any deployed instance that is upgraded will silently miss new columns
and produce silent `KeyError` or `None` mismatches.

**Why it matters:**
This is the most common source of silent data corruption in self-hosted tools. Operators upgrade
the image, the old database has different columns, and the dashboard shows wrong KPIs or drops
findings silently.

**Proposed solution:**
1. **Deduplicate schema DDL**: Move the canonical schema to a shared location — either a
   `shared/schema.py` package (preferred) or embed it in `orchestrator/storage.py` and have the
   dashboard import it via `sys.path` (acceptable given the current monorepo structure).

2. **Add a lightweight migration table** (no Alembic needed at this scale):
   ```sql
   CREATE TABLE IF NOT EXISTS schema_migrations (
       version INTEGER PRIMARY KEY,
       applied_at TEXT NOT NULL,
       description TEXT
   );
   ```
   Apply migrations sequentially on startup via a `migrate_db()` function called from both
   `orchestrator/storage.py:init_db` and `dashboard/db.py:init_db`.

3. **Fix `INSERT OR REPLACE` → `INSERT ... ON CONFLICT DO UPDATE`** in `adapt_schema` for
   PostgreSQL compatibility (currently the PostgreSQL path silently fails or raises on any
   `INSERT OR REPLACE` statement).

**Affected files:**
- `orchestrator/storage.py`
- `dashboard/db.py`
- Both `db_adapter.py` files (`adapt_schema`)

**Migration / compatibility:**
The `schema_migrations` table is additive. `CREATE TABLE IF NOT EXISTS` is idempotent.
Existing deployments are unaffected.

**Tests to add/update:**
- Test that both components produce identical schemas on a fresh database
- Test that `migrate_db()` is idempotent (calling twice is safe)
- Test `adapt_schema` for `INSERT OR REPLACE` with PostgreSQL flag

---

### #8 — Cache key ignores git commit hash

**Problem:**
`orchestrator/cache.py:11-19`, the cache key is built from `tool_name`, `target_type`,
`target_value` (the repo URL), and `context` (scanner config). For a git target, `target_value`
is the repository URL — **not the current commit hash**. If a developer pushes new commits
within the 15-minute TTL window, the orchestrator will serve the cached result from before
the push, silently missing any newly introduced vulnerabilities.

This is especially dangerous for:
- Semgrep SAST results (new code patterns not checked)
- Gitleaks secret scanning (new secret commits not flagged)
- Checkov IaC findings (new misconfigurations missed)

**Why it matters:**
The platform is supposed to act as a CI gate. A cached PASS result from before a `git push`
means the gate passes even when it should block. This undermines the core security value of
the product.

**Proposed solution:**
After cloning the repository (in `prepare_target()`), resolve the HEAD commit SHA and include
it in the cache context:

```python
def get_git_head_sha(repo_path: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None
```

Pass this SHA as part of `cache_context` when calling `execute_tool` for git targets. The
cache key will then be unique per commit, eliminating stale results.

**Affected files:**
- `orchestrator/main.py` (`prepare_target`, `run_single_scan`)
- `orchestrator/cache.py` (documentation update)

**Migration / compatibility:**
All existing cache entries for git targets are effectively invalidated (new keys will miss).
This is the correct behaviour.

**Tests to add/update:**
- `test_cache.py`: assert cache key differs for same URL at different commits
- `test_main_coverage.py`: assert git HEAD SHA is included in cache context

---

### #9 — No Prometheus metrics (observability gap)

**Problem:**
`dashboard/monitoring.py:103-117`, the `/api/metrics` endpoint returns basic JSON with only
`app_uptime_seconds` and static version info. There are no counters for scans completed, no
histograms for scan duration, no gauges for active jobs, no finding counts by severity. The
`version` field is hardcoded to `"1.0.0"` regardless of actual version.

The `prometheus_client` library is not in `dashboard/requirements.txt`, meaning there is no
path to Prometheus scraping. The IMPROVEMENTS.md mentions this as a "future enhancement" but
provides no implementation.

**Why it matters:**
In enterprise environments, the security team needs alerting on: sudden spikes in CRITICAL
findings, scan failures, dropped scans. Without Prometheus metrics, none of these are
automatable. IMPROVEMENTS.md explicitly calls out Prometheus as a P1 item.

**Proposed solution:**
Add `prometheus_client>=0.20.0` to `dashboard/requirements.txt`. Expose a proper `/metrics`
endpoint alongside the existing JSON `/api/metrics`:

```python
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

scans_total = Counter("ssp_scans_total", "Total scans completed", ["status", "policy_status"])
scan_duration = Histogram("ssp_scan_duration_seconds", "Scan duration", buckets=[10,30,60,120,300,600])
findings_total = Gauge("ssp_findings_total", "Current total findings", ["severity"])
```

Mount the Prometheus ASGI app at `/metrics` (unauthenticated is standard for scraping behind
a firewall; optionally add Bearer auth).

Also: read the version from a `VERSION` file or `importlib.metadata` rather than hardcoding.

**Affected files:**
- `dashboard/monitoring.py`
- `dashboard/requirements.txt`
- `dashboard/app.py` (mount metrics endpoint)

**Migration / compatibility:** None. Additive change.

**Tests to add/update:**
- `test_monitoring.py`: assert `/metrics` returns `text/plain; version=0.0.4` content type
- `test_monitoring.py`: assert scan counter increments after a scan completes

---

### #10 — `app.py` god-class (62 KB+)

**Problem:**
`dashboard/app.py` is a 62 KB+ file containing: application bootstrapping, rate limiting
implementation, login/logout handlers, scan trigger logic, 30+ API route handlers, the
`run_scan_async` subprocess wrapper, and middleware configuration. Despite having separate
modules for `auth`, `rbac`, `webhooks`, `finding_management`, and `export`, all route
definitions and much of the business logic remain in `app.py`.

Symptoms already visible:
- CI bandit scan excludes `B608` globally to suppress a false positive in this file
- Test files have names like `test_coverage_gaps.py` and `test_app_coverage.py` — coverage
  archaeology rather than purposeful testing
- The rate limiter (a threading.Lock + deque) is embedded inline, making it untestable
  in isolation

**Why it matters:**
This is the highest-friction change per line of code added to the project. Any new endpoint
requires understanding the entire file. The embedded rate limiter and thread pool cannot be
tested without spinning up the full FastAPI app.

**Proposed solution:**
Extract into FastAPI `APIRouter` modules (incremental, not a rewrite):
1. `dashboard/routers/scans.py` — scan trigger, scan listing, scan detail
2. `dashboard/routers/settings.py` — API key management, webhook management
3. `dashboard/routers/exports.py` — all export endpoints
4. `dashboard/routers/triage.py` — finding status, comments, assignments

Move `_is_rate_limited()` and the rate bucket state into `dashboard/rate_limit.py`.
Move `run_scan_async()` into `dashboard/scan_runner.py`.

Each module can then be independently unit-tested with `TestClient` focused only on that
router's routes.

**Affected files:**
- `dashboard/app.py` (shrinks to ~100 lines of bootstrap + router registration)
- New `dashboard/routers/` directory
- `dashboard/rate_limit.py`, `dashboard/scan_runner.py`

**Migration / compatibility:** API surface unchanged. Purely internal refactor.

**Tests to add/update:**
- Refactor `test_app_coverage.py` into focused `test_routers_*.py` files
- Add `test_rate_limit.py` that tests the rate limiter in pure Python without HTTP

---

## D. Phased Roadmap

### Phase 1: Quick wins — 1–2 days

These are all one-file, low-risk changes. Ship as a single PR.

| Task | File(s) | Time |
|------|---------|------|
| Enable SQLite WAL mode | `dashboard/db_adapter.py`, `orchestrator/db_adapter.py` | 20 min |
| Dashboard non-root Dockerfile | `dashboard/Dockerfile`, `docker-compose.yml` | 30 min |
| Remove `API_KEY_MANAGE` from OPERATOR | `dashboard/rbac.py`, `dashboard/app.py` | 20 min |
| Add Docker Compose healthcheck | `docker-compose.yml` | 15 min |
| Fix shallow clone depth | `orchestrator/scanners.py`, `orchestrator/main.py`, `config/settings.yaml` | 45 min |
| Basic webhook URL validation | `dashboard/webhooks.py` | 45 min |

**Expected outcome:** Zero production-crash bugs, zero trivially exploitable security issues.

### Phase 2: Medium improvements — up to 1 week

| Task | File(s) | Time |
|------|---------|------|
| Git commit hash in cache key | `orchestrator/main.py`, `orchestrator/cache.py` | 2h |
| Schema single source of truth + migration table | `orchestrator/storage.py`, `dashboard/db.py` | 1 day |
| Prometheus metrics | `dashboard/monitoring.py`, `dashboard/requirements.txt` | 3h |
| Fix `INSERT OR REPLACE` PostgreSQL adaptation | `dashboard/db_adapter.py`, `orchestrator/db_adapter.py` | 2h |
| CI: add Python 3.12 to matrix | `.github/workflows/ci.yml` | 30 min |
| CI: add `pip audit` for dependency CVE scanning | `.github/workflows/ci.yml` | 30 min |
| Add `healthcheck` test in CI | `.github/workflows/ci.yml` | 30 min |

### Phase 3: Architectural changes — next sprint

| Task | Description |
|------|-------------|
| `app.py` decomposition | Extract routers, rate limiter, scan runner into separate modules |
| Async job queue | Replace `ThreadPoolExecutor` + `subprocess.run` with a proper async job queue (Celery + Redis, or even just a SQLite-backed job table polled by the orchestrator). Persist job state across restarts. |
| `structlog` adoption | Replace `logging.basicConfig` with structured JSON logging throughout. `structlog` is already a dependency but unused. |
| Type annotation pass | `app.py` and `db.py` use `dict[str, Any]` everywhere. Add Pydantic request/response models for all API endpoints. This would have caught the OPERATOR privilege escalation issue automatically. |

---

## E. Suggested First Implementation Batch

Ship all of Phase 1 in a single PR. Here is the exact implementation order to minimise conflicts:

1. `dashboard/db_adapter.py` → add WAL PRAGMA (no test changes needed, existing tests pass)
2. `orchestrator/db_adapter.py` → add WAL PRAGMA (same)
3. `dashboard/Dockerfile` → add non-root user (build test in CI validates)
4. `docker-compose.yml` → add healthcheck + `user:` field
5. `dashboard/rbac.py` → remove `API_KEY_MANAGE` from OPERATOR
6. `dashboard/app.py` → add role-ceiling check in key creation endpoint
7. `orchestrator/scanners.py` + `orchestrator/main.py` + `config/settings.yaml` → configurable clone depth
8. `dashboard/webhooks.py` → webhook URL validation

**Test additions for this batch:**
- `test_rbac.py`: OPERATOR cannot create ADMIN key
- `test_webhooks.py`: SSRF URL cases rejected
- `test_scanners.py`: clone depth=0 omits `--depth` flag

**Estimated total time:** 4–5 hours of focused implementation + 1–2 hours of test writing.

---

## Additional Notes

**Where SQLite is still fine:**
- Single-server self-hosted deployments
- Up to ~100 scans/day with findings in the low tens of thousands
- Single-region deployments without HA requirements
- Development and CI environments

**Where SQLite becomes a bottleneck:**
- Multiple concurrent scan workers writing simultaneously (>4 concurrent targets)
- Finding tables growing past ~500K rows (query plans degrade without better indexes)
- Multi-node deployments (SQLite cannot be shared across machines)
- When `webhook_deliveries` table grows unboundedly (no retention policy for this table — add one)

**PostgreSQL upgrade trigger:**
Switch to PostgreSQL when `max_concurrent_targets > 4` consistently, or when the team needs
replicated read access to findings from multiple machines. The migration path already exists
and is tested.

---

*This review covers code as of commit `c64e338` on branch `claude/security-platform-review-MqdAz`.*
