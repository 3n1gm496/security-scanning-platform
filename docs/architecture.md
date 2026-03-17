# Architecture

This document is the current product-level architecture reference for the platform.

The Mermaid source of truth lives in [architecture.mmd](architecture.mmd), and a compact rendered view is also embedded in the repository README.

---

## System overview

The platform is split into two major runtimes:
- the **dashboard service**, a FastAPI application that serves the SPA, APIs, auth, analytics, exports, notifications, webhooks, and scan-triggering endpoints
- the **orchestrator**, a Python CLI/runtime that prepares targets, runs scanners, normalizes results, applies policy, and persists outputs

Persistence is shared:
- SQLite by default
- PostgreSQL optionally through `DATABASE_URL`
- optional PostgreSQL read routing through `DATABASE_READ_URL` on dashboard read-heavy paths

The operator-facing experience is the dashboard SPA:
- Vue-based single-page app
- dark-first SOC interface
- charts via Chart.js
- soft-live refresh model for active scan visibility
- hash-routed navigation for `dashboard`, `scans`, `findings`, `analytics`, `compare`, and `settings`

---

## Main components

### Dashboard service

Primary responsibilities:
- authentication and session handling
- API key verification and RBAC
- CSRF protection for browser-based mutating requests
- SPA and template delivery
- scans, findings, analytics, compare, settings, export, audit, and monitoring APIs
- scan trigger orchestration through `scan_runner.py`
- webhook delivery and email notification integrations

Key modules:
- `dashboard/app.py`
- `dashboard/rbac.py`
- `dashboard/pagination.py`
- `dashboard/finding_management.py`
- `dashboard/analytics.py`
- `dashboard/export.py`
- `dashboard/notifications.py`
- `dashboard/webhooks.py`
- `dashboard/scan_runner.py`

### Orchestrator

Primary responsibilities:
- resolve requested targets
- prepare working directories
- clone repositories or resolve local/image/url targets
- choose compatible scanners
- run scanner subprocesses
- normalize raw outputs into unified findings
- apply policy engine decisions
- persist reports and metadata

Key modules:
- `orchestrator/main.py`
- `orchestrator/scanners.py`
- `orchestrator/normalizer.py`
- `orchestrator/compatibility.py`
- `orchestrator/cache.py`
- `orchestrator/policy_engine.py`

### Database layer

Primary responsibilities:
- schema initialization and migrations
- findings and scans persistence
- analytics queries
- RBAC tables
- finding state / triage state
- webhooks, notifications, and audit data

Key modules:
- `common/schema.py`
- `dashboard/db.py`
- `orchestrator/db_adapter.py`

---

## Data flow

### Scan trigger flow

1. A browser user or CI caller hits `POST /api/scan/trigger`.
2. The dashboard validates auth, permissions, and input.
3. `dashboard/scan_runner.py` inserts a `RUNNING` scan row and starts the orchestrator subprocess.
4. The orchestrator:
   - validates the scan id
   - resolves settings and target
   - prepares workspace/report directories
   - runs compatible scanners
   - normalizes findings
   - evaluates policies
   - stores artifacts and normalized output
   - updates the scan row to final status
5. The dashboard surfaces the results through scans, findings, analytics, compare, exports, notifications, and webhook flows.
6. The dashboard runtime dispatches scan summary emails, high/critical finding alerts, and webhook events after final scan results are available.

### Findings lifecycle

1. Raw scanner output is normalized into a common finding shape.
2. Findings are stored centrally.
3. Operators triage findings through:
   - status changes
   - assignment
   - false-positive marking
   - risk acceptance
   - comments
4. Analytics and exports read both the findings table and the finding-state tables.

### Analytics flow

Analytics are query-driven:
- risk distribution
- compliance summary
- trend analysis
- target risk ranking
- tool effectiveness

The dashboard frontend consumes these APIs separately from the scans/findings list APIs so the UI can refresh them with different cadence and motion rules.

---

## Scanner execution model

The orchestrator uses a compatibility matrix as the routing source of truth:
- git/local targets for code and dependency scanners
- image targets for image-aware scanners
- URL targets for live endpoint scanning

Important execution behaviors:
- scanner binaries are checked before execution
- missing binaries are surfaced as skipped/unavailable rather than silently ignored
- scanner subprocesses use a controlled environment
- caching exists for eligible outputs
- policy is evaluated after normalization, not on raw tool output

---

## Reports and artifacts

Main runtime directories:
- reports: normalized output, raw output, metadata
- workspaces: prepared target copies/clones
- cache: scanner cache such as Trivy DB/cache

Relevant environment variables:
- `REPORTS_DIR`
- `WORKSPACE_DIR`
- `TRIVY_CACHE_DIR`
- `ORCH_DB_PATH`
- `DASHBOARD_DB_PATH`

---

## Dashboard frontend architecture

The SPA is template-backed and mounted from `dashboard/templates/app.html`.

Main concerns:
- navigation between dashboard, scans, findings, analytics, compare, and settings
- chart lifecycle management
- soft-live refresh instead of destructive polling
- theme switching without losing chart state
- modal-driven workflows for investigations and configuration

QA for this layer is covered by:
- Python tests for the APIs and backend behavior
- browser smoke screenshots in `artifacts/browser-smoke/`

---

## CI and image build architecture

The repository currently uses:
- Python matrix tests (`3.11`, `3.12`)
- Bandit and `pip-audit`
- Docker builds for dashboard and orchestrator
- Trivy image scanning
- reusable `Security Scan` workflow

Scanner toolchain notes:
- `trivy` is built from source with the patched dependency version required by current scanning policy
- `gitleaks` is built from source with a patched Go toolchain
- `docker/scanner-tools.Dockerfile` is used to prime and reuse scanner-tool cache in CI

Current security-scan workflow semantics:
- remote platform scan when scanner secrets are configured
- local Gitleaks fallback otherwise
- therefore a green workflow result does not always mean the same security depth

---

## Operational modes

Supported deployment styles:
- Docker Compose, the primary documented path
- local development without Docker
- GitHub Actions and GitLab-driven integration
- optional PostgreSQL profile
- optional ZAP service on the internal Docker network

For operational details, see:
- [deployment.md](deployment.md)
- [operations.md](operations.md)
- [security-model.md](security-model.md)
