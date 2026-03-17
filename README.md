# Security Scanning Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135+-009688.svg)](https://fastapi.tiangolo.com)
[![CI](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml)

Centralized security scanning platform with two main runtimes:
- a **FastAPI dashboard service** for auth, APIs, analytics, exports, settings, notifications, webhooks, and the operator UI
- a **Python orchestrator** that prepares targets, runs scanners, normalizes output, applies policy, and persists results

The platform is designed to scan code repositories, local paths, live URLs, and container images with a single normalized findings model.

**Repository:** [github.com/3n1gm496/security-scanning-platform](https://github.com/3n1gm496/security-scanning-platform)

---

## What it does

### Scan orchestration
- runs Semgrep, Bandit, Checkov, Gitleaks, Trivy, Grype, Syft, Nuclei, and optionally OWASP ZAP
- supports `git`, `local`, `url`, and `image` targets
- uses a compatibility matrix so only valid scanners run for each target type
- normalizes raw scanner outputs into a shared findings shape
- evaluates policies after normalization to decide pass/block status

### Dashboard and operations
- central scan history and findings triage
- compare two scans of the same target
- analytics for risk, compliance, trends, target ranking, and tool effectiveness
- exports in CSV, JSON, SARIF, HTML, and PDF
- API key management, webhooks, notifications, audit log, health, readiness, and Prometheus metrics

### Current repository baseline
- `607` Python tests green
- browser smoke covers login, dashboard, scans, findings, analytics, compare, settings, modals, light theme, and mobile nav
- CI builds Docker images and scans them with Trivy
- reusable `Security Scan` workflow supports either remote platform scan or local Gitleaks fallback

---

## Supported scanners

| Scanner | Category | Targets |
|---|---|---|
| Semgrep | SAST | `git`, `local` |
| Bandit | Python SAST | `git`, `local` |
| Checkov | IaC | `git`, `local` |
| Gitleaks | Secret scanning | `git`, `local` |
| Trivy FS | Dependency / config / vuln scanning | `git`, `local` |
| Trivy Image | Container image scanning | `image` |
| Grype | SBOM vulnerability scanning | `git`, `local`, `image` |
| Syft | SBOM generation | `git`, `local`, `image` |
| Nuclei | URL / template scanning | `git`, `local`, `url` |
| OWASP ZAP | DAST | `url` |

Routing and preflight checks are defined in `orchestrator/compatibility.py`.

---

## Architecture

### High-level runtime model

1. A user or CI caller hits the dashboard API.
2. The dashboard authenticates the request and validates permissions.
3. For a triggered scan, `dashboard/scan_runner.py` inserts a running scan row and launches the orchestrator.
4. The orchestrator:
   - validates scan identity and target
   - prepares workspace and report directories
   - selects compatible scanners
   - runs scanners
   - normalizes findings
   - evaluates policies
   - stores reports and final scan state
5. The dashboard surfaces those results through scans, findings, analytics, compare, exports, notifications, webhooks, and metrics.

### Main components

- `dashboard/app.py`
  The FastAPI entrypoint, middleware, router wiring, SPA pages, KPI endpoints, and metrics endpoint.
- `dashboard/rbac.py`
  Role model, API key lifecycle, user credential verification, audit logging.
- `dashboard/pagination.py`
  Cursor-style pagination for scans and findings.
- `dashboard/finding_management.py`
  Triage state, assignment, comments, false positives, risk acceptance, and bulk updates.
- `dashboard/analytics.py`
  Risk distribution, compliance summary, trends, target ranking, and tool effectiveness.
- `dashboard/webhooks.py`
  Webhook registration, validation, signing, retries, and delivery logging.
- `dashboard/notifications.py`
  Email alerting and notification preferences.
- `dashboard/runtime_config.py`
  Resolves `DASHBOARD_DB_PATH` for container and local development execution.
- `orchestrator/main.py`
  Main orchestration pipeline, scan preparation, execution, persistence, and policy flow.
- `orchestrator/scanners.py`
  Scanner wrappers, subprocess controls, SSRF checks, and scanner-specific execution rules.
- `orchestrator/normalizer.py`
  Normalization layer from raw tool output to shared finding objects.
- `orchestrator/policy_engine.py`
  Policy matching, exemptions, and blocking evaluation.
- `common/schema.py`
  Shared schema and migrations source of truth.

### Data stores and artifacts

- SQLite by default
- PostgreSQL optionally via `DATABASE_URL`
- reports directory for raw and normalized scan output
- workspaces directory for prepared scan inputs
- Trivy cache directory and scanner cache state

### Architecture docs

The maintained architecture references are:
- [docs/architecture.md](docs/architecture.md)
- [docs/architecture.mmd](docs/architecture.mmd)

---

## Repository structure

```text
.
├── .github/workflows/          # CI, docker build, security-scan workflow
├── common/schema.py            # Shared schema + migrations
├── config/                     # Scanner settings, policies, batch targets
├── dashboard/
│   ├── app.py
│   ├── runtime_config.py
│   ├── analytics.py
│   ├── pagination.py
│   ├── finding_management.py
│   ├── notifications.py
│   ├── webhooks.py
│   ├── scan_runner.py
│   ├── static/
│   ├── templates/
│   └── tests/
├── docker/
│   ├── scanner-tools.Dockerfile
│   └── semgrep-wrapper.sh
├── orchestrator/
│   ├── main.py
│   ├── scanners.py
│   ├── normalizer.py
│   ├── compatibility.py
│   ├── cache.py
│   ├── db_adapter.py
│   └── tests/
├── scripts/
│   ├── browser_smoke.mjs
│   ├── ops.sh
│   ├── seed_dev_data.py
│   ├── run_scan.sh
│   └── schedule_scan.sh
├── docs/
│   ├── architecture.md
│   ├── architecture.mmd
│   ├── api-reference.md
│   ├── deployment.md
│   ├── operations.md
│   ├── security-model.md
│   ├── gitlab-integration.md
│   ├── ui-operations-guide.md
│   ├── development-and-verification.md
│   └── ui-audit-matrix.md
└── docker-compose*.yml
```

---

## Quick start

### Docker Compose

```bash
git clone https://github.com/3n1gm496/security-scanning-platform.git
cd security-scanning-platform

cp .env.example .env
mkdir -p data/{reports,workspaces,cache/trivy,backups}
docker compose build
docker compose up -d
```

Default dashboard URL:
- `http://localhost:8080`

Before production-like use, set at least:
- `DASHBOARD_PASSWORD`
- `DASHBOARD_SESSION_SECRET`
- `DASHBOARD_HTTPS_ONLY=1` when behind TLS

Health checks:

```bash
curl -fsS http://localhost:8080/api/health
curl -fsS http://localhost:8080/api/ready
curl -fsS http://localhost:8080/metrics
```

### Database path behavior

The dashboard does not rely only on a hardcoded path anymore.

Resolution order:
1. explicit `DASHBOARD_DB_PATH`
2. `/data/security_scans.db` in container or when writable
3. repo-local `data/security_scans.db` when writable
4. XDG state path
5. temp fallback

Implementation:
- `dashboard/runtime_config.py`

---

## Configuration

Main environment variables:

```bash
# Auth
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=change-me-now
DASHBOARD_SESSION_SECRET=replace-with-a-random-secret
DASHBOARD_HTTPS_ONLY=0

# Storage
ORCH_DB_PATH=/data/security_scans.db
REPORTS_DIR=/data/reports
WORKSPACE_DIR=/data/workspaces
TRIVY_CACHE_DIR=/data/cache/trivy

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Optional CSP relaxation
DASHBOARD_CSP_ALLOW_UNSAFE_EVAL=0

# Optional PostgreSQL
# DATABASE_URL=postgresql://security:change-me-postgres@postgres:5432/security_scans
```

Important configuration files:
- `config/settings.yaml`
- `config/policies.yaml`
- `config/targets.yaml`

Important caveat:
- the application now fails fast on insecure runtime auth defaults
- Compose still contains some fallback values, so real deployments must provide a proper `.env`

---

## API surface

Main API groups:
- auth
- scans
- findings
- analytics and charts
- exports
- API keys
- webhooks
- notifications
- audit
- monitoring

Examples:

```bash
# Trigger a scan
curl -X POST http://localhost:8080/api/scan/trigger \
  -H "Authorization: Bearer $API_KEY" \
  -d "target_type=git" \
  -d "target=https://github.com/org/repo.git" \
  -d "name=my-repo" \
  -d "async_mode=true"

# Paginated findings
curl "http://localhost:8080/api/findings/paginated?per_page=20&severity=CRITICAL&status=new"

# Compare two scans
curl "http://localhost:8080/api/scans/compare?scan_id_1=<scan_a>&scan_id_2=<scan_b>"

# SSE stream
curl "http://localhost:8080/api/scans/events"
```

Full reference:
- [docs/api-reference.md](docs/api-reference.md)

---

## Operator UI

The UI is only one layer of the product, but it is now verified as part of normal engineering workflow.

Main pages:
- dashboard
- scans
- findings
- analytics
- compare
- settings

Current UI verification:
- browser smoke screenshots in `artifacts/browser-smoke/`
- light and dark theme coverage
- mobile navigation coverage

Reference:
- [docs/ui-operations-guide.md](docs/ui-operations-guide.md)

---

## CI and Docker build strategy

GitHub Actions currently runs:
- dashboard tests on Python `3.11` and `3.12`
- orchestrator tests on Python `3.11` and `3.12`
- Bandit
- `pip-audit`
- Docker image builds
- Trivy image scans
- reusable `Security Scan` workflow

Current `Security Scan` behavior:
- remote scan when `SECURITY_SCANNER_URL` and `SECURITY_SCANNER_API_KEY` exist
- local Gitleaks fallback otherwise

Docker security/build notes:
- `trivy` is compiled from source in the image build with the required patched dependency version
- `gitleaks` is compiled from source with a patched Go toolchain
- `docker/scanner-tools.Dockerfile` is used to prime and reuse scanner-tool cache in CI

---

## Operations

Useful commands:

```bash
./scripts/ops.sh up
./scripts/ops.sh down
./scripts/ops.sh health
./scripts/ops.sh scan demo
./scripts/ops.sh backup
./scripts/ops.sh retention --days 30
./scripts/ops.sh api-key list
```

Runbooks:
- [docs/operations.md](docs/operations.md)
- [docs/deployment.md](docs/deployment.md)
- [docs/security-model.md](docs/security-model.md)
- [docs/gitlab-integration.md](docs/gitlab-integration.md)

---

## Development and verification

Core checks:

```bash
pytest -q
node --check dashboard/static/app.js
node scripts/browser_smoke.mjs
```

The browser smoke:
- seeds a runtime DB
- boots the dashboard
- exercises login, navigation, compare, settings, modals, theme toggle, and mobile nav
- writes screenshots to `artifacts/browser-smoke/`

Engineering checklist:
- [docs/development-and-verification.md](docs/development-and-verification.md)

---

## Documentation index

- [docs/architecture.md](docs/architecture.md)
- [docs/api-reference.md](docs/api-reference.md)
- [docs/deployment.md](docs/deployment.md)
- [docs/operations.md](docs/operations.md)
- [docs/security-model.md](docs/security-model.md)
- [docs/gitlab-integration.md](docs/gitlab-integration.md)
- [docs/ui-operations-guide.md](docs/ui-operations-guide.md)
- [docs/development-and-verification.md](docs/development-and-verification.md)
- [docs/ui-audit-matrix.md](docs/ui-audit-matrix.md)
- [CHANGELOG.md](CHANGELOG.md)

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
