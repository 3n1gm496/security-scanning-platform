# Security Scanning Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135+-009688.svg)](https://fastapi.tiangolo.com)
[![CI](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml)

Centralized security scanning platform for heterogeneous environments: multi-tool orchestration, normalized findings, policy blocking, and a dark-first SOC-style command center for triage, analytics, compare, reporting, and operational controls.

Current repository baseline:
- `607` Python tests green
- browser smoke with screenshots across login, dashboard, scans, findings, analytics, compare, settings, modals, light theme, and mobile nav
- Docker images scanned in CI with Trivy
- reusable remote or local-fallback security scan workflow

**Repository:** [github.com/3n1gm496/security-scanning-platform](https://github.com/3n1gm496/security-scanning-platform)

---

## Highlights

### Core platform
- CI-agnostic orchestration for Git, local, URL, and image targets
- Unified normalization pipeline across Semgrep, Bandit, Checkov, Gitleaks, Trivy, Grype, Syft, Nuclei, and OWASP ZAP
- Policy-based blocking with persistent scan history
- SQLite by default, PostgreSQL optional
- Structured logging, watchdog timeout handling, and bounded queue/thread controls

### SOC command center
- Dark-first dashboard with light mode toggle
- Dashboard, scans, findings, analytics, compare, and settings in a single SPA
- Stabilized live refresh with soft-live updates instead of disruptive full-page reloads
- Findings triage, scan comparison, exports, notifications, API key management, webhooks, and analytics intelligence board
- Browser smoke flow that captures screenshots into `artifacts/browser-smoke/`

### Security and operations
- Form login plus RBAC API keys (`admin`, `operator`, `viewer`)
- CSRF protection, security headers, session hardening, and rate limiting
- Webhook SSRF controls and HMAC signing
- Trivy and Gitleaks built with patched toolchains in Docker builds
- CI support for remote security scan when secrets are configured and local Gitleaks fallback when they are not

---

## Supported scanners

| Scanner | Category | Targets | Notes |
|---|---|---|---|
| Semgrep | SAST | `git`, `local` | Community or custom rules |
| Bandit | Python SAST | `git`, `local` | Python-focused |
| Checkov | IaC | `git`, `local` | Terraform, Kubernetes, cloud IaC |
| Gitleaks | Secrets | `git`, `local` | Full git history when available |
| Trivy FS | SCA / vuln / config | `git`, `local` | File-system mode |
| Trivy Image | Image scanning | `image` | Registry or local image |
| Grype | SBOM vuln | `git`, `local`, `image` | Pairs well with Syft |
| Syft | SBOM generation | `git`, `local`, `image` | SPDX/CycloneDX style data |
| Nuclei | Pattern / CVE | `git`, `local`, `url` | URL targets supported |
| OWASP ZAP | DAST | `url` | Optional, internal service in Compose |

Compatibility is resolved centrally in `orchestrator/compatibility.py`, so incompatible scanners are skipped rather than misrouted.

---

## Architecture

![Platform Architecture Diagram](docs/architecture.png)

At a high level:
- the **dashboard service** owns the FastAPI API surface, SPA delivery, auth, analytics, exports, notifications, webhooks, monitoring, and scan-trigger flow
- the **orchestrator** prepares targets, routes compatible scanners, normalizes results, applies policy, and persists reports
- the **database layer** stores scans, findings, triage state, audit data, keys, notification preferences, and webhook metadata
- the **frontend** is a command-center SPA on top of those APIs, with restrained live refresh and chart lifecycle controls

Repository layout, trimmed to the parts that matter most today:

```text
.
├── .github/workflows/          # CI, docker build, security-scan workflow
├── common/schema.py            # DB schema + migrations
├── config/                     # settings, policies, targets
├── dashboard/
│   ├── app.py                  # FastAPI app
│   ├── runtime_config.py       # DASHBOARD_DB_PATH resolution
│   ├── pagination.py           # cursor-style scans/findings pagination
│   ├── notifications.py        # email notifications
│   ├── webhooks.py             # webhook delivery + signing
│   ├── static/                 # app.js, app.css, login.css, fonts
│   ├── templates/              # app.html, login.html
│   └── tests/
├── docker/
│   ├── scanner-tools.Dockerfile
│   └── semgrep-wrapper.sh
├── orchestrator/
│   ├── main.py
│   ├── scanners.py
│   ├── normalizer.py
│   └── tests/
├── scripts/
│   ├── browser_smoke.mjs
│   ├── ops.sh
│   ├── run_scan.sh
│   ├── seed_dev_data.py
│   └── schedule_scan.sh
├── docs/
│   ├── architecture.mmd
│   ├── architecture.md
│   ├── api-reference.md
│   ├── deployment.md
│   ├── development-and-verification.md
│   ├── gitlab-integration.md
│   ├── operations.md
│   ├── security-model.md
│   ├── ui-audit-matrix.md
│   └── ui-operations-guide.md
└── docker-compose*.yml
```

Deep references:
- [docs/architecture.md](docs/architecture.md)
- [docs/api-reference.md](docs/api-reference.md)
- [docs/deployment.md](docs/deployment.md)
- [docs/operations.md](docs/operations.md)
- [docs/security-model.md](docs/security-model.md)

---

## Quick start

### Docker-first path

```bash
git clone https://github.com/3n1gm496/security-scanning-platform.git
cd security-scanning-platform

cp .env.example .env
mkdir -p data/{reports,workspaces,cache/trivy,backups}
```

Edit `.env` before first boot:
- set a real `DASHBOARD_PASSWORD`
- set a strong random `DASHBOARD_SESSION_SECRET`
- enable `DASHBOARD_HTTPS_ONLY=1` when serving behind TLS
- configure SMTP only if you need email notifications
- enable PostgreSQL only if you actually want it

Then build and start:

```bash
docker compose build
docker compose up -d
```

Default URL:
- dashboard: `http://localhost:8080`

Useful checks:

```bash
docker compose ps
curl -fsS http://localhost:8080/api/health
curl -fsS http://localhost:8080/api/ready
```

### Local dashboard database path behavior

The dashboard now resolves `DASHBOARD_DB_PATH` more intelligently:
- explicit `DASHBOARD_DB_PATH` wins
- in containers it uses `/data/security_scans.db`
- outside containers it prefers a writable repo-local `data/security_scans.db`
- if needed it falls back to XDG state or a temp directory

This logic lives in `dashboard/runtime_config.py`.

---

## Configuration overview

Key environment variables:

```bash
# Auth
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=change-me-now
DASHBOARD_SESSION_SECRET=replace-with-a-random-secret
DASHBOARD_HTTPS_ONLY=0

# Runtime paths
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

Notes:
- the application fails fast if insecure auth defaults are left in place at runtime
- `DASHBOARD_CSP_ALLOW_UNSAFE_EVAL` is `0` by default in Compose; enable it explicitly only if your deployment mode requires it
- `docker-compose.yml` still contains fallback values for some envs, so production should always supply a real `.env`

Main config files:
- `config/settings.yaml`
- `config/policies.yaml`
- `config/targets.yaml`

---

## UI and operator workflows

### Dashboard
- posture overview, critical pressure, severity chart, trend chart, remediation chart, recent scans watchlist
- stabilized live refresh that updates state without thrashing the whole page

### Scans
- queue/workspace view with soft-live updates
- compare entry flow and scan detail modal

### Findings
- triage workspace with filters, bulk actions, exports, and detail modal
- status-aware remediation workflow

### Analytics
- risk distribution, OWASP map, trend intelligence, tool effectiveness, target risk ranking
- restrained chart motion for user-driven changes and near-silent background refreshes

### Compare
- baseline vs comparison workflow with new/resolved/unchanged summaries

### Settings
- API keys
- webhooks
- notification preferences

### Theme and QA
- dark mode is the primary visual mode
- light mode remains supported and smoke-tested
- browser screenshots are written to `artifacts/browser-smoke/`

For a page-by-page guide, see [docs/ui-operations-guide.md](docs/ui-operations-guide.md).

---

## Common API flows

Authentication:
- session login via `POST /login`
- API key via `Authorization: Bearer ssp_<...>`

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

# Scan comparison
curl "http://localhost:8080/api/scans/<scan_a>/compare?other_scan_id=<scan_b>"

# Export findings
curl "http://localhost:8080/api/export/findings?format=csv&limit=5000" -o findings.csv

# Analytics
curl "http://localhost:8080/api/analytics/risk-distribution"
curl "http://localhost:8080/api/analytics/trends?days=30"
```

Health and monitoring:

```bash
curl http://localhost:8080/api/health
curl http://localhost:8080/api/ready
curl http://localhost:8080/metrics
```

---

## CI, security scan workflow, and Docker builds

### GitHub Actions CI

The main CI workflow runs:
- orchestrator tests on Python `3.11` and `3.12`
- dashboard tests on Python `3.11` and `3.12`
- Bandit and `pip-audit`
- Docker image builds
- Trivy image scans
- reusable `Security Scan` workflow

### Security Scan workflow

`.github/workflows/security-scan.yml` behaves as follows:
- if `SECURITY_SCANNER_URL` and `SECURITY_SCANNER_API_KEY` are present, it triggers a remote scan through the platform API
- if they are absent, it runs a local Gitleaks fallback and still publishes `scan-results.json`

That means a green run can represent either:
- remote platform scan, or
- local fallback scan

### Docker scanner toolchain

The project builds patched scanner binaries in Docker:
- `gitleaks` from source with patched Go
- `trivy` from source with the fixed `docker/cli` dependency

`docker/scanner-tools.Dockerfile` exists to prime and reuse scanner-tool cache in CI. The application images continue to validate the installed toolchain during build.

---

## Development and verification

### Local Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r dashboard/requirements-test.txt
pip install -r orchestrator/requirements-test.txt
```

### Core checks

```bash
pytest -q
node --check dashboard/static/app.js
node scripts/browser_smoke.mjs
```

### Browser smoke

The smoke script:
- seeds a runtime database
- boots the dashboard on a temporary port
- exercises login, dashboard, scans, findings, analytics, compare, settings, modals, light theme, and mobile nav
- stores screenshots in `artifacts/browser-smoke/`

### CLI helpers

```bash
./scripts/ops.sh up
./scripts/ops.sh down
./scripts/ops.sh health
./scripts/ops.sh scan demo
./scripts/ops.sh test
./scripts/ops.sh lint
./scripts/ops.sh api-key list
```

For the full engineering checklist, see [docs/development-and-verification.md](docs/development-and-verification.md).

---

## Hardening notes

- supply real credentials and secrets through `.env`
- prefer HTTPS with `DASHBOARD_HTTPS_ONLY=1`
- expose the dashboard only through trusted interfaces or a reverse proxy
- use least-privilege API keys
- keep webhook targets public and expected; SSRF controls are enforced
- review `config/policies.yaml` before treating the platform as a blocking gate

Accepted but still present by choice:
- some Compose fallback values remain in `docker-compose.yml`

---

## Documentation index

- [docs/architecture.md](docs/architecture.md)
- [docs/api-reference.md](docs/api-reference.md)
- [docs/deployment.md](docs/deployment.md)
- [docs/operations.md](docs/operations.md)
- [docs/security-model.md](docs/security-model.md)
- [docs/ui-operations-guide.md](docs/ui-operations-guide.md)
- [docs/development-and-verification.md](docs/development-and-verification.md)
- [docs/ui-audit-matrix.md](docs/ui-audit-matrix.md)
- [docs/gitlab-integration.md](docs/gitlab-integration.md)
- [CHANGELOG.md](CHANGELOG.md)
- [IMPROVEMENTS.md](IMPROVEMENTS.md)

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
