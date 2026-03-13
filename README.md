# Centralized Security Scanning Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135+-009688.svg)](https://fastapi.tiangolo.com)
[![CI](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml)

Open-source, Linux-based, CI-agnostic platform for centralized security scanning in heterogeneous enterprise environments. Automated orchestration of 10+ OSS scanners with unified dashboard, result normalization, and **468 unit and integration tests**.

**Repository:** [github.com/3n1gm496/security-scanning-platform](https://github.com/3n1gm496/security-scanning-platform)

---

## Table of Contents

- [Goal](#-goal)
- [Features](#-features)
- [Supported Scanners](#-supported-scanners)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [REST API](#-rest-api)
- [Deployment](#-deployment)
- [GitLab Enterprise Integration](#-gitlab-enterprise-integration)
- [Hardening](#-hardening)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## Goal

A centralized, repeatable, and pragmatic platform to run:

- **SAST** with **Semgrep** (repository analysis)
- **Python-specific SAST** with **Bandit**
- **Pattern-based discovery** with **Nuclei**
- **SBOM-based vulnerability scanning** with **Grype**
- **SCA / dependency scanning** with **Trivy**
- **Secret scanning** with **Gitleaks**
- **Container image scanning** with **Trivy**
- **IaC scanning** with **Checkov**
- **SBOM generation** with **Syft**
- **DAST** (optional) with **OWASP ZAP**

Centralized collection in **SQLite** (default) or **PostgreSQL** with a unified **FastAPI dashboard**.

---

## Features

### Core
- **CI-Agnostic** — Integrates with GitLab, Jenkins, Azure DevOps, GitHub Actions, or cron/systemd
- **Containerized** — Rapid deployment with Docker Compose on any Linux server
- **10+ OSS Scanners** — Semgrep, Bandit, Nuclei, Trivy, Grype, Gitleaks, Checkov, ZAP, Syft
- **Intelligent Normalization** — Unified output in a standard format for all scanners
- **Policy-based Blocking** — Automatic pipeline blocking on critical findings
- **Batch Scanning** — Multi-target scanning from YAML files

### Dashboard & UI
- **Centralized Dashboard** — REST API + Vue.js 3 SPA to view scans, findings, and trends
- **Cursor-based Pagination** — Bidirectional pagination with total counts, severity/tool/status filters
- **Finding Triage** — Status management (new, acknowledged, in progress, resolved, false positive, risk accepted)
- **Export** — Findings export in CSV, JSON, SARIF, HTML, and PDF formats; streaming CSV for large datasets
- **Analytics** — Risk distribution, compliance summary, trend analysis, tool effectiveness, target risk scoring
- **Scan Comparison** — Side-by-side comparison of findings between scans
- **Dark Mode** — Light/dark theme with `localStorage` persistence; automatic chart update on theme change
- **Real-Time Scan Monitoring** — Automatic polling every 5s after launching a scan; status banner on the dashboard
- **Accessibility** — ARIA attributes, `prefers-reduced-motion` support, keyboard navigation, `<noscript>` fallback

### Security & Auth
- **Authentication** — Form-based login with secure sessions; bcrypt password hashing; `HttpOnly`/`Secure` cookies
- **API Key Auth** — RBAC-based API keys (`ssp_` prefix) with admin/operator/viewer roles
- **Security Headers** — `Content-Security-Policy`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`, `Referrer-Policy`
- **Rate Limiting** — Brute-force protection on `/login` (10 req/min) and API (180 req/min) with sliding window
- **Path Traversal Protection** — Input validation and sanitization on all scan endpoints
- **SSRF Protection** — Webhook URL validation with DNS-rebinding mitigation (blocked: RFC 1918, loopback, link-local, AWS IMDS)
- **Subresource Integrity** — SRI hashes on CDN scripts (Vue.js, Chart.js)

### Operations
- **SQLite or PostgreSQL** — SQLite by default; optional PostgreSQL via Docker Compose profile
- **Email Notifications** — Critical alerts and granular per-user notification preferences
- **Webhooks** — Event-driven notifications with HMAC signatures, retry logic, and circuit breaker auto-disable
- **Prometheus Metrics** — `/metrics` endpoint for observability and monitoring
- **Audit Log** — API key operations and triage actions logged with CSV/JSON export
- **High Test Coverage** — 468 total tests (273 dashboard + 195 orchestrator) across Python 3.11 and 3.12

---

## Supported Scanners

| Scanner | Type | Compatible Target Types | Output |
|---------|------|------------------------|--------|
| **Semgrep** | SAST | `git`, `local` | SARIF / JSON |
| **Bandit** | SAST | `git`, `local` | JSON |
| **Checkov** | IaC | `git`, `local` | JSON |
| **Gitleaks** | Secrets | `git`, `local` | JSON |
| **Trivy** | Container/SCA | `git`, `local` (fs mode) · `image` (image mode) | JSON |
| **Grype** | SBOM Vuln | `git`, `local`, `image` | JSON |
| **Syft** | SBOM Gen | `git`, `local`, `image` | JSON |
| **Nuclei** | Pattern/CVE | `git`, `local`, `url` | JSON |
| **OWASP ZAP** | DAST | `url` | JSON |

> **Compatibility matrix** — The orchestrator uses a centralized compatibility matrix
> (`orchestrator/compatibility.py`) as the single source of truth for scanner–target routing.
> Scanners not compatible with the requested target type are automatically skipped;
> scanners whose binary is missing at runtime are also skipped (preflight check) and
> reported in the per-tool execution results visible in the scan detail modal.
>
> **URL target type** — Pass `target_type=url` with a `target` value of `https://…` to
> run DAST tools (Nuclei, OWASP ZAP) against a live web endpoint without cloning any repository.

---

## Architecture

![Platform Architecture Diagram](docs/architecture.png)

### Repository Structure

```text
.
├── .github/workflows/       # GitHub Actions CI (test, lint, SAST, docker build)
├── .gitlab-ci.yml           # GitLab Enterprise CI/CD pipeline
├── config/
│   ├── settings.yaml        # Scanner and policy configuration
│   ├── policies.yaml        # Pipeline blocking policies
│   └── targets.yaml         # Batch scan targets
├── dashboard/
│   ├── app.py               # Main FastAPI application (1500+ lines)
│   ├── db.py                # Centralized DB connection (SQLite + PostgreSQL)
│   ├── rbac.py              # Role-based access control & API keys
│   ├── webhooks.py          # Webhook system with SSRF protection
│   ├── finding_management.py # Finding triage & status management
│   ├── pagination.py        # Cursor-based bidirectional pagination
│   ├── remediation.py       # Remediation engine
│   ├── analytics.py         # Risk scoring, compliance, trends
│   ├── static/              # Vue.js 3 SPA (app.js, app.css, login.css)
│   ├── templates/           # Jinja2 templates (app.html, login.html)
│   ├── Dockerfile
│   └── tests/               # 273 tests
├── orchestrator/
│   ├── main.py              # Scan orchestration & scheduling
│   ├── scanners.py          # Scanner wrappers (9 scanners)
│   ├── normalizers.py       # Result normalization
│   ├── Dockerfile
│   └── tests/               # 195 tests
├── scripts/
│   ├── ops.sh               # Unified CLI for all operations
│   ├── run_scan.sh
│   └── schedule_scan.sh
├── systemd/                 # systemd services and timers
├── docker-compose.yml       # Production stack
├── docker-compose.dev.yml   # Development override (hot-reload)
├── docker-compose.ci.yml    # CI sandbox override
├── CHANGELOG.md
├── IMPROVEMENTS.md          # Detailed feature documentation (phases 0–3)
└── .env.example
```

## Linux Prerequisites

- Docker Engine + Docker Compose plugin
- Outbound Internet access for:
  - downloading images / scanners at build time
  - Trivy database updates
  - fetching Semgrep community rules when using `p/default`
- Optional: access to container registries and remote Git repositories
- Optional: host Docker socket mount if you want to scan local images

---

## Quick Start

### Rapid Installation

```bash
# Clone repository
git clone https://github.com/3n1gm496/security-scanning-platform.git
cd security-scanning-platform

# Setup environment
cp .env.example .env
mkdir -p data/{reports,workspaces,cache/trivy,backups}

# Build and start
docker compose build
docker compose up -d
```

**Dashboard:** `http://localhost:8080`
**Credentials:** Defined in `.env` (configurable defaults)

### With PostgreSQL

```bash
# Uncomment DATABASE_URL and POSTGRES_* variables in .env, then:
docker compose --profile postgres up -d
```

### Demo Test

```bash
./scripts/init_demo.sh
```

---

## Configuration

### Configuration Files

#### `config/settings.yaml`

```yaml
scanners:
  semgrep:
    enabled: true
    timeout: 600
  trivy:
    enabled: true
    timeout: 300
  gitleaks:
    enabled: true
    timeout: 180
  # ... other scanners

policies:
  block_on_critical: true
  block_on_high: false
  max_findings_warning: 50
```

#### `config/targets.yaml`

```yaml
targets:
  - name: my-app
    type: local
    path: /path/to/repo
    enabled: true

  - name: external-service
    type: git
    url: https://github.com/org/repo.git
    branch: main
    enabled: true

  - name: production-image
    type: image
    image: my-registry/my-app:latest
    enabled: true
```

#### `.env`

```bash
# Dashboard
DASHBOARD_PORT=8080
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=change-me-now
DASHBOARD_SESSION_SECRET=replace-with-a-random-secret

# Set to '1' when served over HTTPS (enables Secure cookie flag)
DASHBOARD_HTTPS_ONLY=0

# Database paths
ORCH_DB_PATH=/data/security_scans.db
REPORTS_DIR=/data/reports
WORKSPACE_DIR=/data/workspaces
TRIVY_CACHE_DIR=/data/cache/trivy

# Logging
LOG_LEVEL=INFO

# Email notifications (optional)
SMTP_SERVER=localhost
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=security@example.com
EMAIL_FROM_NAME=Security Scanner

# PostgreSQL (optional — uncomment to use instead of SQLite)
# DATABASE_URL=postgresql://security:change-me-postgres@localhost:5432/security_scans
# POSTGRES_DB=security_scans
# POSTGRES_USER=security
# POSTGRES_PASSWORD=change-me-postgres
# POSTGRES_PORT=5432

# Tuning (optional)
# ANALYTICS_CACHE_TTL_SECONDS=60
# WEBHOOK_TIMEOUT_SECONDS=10
# WEBHOOK_RETRY_COUNT=3
# WEBHOOK_CIRCUIT_BREAKER_THRESHOLD=5
```

---

## Usage

### CLI Operations (ops.sh)

Utility script for managing the stack, database, scans, and development operations:

```bash
# Stack
./scripts/ops.sh up                    # Start Docker Compose stack
./scripts/ops.sh down                  # Stop stack
./scripts/ops.sh health                # Health check (/, /health, /ready)
./scripts/ops.sh open                  # Open dashboard in browser

# Scan
./scripts/ops.sh scan demo             # Run demo scan
./scripts/ops.sh scan local --path $PWD --name my-app
./scripts/ops.sh scan git --url https://github.com/org/repo --name my-repo
./scripts/ops.sh scan image --image nginx:latest --name nginx

# Dev / CI (without Docker)
./scripts/ops.sh test                  # Run all tests (pytest)
./scripts/ops.sh test dashboard        # Dashboard tests only
./scripts/ops.sh lint                  # flake8 + black check
./scripts/ops.sh lint --fix            # Apply black
./scripts/ops.sh deps-compile          # Regenerate pinned requirements.txt

# API Keys
./scripts/ops.sh api-key create --name ci-runner --role operator
./scripts/ops.sh api-key list
./scripts/ops.sh api-key revoke --prefix abc123

# Maintenance
./scripts/ops.sh backup
./scripts/ops.sh retention --days 30
./scripts/ops.sh logs dashboard
```

---

## REST API

### Authentication

All `/api/*` endpoints require authentication. Use either:
- **Session-based** — `POST /login` with form data, then use session cookie
- **API key** — `Authorization: Bearer ssp_<key>` header

### Endpoints

#### Scans

```bash
# List all scans
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/api/scans

# Scan details
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/api/scans/{scan_id}

# Findings for a scan
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/api/scans/{scan_id}/findings

# Trigger async scan (recommended)
curl -X POST http://localhost:8080/api/scan/trigger \
     -H "Authorization: Bearer $API_KEY" \
     -d "target_type=git&target=https://github.com/org/repo.git&name=my-repo&async_mode=true"
```

#### Findings

```bash
# Paginated findings with filters
curl "$BASE/api/findings/paginated?per_page=20&severity=CRITICAL&tool=semgrep&status=new"

# Finding triage
curl -X PATCH "$BASE/api/findings/{id}/status" \
     -d "status_value=acknowledged&notes=Investigating"

# Status counts (aggregated)
curl "$BASE/api/findings/status-counts"
```

#### Export

```bash
# CSV export
curl "$BASE/api/export/findings?format=csv&limit=5000" -o findings.csv

# JSON export
curl "$BASE/api/export/findings?format=json&limit=5000" -o findings.json

# SARIF export
curl "$BASE/api/export/findings?format=sarif&limit=5000" -o findings.sarif

# Audit log export
curl "$BASE/api/audit/export?format=csv" -o audit.csv
```

#### Dashboard & Analytics

```bash
# KPIs
curl "$BASE/api/kpi"

# Severity distribution chart
curl "$BASE/api/chart/severity-distribution"

# Trends
curl "$BASE/api/trends"

# Analytics
curl "$BASE/api/analytics/risk-distribution"
curl "$BASE/api/analytics/compliance"
curl "$BASE/api/analytics/trends?days=30"
curl "$BASE/api/analytics/tool-effectiveness"
curl "$BASE/api/analytics/target-risk"
```

#### Webhooks & API Keys

```bash
# Webhooks
curl -X POST "$BASE/api/webhooks" -d "name=Slack&url=https://hooks.slack.com/xxx&events=scan.completed"
curl "$BASE/api/webhooks"
curl -X DELETE "$BASE/api/webhooks/{id}"

# API keys
curl -X POST "$BASE/api/keys" -d "name=ci-runner&role=operator"
curl "$BASE/api/keys"
curl -X DELETE "$BASE/api/keys/{prefix}"
```

#### Monitoring

```bash
curl "$BASE/api/health"    # Liveness
curl "$BASE/api/ready"     # Readiness (DB check)
curl "$BASE/metrics"       # Prometheus metrics
```

---

## Deployment

### Docker Compose (Recommended)

The recommended method is to use the provided `docker-compose.yml`. Configure variables in `.env` and start with:

```bash
docker compose up -d
```

Three compose files are provided:

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Production stack (dashboard + optional PostgreSQL) |
| `docker-compose.dev.yml` | Development override with hot-reload |
| `docker-compose.ci.yml` | CI sandbox override (no iptables required) |

### Systemd

For production environments, systemd services and timers are provided to manage the stack and scheduled scans. Copy the files from `systemd/` to `/etc/systemd/system/` and enable them.

---

## GitLab Enterprise Integration

The platform includes a complete `.gitlab-ci.yml` pipeline designed for GitLab Enterprise on-premises deployments. See below for a detailed integration guide.

### Pipeline Overview

```
lint → test → security → build → scan-self → deploy
```

| Stage | Jobs | Description |
|-------|------|-------------|
| `lint` | `lint:orchestrator`, `lint:dashboard` | flake8 + black formatting check |
| `test` | `test:orchestrator`, `test:dashboard` | pytest with coverage + JUnit reports |
| `security` | `sast:bandit` | Bandit SAST scan on both modules |
| `build` | `build:orchestrator`, `build:dashboard` | Docker build + push to GitLab Container Registry |
| `scan-self` | `scan-self` | Self-scan of the repository using the platform's own API |
| `deploy` | `deploy:staging`, `deploy:production` | SSH-based deployment (production requires manual approval) |

### Step-by-Step Integration for GitLab On-Premises

#### 1. Import the repository

```bash
# On your GitLab instance
git clone https://github.com/3n1gm496/security-scanning-platform.git
cd security-scanning-platform
git remote add gitlab https://gitlab.yourcompany.com/security/scanning-platform.git
git push gitlab main
```

#### 2. Configure CI/CD Variables

Go to **Settings > CI/CD > Variables** and add:

| Variable | Required | Protected | Description |
|----------|----------|-----------|-------------|
| `SECURITY_SCANNER_URL` | Yes | No | URL of the deployed platform, e.g. `https://scanner.yourcompany.com` |
| `SECURITY_SCANNER_API_KEY` | Yes | Yes | API key with `operator` role (`ssp_` prefix) |
| `DEPLOY_SSH_KEY` | For deploy | Yes | SSH private key for deployment to target servers |
| `DEPLOY_HOST` | For deploy | No | Target server hostname or IP |
| `DEPLOY_USER` | For deploy | No | SSH user (default: `deploy`) |
| `DEPLOY_PATH` | For deploy | No | Remote project path (default: `/opt/security-scanning-platform`) |

#### 3. Configure GitLab Runner

The pipeline requires a GitLab Runner with Docker executor (for test/lint jobs) and Docker-in-Docker support (for build jobs).

```toml
# /etc/gitlab-runner/config.toml
[[runners]]
  name = "security-scanner-runner"
  executor = "docker"
  [runners.docker]
    image = "python:3.11-slim"
    privileged = true                    # Required for Docker-in-Docker builds
    volumes = ["/cache", "/certs/client"]
    # For air-gapped environments, pull images through your internal registry:
    # allowed_images = ["python:*", "docker:*", "alpine:*"]
```

If your GitLab instance is **air-gapped** (no internet), pre-pull the required images into your internal registry:

```bash
# Required base images
docker pull python:3.11-slim
docker pull docker:27
docker pull docker:27-dind
docker pull alpine:3.19
docker pull postgres:16-alpine  # Only if using PostgreSQL

# Tag and push to your internal registry
for img in python:3.11-slim docker:27 docker:27-dind alpine:3.19; do
  docker tag "$img" registry.yourcompany.com/base/$img
  docker push registry.yourcompany.com/base/$img
done
```

Then update `.gitlab-ci.yml` to reference your internal registry:

```yaml
default:
  image: registry.yourcompany.com/base/python:3.11-slim
```

#### 4. Deploy the Platform on Your Server

```bash
# On the target server
ssh deploy@scanner.yourcompany.com

git clone https://gitlab.yourcompany.com/security/scanning-platform.git /opt/security-scanning-platform
cd /opt/security-scanning-platform

cp .env.example .env
# Edit .env with production values:
#   - Strong DASHBOARD_PASSWORD
#   - Random DASHBOARD_SESSION_SECRET (e.g. openssl rand -hex 32)
#   - DASHBOARD_HTTPS_ONLY=1 if behind TLS reverse proxy
#   - Configure SMTP for email notifications

mkdir -p data/{reports,workspaces,cache/trivy,backups}
docker compose build
docker compose up -d
```

#### 5. Create an API Key for CI

```bash
./scripts/ops.sh api-key create --name gitlab-ci --role operator
# Output: ssp_abc123...
# Copy this value to GitLab CI/CD variable SECURITY_SCANNER_API_KEY
```

#### 6. Configure Scheduled Pipelines (Optional)

For nightly full scans, go to **CI/CD > Schedules** and create:

| Field | Value |
|-------|-------|
| Description | Nightly security scan |
| Interval pattern | `0 2 * * *` (daily at 02:00 UTC) |
| Cron timezone | UTC |
| Target branch | `main` |

The `nightly:scan` job in `.gitlab-ci.yml` automatically triggers when `CI_PIPELINE_SOURCE == "schedule"`.

#### 7. GitLab Ultimate Integration (Optional)

If you have GitLab Ultimate, uncomment the SAST templates in `.gitlab-ci.yml` to enable GitLab's native security scanning alongside the platform:

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
```

#### 8. Network / Firewall Requirements

Ensure the following connectivity for on-premises deployment:

| Source | Destination | Port | Purpose |
|--------|------------|------|---------|
| GitLab Runner | Internal registry | 443/5000 | Pull base images, push built images |
| GitLab Runner | Platform server | 8080/443 | Self-scan API calls |
| Platform server | Git repositories | 443/22 | Clone targets for scanning |
| Platform server | Internet (optional) | 443 | Trivy DB updates, Semgrep rules |
| Users | Platform server | 8080/443 | Dashboard access |
| Deploy host | Platform server | 22 | SSH deployment |

#### 9. Reverse Proxy (Production)

For production, place the platform behind a TLS-terminating reverse proxy:

```nginx
# /etc/nginx/sites-available/scanner
server {
    listen 443 ssl http2;
    server_name scanner.yourcompany.com;

    ssl_certificate     /etc/ssl/certs/scanner.crt;
    ssl_certificate_key /etc/ssl/private/scanner.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `DASHBOARD_HTTPS_ONLY=1` in `.env` to enable `Secure` cookie flag.

---

## Hardening

- **Credentials**: Do not use default credentials. Generate a strong `SECRET_KEY` (`openssl rand -hex 32`).
- **Network**: Only expose port `8080` on trusted network interfaces.
- **Docker Socket**: If mounting the Docker socket, apply security best practices to protect it.
- **HTTPS**: Use a reverse proxy (e.g. Nginx, Caddy) to terminate TLS and add additional security headers.
- **Webhooks**: The platform blocks SSRF attempts (private IPs, loopback, link-local, AWS IMDS) and validates DNS resolution. Only public endpoints are allowed.
- **API Keys**: Use least-privilege roles (`viewer` for read-only, `operator` for scans, `admin` for full access). Revoke unused keys.

---

## Development

### Environment Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies (dashboard + orchestrator + test)
pip install -r dashboard/requirements.txt -r dashboard/requirements-test.txt
pip install -r orchestrator/requirements.txt -r orchestrator/requirements-test.txt
```

### Docker Compose for Development

```bash
# Start with hot-reload
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

### Dependency Management

The project uses `pip-tools` for pinning dependencies. To update or add packages:

1.  Edit the `.in` files (`dashboard/requirements.in`, `orchestrator/requirements.in`, etc.).
2.  Run the `ops.sh` script to recompile the `.txt` files:

```bash
./scripts/ops.sh deps-compile
```

### Running Tests

```bash
# Run all 468 tests
./scripts/ops.sh test

# Run only dashboard tests (273 tests)
./scripts/ops.sh test dashboard

# Run only orchestrator tests with coverage (195 tests)
./scripts/ops.sh test orchestrator --coverage
```

---

## Contributing

Contributions are welcome! Please open an issue to discuss proposed changes, or a Pull Request with a clear description of your modifications.

See [CHANGELOG.md](CHANGELOG.md) for version history and [IMPROVEMENTS.md](IMPROVEMENTS.md) for detailed feature documentation.

## License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.
