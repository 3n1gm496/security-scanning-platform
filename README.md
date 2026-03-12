# Centralized Security Scanning Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135+-009688.svg)](https://fastapi.tiangolo.com)
[![CI](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml)

Open-source, Linux-based, CI-agnostic platform for centralized security scanning in heterogeneous enterprise environments. Automated orchestration of 10+ OSS scanners with unified dashboard, result normalization, and **436 unit and integration tests**.

🔗 **Repository:** [github.com/3n1gm496/security-scanning-platform](https://github.com/3n1gm496/security-scanning-platform)

---

## 📋 Table of Contents

- [Goal](#-goal)
- [Features](#-features)
- [Supported Scanners](#-supported-scanners)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Deployment](#-deployment)
- [Hardening](#-hardening)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Goal

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

Centralized collection in **SQLite + JSON** with a unified **FastAPI dashboard**.

---

## ✨ Features

- **🔄 CI-Agnostic** — Integrates with GitLab, Jenkins, Azure DevOps, GitHub Actions, or cron/systemd
- **🐳 Containerized** — Rapid deployment with Docker Compose on any Linux server
- **📊 Centralized Dashboard** — REST API + web UI to view scans, findings, and trends, with cursor-based pagination and status filters
- **✅ High Test Coverage** — 436 total tests, with **coverage >86%** for the orchestrator module
- **🔍 10+ OSS Scanners** — Semgrep, Bandit, Nuclei, Trivy, Grype, Gitleaks, Checkov, ZAP, Syft, and more
- **📝 Intelligent Normalization** — Unified output in a standard format for all scanners
- **🎯 Policy-based Blocking** — Automatic pipeline blocking on critical findings
- **💾 SQLite Backend** — Simple data persistence, easy backups, zero external dependencies
- **🔐 Authentication** — Form-based login with secure sessions; bcrypt password hashing; `HttpOnly`/`Secure` cookies
- **🛡️ Security Headers** — `Content-Security-Policy`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`
- **⚡ Rate Limiting** — Brute-force protection on `/login` (10 req/min) and API (180 req/min) with sliding window
- **🔒 Path Traversal Protection** — Input validation and sanitization on all scan endpoints
- **🚀 Batch Scanning** — Multi-target scanning from YAML files
- **📈 Trending and History** — Historical finding tracking for time-based analysis
- **📧 Email Notifications** — Critical alerts and granular per-user notification preferences (email, preferred channel, weekly/daily digests)
- **📡 Prometheus Metrics** — `/metrics` endpoint for observability and monitoring
- **🔁 GitLab Enterprise CI** — Complete `.gitlab-ci.yml` pipeline (lint → test → SAST → build → scan-self → deploy)
- **🌙 Dark Mode** — Light/dark theme with `localStorage` persistence; automatic chart update on theme change
- **♿ Accessibility** — ARIA attributes (`role`, `aria-label`, `aria-current`), `prefers-reduced-motion` support, keyboard navigation (Escape to close modals)
- **📡 Real-Time Scan Monitoring** — Automatic polling every 5s after launching a scan; status banner on the dashboard; KPI update on completion

---

## 🔎 Supported Scanners

| Scanner | Type | Languages/Targets | Output |
|---------|------|-------------------|--------|
| **Semgrep** | SAST | Multi-language | SARIF / JSON |
| **Bandit** | SAST | Python | JSON |
| **Nuclei** | Pattern/CVE | Web/Network | JSON |
| **Trivy** | Container/SCA | Images, Repos | JSON |
| **Grype** | SBOM Vuln | SBOM files | JSON |
| **Gitleaks** | Secrets | Git repos | JSON |
| **Checkov** | IaC | Terraform, K8s, Docker | JSON |
| **Syft** | SBOM Gen | Multiple | JSON |
| **OWASP ZAP** | DAST | Web apps | JSON |

---

## 🏗️ Architecture

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
│   ├── app.py               # Main FastAPI application
│   ├── db.py                # Centralized DB connection
│   ├── requirements.in      # Source dependencies (pip-tools)
│   ├── requirements.txt     # Pinned dependencies (generated)
│   ├── Dockerfile
│   ├── static/
│   ├── templates/
│   └── tests/               # ~194 tests for the dashboard
├── orchestrator/
│   ├── main.py
│   ├── requirements.in      # Source dependencies (pip-tools)
│   ├── requirements.txt     # Pinned dependencies (generated)
│   └── tests/               # ~242 tests for the orchestrator
├── scripts/
│   ├── ops.sh               # Unified CLI for all operations
│   ├── run_scan.sh
│   └── schedule_scan.sh
├── systemd/                 # systemd services and timers
├── CHANGELOG.md
├── docker-compose.yml
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

## 🚀 Quick Start

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

### Demo Test

```bash
./scripts/init_demo.sh
```

---

## ⚙️ Configuration

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
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=changeme
SECRET_KEY=your-secret-key-here

# Database
DATABASE_PATH=/data/security_scans.db

# Orchestrator
LOG_LEVEL=INFO

# Email notifications (optional)
SMTP_SERVER=localhost
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=security@example.com
EMAIL_FROM_NAME=Security Scanner
```

---

## 💻 Usage

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

### REST API

#### Query Scanning Results

```bash
# List all scans
curl http://localhost:8080/api/scans

# Specific scan details
curl http://localhost:8080/api/scans/{scan_id}

# Findings for a scan
curl http://localhost:8080/api/scans/{scan_id}/findings
```

#### Trigger Scans

Endpoint for triggering scans via API or the dashboard UI (requires authentication and `SCAN_WRITE` permission). The `async_mode=true` parameter (default from UI) returns immediately with a scan ID, while the scan continues in the background.

```bash
# Asynchronous (recommended) — returns immediately, scan continues in background
curl -X POST http://localhost:8080/api/scan/trigger \
     -H "Authorization: Bearer <your_api_key>" \
     -d "target_type=local&target=/path/to/scan&name=my-local-scan&async_mode=true"

# Synchronous — waits for completion before responding (not recommended for long scans)
curl -X POST http://localhost:8080/api/scan/trigger \
     -H "Authorization: Bearer <your_api_key>" \
     -d "target_type=git&target=https://github.com/pallets/flask.git&name=flask-repo&async_mode=false"
```

---

## 🚀 Deployment

### Docker Compose (Recommended)

The recommended method is to use the provided `docker-compose.yml`. Configure variables in `.env` and start with:

```bash
docker compose up -d
```

### Systemd

For production environments, systemd services and timers are provided to manage the stack and scheduled scans. Copy the files from `systemd/` to `/etc/systemd/system/` and enable them.

---

## 🛡️ Hardening

- **Credentials**: Do not use default credentials. Generate a strong `SECRET_KEY`.
- **Network**: Only expose port `8080` on trusted network interfaces.
- **Docker Socket**: If mounting the Docker socket, apply security best practices to protect it.
- **HTTPS**: Use a reverse proxy (e.g. Nginx, Caddy) to terminate TLS and add additional security headers.

---

## 🛠️ Development

### Environment Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies (dashboard + orchestrator + test)
pip install -r dashboard/requirements.txt -r dashboard/requirements-test.txt
pip install -r orchestrator/requirements.txt -r orchestrator/requirements-test.txt
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
# Run all 436 tests
./scripts/ops.sh test

# Run only dashboard tests
./scripts/ops.sh test dashboard

# Run only orchestrator tests with coverage
./scripts/ops.sh test orchestrator --coverage
```

---

## 🤝 Contributing

Contributions are welcome! Please open an issue to discuss proposed changes, or a Pull Request with a clear description of your modifications.

## 📜 License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.
