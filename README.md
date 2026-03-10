# Centralized Security Scanning Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135+-009688.svg)](https://fastapi.tiangolo.com)
[![CI](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/3n1gm496/security-scanning-platform/actions/workflows/ci.yml)

Piattaforma open source, Linux-based e CI-agnostic per security scanning centralizzato in ambienti enterprise eterogenei. Orchestrazione automatica di 10+ scanner OSS con dashboard unificata, normalizzazione dei risultati e **oltre 350 test di unità e integrazione**.

🔗 **Repository:** [github.com/3n1gm496/security-scanning-platform](https://github.com/3n1gm496/security-scanning-platform)

---

## 📋 Indice

- [Obiettivo](#-obiettivo)
- [Features](#-features)
- [Scanner Supportati](#-scanner-supportati)
- [Architettura](#-architettura)
- [Quick Start](#-quick-start)
- [Configurazione](#-configurazione)
- [Utilizzo](#-utilizzo)
- [Deployment](#-deployment)
- [Hardening](#-hardening)
- [Sviluppo](#-sviluppo)
- [Contributing](#-contributing)
- [Licenza](#-licenza)

---

## 🎯 Obiettivo

Piattaforma centralizzata, ripetibile e pragmatica per eseguire:

- **SAST** con **Semgrep** (repository analysis)
- **Python-specific SAST** con **Bandit**
- **Pattern-based discovery** con **Nuclei**
- **SBOM-based vulnerability scanning** con **Grype**
- **SCA / dependency scanning** con **Trivy**
- **Secret scanning** con **Gitleaks**
- **Container image scanning** con **Trivy**
- **IaC scanning** con **Checkov**
- **SBOM generation** con **Syft**
- **DAST** (opzionale) con **OWASP ZAP**

Raccolta centralizzata in **SQLite + JSON** con **dashboard FastAPI** unificata.

---

## ✨ Features

- **🔄 CI-Agnostic** — Integrabile con GitLab, Jenkins, Azure DevOps, GitHub Actions o cron/systemd
- **🐳 Containerizzato** — Deploy rapido con Docker Compose su qualsiasi server Linux
- **📊 Dashboard Centralizzata** — API REST + UI web per visualizzare scan, findings e trend, con paginazione cursor-based e filtri per stato
- **✅ Test Coverage Elevata** — Oltre 350 test totali, con **coverage >86%** per il modulo orchestratore.
- **🔍 10+ Scanner OSS** — Semgrep, Bandit, Nuclei, Trivy, Grype, Gitleaks, Checkov, ZAP, Syft e altri
- **📝 Normalizzazione Intelligente** — Output unificato in formato standard per tutti gli scanner
- **🎯 Policy-based Blocking** — Blocco automatico della pipeline su finding critici
- **💾 SQLite Backend** — Persistenza dati semplice, backup facili, zero dipendenze esterne
- **🔐 Autenticazione** — Login basato su form con sessioni sicure; password con hashing bcrypt; cookie `HttpOnly`/`Secure`
- **🛡️ Security Headers** — `Content-Security-Policy`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`
- **⚡ Rate Limiting** — Protezione brute-force su `/login` (10 req/min) e API (180 req/min) con sliding window
- **🔒 Path Traversal Protection** — Validazione e sanitizzazione degli input su tutti gli endpoint di scan
- **🚀 Batch Scanning** — Scansione multipla di target da file YAML
- **📈 Trending e History** — Tracking storico dei finding per analisi nel tempo
- **📧 Email Notifications** — Alert critici e preferenze di notifica granulari per utente (email, canale preferito, digest settimanali/giornalieri)
- **📡 Prometheus Metrics** — Endpoint `/metrics` per osservabilità e monitoring
- **🔁 GitLab Enterprise CI** — Pipeline `.gitlab-ci.yml` completa (lint → test → SAST → build → scan-self → deploy)

---

## 🔎 Scanner Supportati

| Scanner | Tipo | Linguaggi/Target | Output |
|---------|------|------------------|--------|
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

## 🏗️ Architettura

![Diagramma Architettura Piattaforma di Scansione](docs/architecture.png)

### Struttura Repository

```text
.
├── .github/workflows/       # GitHub Actions CI (test, lint, SAST, docker build)
├── .gitlab-ci.yml           # GitLab Enterprise CI/CD pipeline
├── config/
│   ├── settings.yaml        # Configurazione scanner e policy
│   ├── policies.yaml        # Policy di blocco pipeline
│   └── targets.yaml         # Target batch scan
├── dashboard/
│   ├── app.py               # Applicazione FastAPI principale
│   ├── db.py                # Connessione DB centralizzata
│   ├── requirements.in      # Dipendenze sorgente (pip-tools)
│   ├── requirements.txt     # Dipendenze pinnate (generato)
│   ├── Dockerfile
│   ├── static/
│   ├── templates/
│   └── tests/               # ~194 test per il dashboard
├── orchestrator/
│   ├── main.py
│   ├── requirements.in      # Dipendenze sorgente (pip-tools)
│   ├── requirements.txt     # Dipendenze pinnate (generato)
│   └── tests/               # ~165 test per l'orchestratore
├── scripts/
│   ├── ops.sh               # CLI unificata per tutte le operazioni
│   ├── run_scan.sh
│   └── schedule_scan.sh
├── systemd/                 # Service e timer systemd
├── CHANGELOG.md
├── docker-compose.yml
└── .env.example
```

## Prerequisiti Linux

- Docker Engine + Docker Compose plugin
- accesso Internet in uscita per:
  - download immagini / scanner al build
  - update database Trivy
  - fetch regole Semgrep community se si usa `p/default`
- opzionale: accesso a registry container e repository Git remoti
- opzionale: mount del Docker socket host se si vogliono scansionare immagini locali

---

## 🚀 Quick Start

### Installazione Rapida

```bash
# Clone repository
git clone https://github.com/3n1gm496/security-scanning-platform.git
cd security-scanning-platform

# Setup environment
cp .env.example .env
mkdir -p data/{reports,workspaces,cache/trivy,backups}

# Build e avvio
docker compose build
docker compose up -d
```

**Dashboard:** `http://localhost:8080`  
**Credenziali:** Definite in `.env` (default configurabili)

### Test Demo

```bash
./scripts/init_demo.sh
```

---

## ⚙️ Configurazione

### File di Configurazione

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
  # ... altri scanner

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

## 💻 Utilizzo

### Operazioni CLI (ops.sh)

Script di utilità per gestire stack, database, scansioni e operazioni di sviluppo:

```bash
# Stack
./scripts/ops.sh up                    # Avvia stack Docker Compose
./scripts/ops.sh down                  # Arresta stack
./scripts/ops.sh health                # Health check (/, /health, /ready)
./scripts/ops.sh open                  # Apri dashboard nel browser

# Scan
./scripts/ops.sh scan demo             # Esegui demo scan
./scripts/ops.sh scan local --path $PWD --name my-app
./scripts/ops.sh scan git --url https://github.com/org/repo --name my-repo
./scripts/ops.sh scan image --image nginx:latest --name nginx

# Dev / CI (senza Docker)
./scripts/ops.sh test                  # Esegui tutti i test (pytest)
./scripts/ops.sh test dashboard        # Solo test dashboard
./scripts/ops.sh lint                  # flake8 + black check
./scripts/ops.sh lint --fix            # Applica black
./scripts/ops.sh deps-compile          # Rigenera requirements.txt pinnati

# API Keys
./scripts/ops.sh api-key create --name ci-runner --role operator
./scripts/ops.sh api-key list
./scripts/ops.sh api-key revoke --prefix abc123

# Manutenzione
./scripts/ops.sh backup
./scripts/ops.sh retention --days 30
./scripts/ops.sh logs dashboard
```

### API REST

#### Query Scanning Results

```bash
# Lista tutti gli scan
curl http://localhost:8080/api/scans

# Dettaglio scan specifico
curl http://localhost:8080/api/scans/{scan_id}

# Findings per scan
curl http://localhost:8080/api/scans/{scan_id}/findings
```

#### Trigger Scans from Dashboard

Nuovo endpoint per triggerare scans direttamente dalla UI dashboard (richiede autenticazione e permesso `SCAN_WRITE`):

**Trigger Scan Sincrono:**

```bash
curl -X POST http://localhost:8080/api/scan/trigger \
     -H "Authorization: Bearer <your_api_key>" \
     -d "target_type=local&target=/path/to/scan&name=my-local-scan"
```

**Trigger Scan Asincrono:**

```bash
curl -X POST http://localhost:8080/api/scan/trigger-async \
     -H "Authorization: Bearer <your_api_key>" \
     -d "target_type=git&target=https://github.com/pallets/flask.git&name=flask-repo"
```

---

## 🚀 Deployment

### Docker Compose (Consigliato)

Il metodo consigliato è usare `docker-compose.yml` fornito. Configurare le variabili in `.env` e avviare con:

```bash
docker compose up -d
```

### Systemd

Per ambienti di produzione, sono forniti service e timer `systemd` per gestire lo stack e le scansioni schedulate. Copiare i file da `systemd/` in `/etc/systemd/system/` e abilitarli.

---

## 🛡️ Hardening

- **Credenziali**: Non usare le credenziali di default. Generare una `SECRET_KEY` robusta.
- **Network**: Esporre la porta `8080` solo su interfacce di rete fidate.
- **Docker Socket**: Se si monta il socket Docker, applicare le best practice di sicurezza per proteggerlo.
- **HTTPS**: Usare un reverse proxy (es. Nginx, Caddy) per terminare TLS e aggiungere ulteriori header di sicurezza.

---

## 🛠️ Sviluppo

### Setup Ambiente

```bash
# Crea virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Installa dipendenze (dashboard + orchestrator + test)
pip install -r dashboard/requirements.txt -r dashboard/requirements-test.txt
pip install -r orchestrator/requirements.txt -r orchestrator/requirements-test.txt
```

### Gestione Dipendenze

Il progetto usa `pip-tools` per pinnare le dipendenze. Per aggiornare o aggiungere pacchetti:

1.  Modifica i file `.in` (`dashboard/requirements.in`, `orchestrator/requirements.in`, etc.).
2.  Esegui lo script `ops.sh` per ricompilare i file `.txt`:

```bash
./scripts/ops.sh deps-compile
```

### Eseguire i Test

```bash
# Esegui tutti i 350+ test
./scripts/ops.sh test

# Esegui solo i test del dashboard
./scripts/ops.sh test dashboard

# Esegui solo i test dell'orchestratore con coverage
./scripts/ops.sh test orchestrator --coverage
```

---

## 🤝 Contributing

I contributi sono benvenuti! Si prega di aprire un issue per discutere le modifiche proposte o un Pull Request con una descrizione chiara delle modifiche.

## 📜 Licenza

Questo progetto è rilasciato sotto la licenza MIT. Vedi il file [LICENSE](LICENSE) per maggiori dettagli.
