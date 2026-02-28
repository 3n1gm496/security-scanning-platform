# Centralized Security Scanning Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)

Piattaforma open source, Linux-based e CI-agnostic per security scanning centralizzato in ambienti enterprise eterogenei. Orchestrazione automatica di 10+ scanner OSS con dashboard unificata e normalizzazione dei risultati.

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
- **📊 Dashboard Centralizzata** — API REST + UI web per visualizzare scan, findings e trend
- **🔍 10+ Scanner OSS** — Semgrep, Bandit, Nuclei, Trivy, Grype, Gitleaks, Checkov, ZAP, Syft e altri
- **📝 Normalizzazione Intelligente** — Output unificato in formato standard per tutti gli scanner
- **🎯 Policy-based Blocking** — Blocco automatico della pipeline su finding critici
- **💾 SQLite Backend** — Persistenza dati semplice, backup facili, zero dipendenze esterne
- **🔐 Autenticazione** — Login basato su form con sessioni sicure
- **🚀 Batch Scanning** — Scansione multipla di target da file YAML
- **📈 Trending e History** — Tracking storico dei finding per analisi nel tempo

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

- **Orchestratore Python 3.11**: semplice da manutenere dal team IT/Security
- **Scanner CLI OSS**: facilmente riusabili anche fuori piattaforma
- **SQLite**: sufficiente per MVP singolo nodo, backup semplice, costo quasi nullo
- **FastAPI dashboard**: API + UI basilare nello stesso componente
- **Docker Compose**: deploy rapido su server Linux standard
- **CI-agnostic**: utilizzabile da GitLab, Jenkins, Azure DevOps, cron, systemd o run manuali

### Scelte Architetturali

- **Orchestratore Python 3.11** — Semplice da mantenere per team IT/Security
- **Scanner CLI OSS** — Riutilizzabili anche fuori dalla piattaforma
- **SQLite** — Sufficiente per MVP singolo nodo, backup semplici, costo nullo
- **FastAPI Dashboard** — API + UI nello stesso componente
- **Docker Compose** — Deploy rapido su server Linux standard
- **CI-agnostic** — Utilizzabile da qualsiasi tool CI/CD o schedulatore

### Componenti

```
┌─────────────────┐      ┌──────────────────┐
│   Dashboard     │◄─────┤   Orchestrator   │
│   (FastAPI)     │      │   (Python CLI)   │
└────────┬────────┘      └────────┬─────────┘
         │                        │
         │                        │
         ▼                        ▼
  ┌─────────────┐         ┌─────────────────┐
  │   SQLite    │         │   10+ Scanners  │
  │   Database  │         │   (CLI tools)   │
  └─────────────┘         └─────────────────┘
```

### Struttura Repository

```text
.
├── config/
│   ├── settings.yaml
│   └── targets.yaml
├── dashboard/
│   ├── app.py
│   ├── db.py
│   ├── models.py
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── static/style.css
│   └── templates/
├── demo/
│   ├── demo-app/
│   └── sample-normalized-report.json
├── orchestrator/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   ├── normalizer.py
│   ├── scanners.py
│   ├── storage.py
│   ├── requirements.txt
│   └── Dockerfile
├── scripts/
│   ├── init_demo.sh
│   ├── run_scan.sh
│   ├── schedule_scan.sh
│   └── schedule_retention.sh
├── systemd/
│   ├── security-dashboard.service
│   ├── security-scanner.service
│   ├── security-retention.service
│   └── security-retention.timer
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
- per utilizzare **Bandit / Nuclei / Grype / OWASP ZAP** la macchina/container deve poter scaricare i rispettivi binari (il `Dockerfile` prova a scaricarli durante la build).
  Se la rete non è disponibile la build continuerà comunque ma gli scanner non saranno presenti: in quel caso è possibile
  * installarli manualmente all'interno dell'immagine (`docker exec`),
  * estendere il `Dockerfile` con i passi di download oppure
  * montare i binari nella cartella `/usr/local/bin`.
  I wrapper implementano un controllo sul `PATH` e, in assenza degli eseguibili, emettono un warning
  e restituiscono risultati vuoti anziché far fallire l'esecuzione.
  
  **Nota**: nuclei ha modificato l'interfaccia CLI a partire dalla serie v2.x.  In particolare il flag
  `-json` utilizzato nelle versioni precedenti non esiste più; il wrapper interno utilizza
  `-json-export`/`-je` e il Dockerfile costruisce sempre una versione v2 compatibile.  Se vedete un errore
  `flag provided but not defined: -json` significa che avete in PATH un'installazione troppo vecchia.

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
docker compose up -d dashboard orchestrator
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
    image: myregistry/app:latest
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
```

---

## 💻 Utilizzo

### Scan Singolo - Repository Locale

```bash
./scripts/run_scan.sh \
  --target-type local \
  --target /path/to/repo \
  --target-name my-project \
  --fail-on-policy-block
```

### Scan Singolo - Repository Git

```bash
./scripts/run_scan.sh \
  --target-type git \
  --target https://github.com/OWASP/NodeGoat.git \
  --target-name nodegoat
```

### Scan Singolo - Container Image

```bash
./scripts/run_scan.sh \
  --target-type image \
  --target nginx:1.27-alpine \
  --target-name nginx-demo
```

### Scan Batch da File

```bash
./scripts/run_scan.sh --targets-file config/targets.yaml
```

### Scheduling con Cron

```bash
# Aggiungi a crontab
0 2 * * * /opt/security-scanner/scripts/schedule_scan.sh >> /var/log/security-scanner/cron.log 2>&1
```

### Retention Manuale (Cleanup)

```bash
# Esegue solo retention e termina
./scripts/run_scan.sh --retention-only --settings config/settings.yaml

# Dry-run retention (nessuna cancellazione)
./scripts/run_scan.sh --retention-only --retention-dry-run --settings config/settings.yaml
```

### Scheduling Retention con Cron

```bash
# Esegue retention giornaliera alle 03:30
30 3 * * * /opt/security-scanner/scripts/schedule_retention.sh >> /var/log/security-scanner/retention.log 2>&1
```

### API REST

```bash
# Lista tutti gli scan
curl http://localhost:8080/api/scans

# Dettaglio scan specifico
curl http://localhost:8080/api/scans/{scan_id}

# Findings per scan
curl http://localhost:8080/api/scans/{scan_id}/findings
```

---

## 🐳 Deployment

### Docker Compose (Raccomandato)

```bash
docker compose up -d
```

### Systemd Service

```bash
# Copia service files
sudo cp systemd/*.service /etc/systemd/system/
sudo cp systemd/*.timer /etc/systemd/system/

# Enable e start
sudo systemctl enable security-dashboard security-scanner
sudo systemctl start security-dashboard security-scanner

# Enable retention timer giornaliero
sudo systemctl enable --now security-retention.timer

# Verifica prossima esecuzione timer
systemctl list-timers security-retention.timer
```

### Kubernetes (Avanzato)

Vedi [`docs/kubernetes-deployment.md`](docs/kubernetes-deployment.md) per configurazione completa.

---

## 🔒 Hardening

### Checklist Sicurezza

- ✅ **Server dedicato** con utenza non-root per deployment
- ✅ **Backup giornaliero** di `/data` (cronjob + rsync)
- ✅ **Reverse proxy** (nginx/Caddy) con TLS per dashboard
- ✅ **Firewall** — Limita accesso dashboard solo da admin network
- ✅ **Credenziali robuste** — Cambia default in `.env`
- ✅ **Docker socket** — Rimuovi mount se non necessario per scan immagini locali
- ✅ **Separazione privilegi** — Dashboard e orchestrator con utenze diverse
- ✅ **Log rotation** — Configura logrotate per `/var/log/security-scanner/`

### Esempio Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name security.example.com;
    
    ssl_certificate /etc/ssl/certs/security.crt;
    ssl_certificate_key /etc/ssl/private/security.key;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 🛠️ Sviluppo

### Setup Locale

```bash
# Orchestrator
cd orchestrator
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py --help

# Dashboard
cd dashboard
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8080
```

### Test

```bash
# Orchestrator tests
cd orchestrator/tests
pytest test_normalizer.py -v

# Dashboard tests
cd dashboard/tests
pytest test_api.py -v
```

### Struttura Codebase

```
security-scanning-platform/
├── orchestrator/           # CLI orchestration engine
│   ├── main.py            # Entry point
│   ├── scanners.py        # Scanner wrappers
│   ├── normalizer.py      # Output normalization
│   └── storage.py         # Data persistence
├── dashboard/             # FastAPI web interface
│   ├── app.py            # Main application
│   ├── db.py             # Database models
│   └── templates/        # Jinja2 templates
├── config/               # Configuration files
├── scripts/              # Helper scripts
└── docs/                # Documentation
```

---

## 🤝 Contributing

Le contribuzioni sono benvenute! Per contribuire:

1. **Fork** del repository
2. **Crea branch** per la tua feature (`git checkout -b feature/NewScanner`)
3. **Commit** delle modifiche (`git commit -m 'Add support for new scanner'`)
4. **Push** al branch (`git push origin feature/NewScanner`)
5. **Pull Request** con descrizione dettagliata

### Aggiungere un Nuovo Scanner

1. Crea wrapper in [`orchestrator/scanners.py`](orchestrator/scanners.py)
2. Aggiungi normalizzatore in [`orchestrator/normalizer.py`](orchestrator/normalizer.py)
3. Aggiorna configurazione in `config/settings.yaml`
4. Aggiungi test in `orchestrator/tests/`
5. Documenta in README

---

## 📄 Licenza

Questo progetto è distribuito sotto licenza MIT. Vedi il file [`LICENSE`](LICENSE) per maggiori dettagli.

---

## 📚 Documentazione Aggiuntiva

- [Architettura Tecnica](docs/technical-architecture.md)
- [API Reference](docs/api-reference.md)
- [Scanner Integration Guide](docs/scanner-integration.md)
- [Troubleshooting](docs/troubleshooting.md)

---

## 🙏 Riconoscimenti

Grazie alla community open source e ai maintainer degli scanner integrati:

- [Semgrep](https://semgrep.dev/) — SAST multi-language
- [Trivy](https://trivy.dev/) — Container & dependency scanning
- [Gitleaks](https://gitleaks.io/) — Secret detection
- [Nuclei](https://nuclei.projectdiscovery.io/) — Vulnerability scanning
- [Checkov](https://www.checkov.io/) — IaC security
- [OWASP ZAP](https://www.zaproxy.org/) — DAST scanning
- E tutti gli altri progetti OSS utilizzati

---

<div align="center">

**⭐ Se questo progetto ti è utile, considera di dargli una stella su GitHub! ⭐**

[Segnala Bug](https://github.com/3n1gm496/security-scanning-platform/issues) · [Richiedi Feature](https://github.com/3n1gm496/security-scanning-platform/issues) · [Discussioni](https://github.com/3n1gm496/security-scanning-platform/discussions)

</div>

