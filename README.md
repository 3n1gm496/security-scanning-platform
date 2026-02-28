# Centralized Security Scanning Platform

Piattaforma open source, Linux-based, CI-agnostic, pensata per ambienti enterprise eterogenei con budget quasi nullo.

## Obiettivo

Eseguire in modo centralizzato, ripetibile e pragmatico:

- SAST con **Semgrep** (repository analysis)
- Python-specific SAST con **Bandit**
- pattern-based discovery con **Nuclei**
- SBOM-based vulnerability scanning con **Grype**
- SCA / dependency scanning con **Trivy**
- secret scanning con **Gitleaks**
- container image scanning con **Trivy**
- IaC scanning con **Checkov**
- SBOM generation con **Syft**
- opzionale DAST con **OWASP ZAP** (tramite zap-cli)
- raccolta centralizzata dei risultati in **SQLite + JSON**
- dashboard centralizzata con **FastAPI**

## Scelte MVP

- **Orchestratore Python 3.11**: semplice da manutenere dal team IT/Security
- **Scanner CLI OSS**: facilmente riusabili anche fuori piattaforma
- **SQLite**: sufficiente per MVP singolo nodo, backup semplice, costo quasi nullo
- **FastAPI dashboard**: API + UI basilare nello stesso componente
- **Docker Compose**: deploy rapido su server Linux standard
- **CI-agnostic**: utilizzabile da GitLab, Jenkins, Azure DevOps, cron, systemd o run manuali

## Struttura

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
│   └── schedule_scan.sh
├── systemd/
│   ├── security-dashboard.service
│   └── security-scanner.service
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

## Quick start

```bash
cp .env.example .env
mkdir -p data/reports data/workspaces data/cache/trivy
docker compose build
docker compose up -d dashboard orchestrator
```

Dashboard: `http://localhost:8080`

Credenziali default MVP: definite in `.env`.

> 🔐 **Autenticazione aggiornata** – il dashboard usa ora un sistema di login basato su form
> e cookie invece dell'HTTP Basic; impostare `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD`
> come prima e fornire anche `SECRET_KEY` per firmare le sessioni (aggiunto nel `.env`).

## Esecuzione manuale singolo target

### Repository locale

```bash
./scripts/run_scan.sh --target-type local --target "$PWD/demo/demo-app" --target-name demo-local --fail-on-policy-block
```

### Repository Git remoto

```bash
./scripts/run_scan.sh --target-type git --target https://github.com/OWASP/NodeGoat.git --target-name nodegoat
```

### Immagine container

```bash
./scripts/run_scan.sh --target-type image --target nginx:1.27-alpine --target-name nginx-demo
```

## Esecuzione batch da file targets

```bash
./scripts/run_scan.sh --targets-file config/targets.yaml
```

## Scheduling

Per batch periodico:

```bash
./scripts/schedule_scan.sh
```

Esempio cron:

```cron
0 2 * * * /opt/security-scanner/scripts/schedule_scan.sh >> /var/log/security-scanner/cron.log 2>&1
```

## Percorsi dati

- DB SQLite: `/data/security_scans.db`
- report raw: `/data/reports/<scan_id>/raw/`
- findings normalizzati: `/data/reports/<scan_id>/normalized_findings.json`
- summary scan: `/data/reports/<scan_id>/summary.json`
- workspace clone Git: `/data/workspaces/<scan_id>/repo`

## Modello operativo consigliato

1. Team Security gestisce piattaforma e baseline policy
2. Team applicativi / fornitori usano script o pipeline wrapper
3. Dashboard centralizza risultati e trend
4. Blocking iniziale solo su casi ad alto valore
5. Le eccezioni vivono in repository (`.gitleaksignore`, `.trivyignore`, `.checkov.yaml`, regole semgrep custom) o in governance centrale

## Note importanti

- **DAST è ora supportato** tramite OWASP ZAP + zap-cli; il sistema scarica una versione headless durante la build e l'abilitazione avviene con `scanners.owasp_zap.enabled: true` nello YAML.
- **SQLite è solo per MVP/singolo nodo**: per HA o carichi maggiori migrare a PostgreSQL.
- **Docker socket**: montarlo solo se serve per immagini locali; altrimenti preferire scan di immagini via registry.
- **SQLite è solo per MVP/singolo nodo**: per HA o carichi maggiori migrare a PostgreSQL.
- **Docker socket**: montarlo solo se serve per immagini locali; altrimenti preferire scan di immagini via registry.

## Hardening minimo consigliato

- server Linux dedicato
- utenza dedicata per deployment
- backup giornaliero di `/data`
- reverse proxy davanti alla dashboard con TLS
- firewall solo verso admin network
- dashboard con credenziali non di default
- rimozione del mount `docker.sock` se non necessario
- separazione privilegi tra dashboard e orchestratore

## Demo rapida

```bash
./scripts/init_demo.sh
```

Questo avvia una scansione della demo locale inclusa nel repository.
