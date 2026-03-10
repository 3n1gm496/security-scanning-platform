# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.0.0/) e il progetto adotta
[Semantic Versioning](https://semver.org/lang/it/).

---

## [Unreleased]

## [1.2.0] — 2026-03-10

Questa release completa la modernizzazione del frontend e degli endpoint API, allineando la paginazione, correggendo le preferenze di notifica e migliorando la compatibilità con Docker in ambienti sandbox.

### Added

- **Filtro per stato nella paginazione dei findings**: Aggiunto parametro `status` alla route `GET /api/findings/paginated` e al `FindingsPaginator` per filtrare i risultati per stato di triage (`open`, `resolved`, `in_progress`, etc.).
- **Test di integrazione per filtro stato**: Aggiunto `test_findings_paginator_with_status_filter` per validare il nuovo filtro.
- **Test di integrazione per preferenze notifiche**: Aggiunto `test_notification_preferences_api_flow` per un test E2E del salvataggio e recupero delle preferenze.

### Changed

- **Allineamento paginazione frontend**: La funzione `loadFindings()` in `app.js` ora usa esclusivamente l'endpoint `/api/findings/paginated` per tutti i filtri, garantendo una paginazione cursor-based consistente.
- **Correzione estrazione cursore**: `loadFindings()` e `loadScans()` ora estraggono correttamente `result.pagination.next_cursor` invece di `result.next_cursor`, allineandosi alla struttura della risposta del backend.
- **Correzione endpoint notifiche**: L'endpoint per le preferenze di notifica è stato corretto da `/api/settings/notifications` a `/api/notifications/preferences` in `app.js`.
- **Allineamento campi notifiche**: I nomi dei campi nel form delle notifiche (`app.html`) e nel modello Vue (`app.js`) sono stati allineati allo schema del backend (`notify_critical` → `critical_alerts`, etc.).

### Fixed

- **Compatibilità Docker in sandbox**: Abilitato `network_mode: "host"` nel `docker-compose.yml` per il servizio `dashboard`, risolvendo l'errore di creazione della rete in ambienti senza supporto per `iptables raw`.

---

## [1.1.0] — 2026-03-09

Questa release consolida i risultati della **due diligence tecnica** condotta sul codebase.
Tutte le modifiche sono state introdotte tramite Pull Request con CI verde prima del merge.

### Sicurezza (P0)

#### fix(security): path traversal su `/api/scan/trigger` — PR #1

- Aggiunta validazione e sanitizzazione degli input `target`, `name` e `target_type`
  nell'endpoint `/api/scan/trigger` del dashboard.
- I path locali vengono ora risolti con `os.path.realpath` e verificati contro
  `WORKSPACE_DIR` configurato: qualsiasi tentativo di uscire dalla directory di lavoro
  restituisce `HTTP 400`.
- I nomi dei target sono sanitizzati con una whitelist di caratteri sicuri.
- Aggiunti 12 test dedicati in `dashboard/tests/test_scan_trigger.py`.
- Corretti contestualmente: `orchestrator/requirements.txt` (aggiunto `tenacity`),
  `orchestrator/Dockerfile` e `docker-compose.yml` allineati al contesto di build
  `./orchestrator` usato dalla CI.

#### feat(security): rate limiting robusto su login e API — PR #2

- Il rate limiter in-memory ora protegge anche l'endpoint `/login`
  (limite separato: 10 richieste/minuto per IP).
- Aggiunta pulizia periodica del dizionario `defaultdict(deque)` tramite
  `threading.Timer` per prevenire memory leak con molti IP distinti.
- Corretti contestualmente tutti i warning `flake8` preesistenti in
  `charting.py`, `finding_management.py`, `notifications.py` e `remediation.py`.
- Aggiunti 8 test dedicati in `dashboard/tests/test_rate_limiting.py`.

#### feat(security): hashing password con bcrypt — PR #3

- La verifica della password ora supporta hash bcrypt nell'env var
  `DASHBOARD_PASSWORD` (formato `$2b$...`).
- Retrocompatibilità garantita: se la variabile contiene una password in chiaro,
  viene confrontata con `secrets.compare_digest` e viene emesso un warning di
  deprecazione nel log.
- Aggiunto `bcrypt>=4.0.0` ai `dashboard/requirements.txt`.
- Aggiunti 10 test dedicati in `dashboard/tests/test_password_hashing.py`.

### Architettura (P1)

#### feat(arch): thread pool bounded per scan async + security headers — PR #4

- Sostituito `threading.Thread` illimitato con `concurrent.futures.ThreadPoolExecutor`
  con dimensione massima configurabile via `MAX_SCAN_WORKERS` (default: 4).
- Aggiunti gli header di sicurezza mancanti nel middleware:
  - `Content-Security-Policy` (default-src 'self'; script-src 'self' 'unsafe-inline')
  - `Strict-Transport-Security` (max-age=31536000; includeSubDomains)
- Aggiunti 6 test dedicati in `dashboard/tests/test_scan_thread_pool.py`.

#### refactor(db): centralizzazione connessioni SQLite e fix datetime — PR #5

- `finding_management.py`, `rbac.py` e `webhooks.py` ora usano `get_connection()`
  da `db.py` invece di chiamare `sqlite3.connect()` direttamente.
- `get_connection()` imposta sempre `row_factory = sqlite3.Row`, garantendo
  accesso uniforme per nome di colonna in tutto il codebase.
- Corretto il bug in `webhooks.py`: `hmac.new()` → `hmac.new()` (era già corretto,
  verificato che `hmac.new` è un alias valido in Python 3.11).
- Sostituito `datetime.utcnow()` (deprecato in Python 3.12) con
  `datetime.now(timezone.utc)` in `monitoring.py` e `charting.py`.

### Developer Experience (P2)

#### feat(dx): pinning dipendenze con pip-tools + ops.sh migliorato — PR #6

- Introdotto **pip-tools** per la gestione delle dipendenze:
  - `dashboard/requirements.in` e `orchestrator/requirements.in` come file sorgente
  - `dashboard/requirements-test.in` e `orchestrator/requirements-test.in` per le
    dipendenze di test
  - I `requirements.txt` sono ora generati con `pip-compile` e contengono versioni
    pinnate di tutte le dipendenze transitive
- `scripts/ops.sh` — nuovi comandi aggiunti:
  - `test [dashboard|orchestrator]` — esegue pytest con coverage
  - `lint [--fix]` — flake8 + black check (con `--fix` applica black)
  - `deps-compile` — rigenera tutti i `requirements.txt` con pip-compile
  - `api-key create|list|revoke` — gestione API key dalla CLI
  - `health` migliorato: verifica anche gli endpoint `/health` e `/ready` con curl

### CI/CD

#### feat(ci): GitLab Enterprise CI/CD pipeline — PR #7

- Aggiunto `.gitlab-ci.yml` con pipeline completa in 6 stage:
  - `lint`: flake8 + black check (parallelo per orchestrator e dashboard)
  - `test`: pytest con report JUnit e coverage Cobertura (nativi GitLab)
  - `security`: Bandit SAST con artefatti JSON
  - `build`: Docker build + push al GitLab Container Registry con layer caching
    e OCI labels (`org.opencontainers.image.*`)
  - `scan-self`: auto-scansione del repository tramite la piattaforma stessa;
    fallisce la pipeline se la policy restituisce `BLOCK` (configurabile)
  - `deploy`: SSH-based con `docker compose pull && up`; staging automatico su
    `develop`, production con approvazione manuale su `main`
  - `nightly:scan`: scansione notturna programmata (solo `schedule`)
- Aggiunto `templates/gitlab-scan-template.yml`: template riutilizzabile per
  altri repository del gruppo GitLab tramite `include:`.
- Aggiunta `docs/gitlab-integration.md`: guida completa con prerequisiti,
  setup variabili, configurazione server, GitLab Ultimate SAST, scansioni
  notturne e troubleshooting.

### Documentazione

#### docs: aggiornamento README e CHANGELOG — PR #8

- `README.md`:
  - Aggiunto badge CI GitHub Actions.
  - Sezione Features aggiornata con le nuove funzionalità di sicurezza.
  - Sezione `ops.sh` aggiornata con i nuovi comandi (`test`, `lint`,
    `deps-compile`, `api-key`).
  - Sezione Sviluppo aggiornata con istruzioni per test, lint e gestione
    dipendenze pinnate.
  - Aggiunto link a `docs/gitlab-integration.md` nella sezione documentazione.
- Creato `CHANGELOG.md` (questo file).

---

## [1.0.0] — 2025-01-01

Versione iniziale della piattaforma.

### Aggiunto

- Orchestratore Python 3.11 con supporto a 10+ scanner OSS (Semgrep, Bandit,
  Nuclei, Trivy, Grype, Gitleaks, Checkov, Syft, OWASP ZAP).
- Dashboard FastAPI con autenticazione, RBAC, gestione finding, notifiche email,
  webhook, export CSV/JSON, metriche Prometheus.
- Deploy Docker Compose e systemd service/timer.
- `scripts/ops.sh` come punto di ingresso unificato per tutte le operazioni.
- CI GitHub Actions con test, lint, SAST e docker build.
- Integrazione Azure DevOps (`azure-pipelines.yml.example`).
- Demo app e script `init_demo.sh`.

---

[Unreleased]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/3n1gm496/security-scanning-platform/releases/tag/v1.0.0
