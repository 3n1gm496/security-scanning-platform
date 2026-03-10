# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.0.0/) e il progetto adotta
[Semantic Versioning](https://semver.org/lang/it/).

---

## [Unreleased]

## [1.5.0] — 2026-03-10

Questa release si concentra sul **miglioramento radicale della qualità e dell'affidabilità dell'orchestratore** attraverso un aumento massiccio della test coverage, che passa dal 72% a oltre l'86%. Sono stati aggiunti 100 nuovi test, portando il totale a 359.

### Added

- **Aggiunti 100 nuovi test per l'orchestratore**:
  - **`test_normalizers_extended.py`**: 34 nuovi test per le funzioni di normalizzazione (`normalize_trivy`, `normalize_gitleaks`, `normalize_checkov`) e le funzioni helper (`_severity`, `_fingerprint`, `_rel_path`).
  - **`test_scanners_extended.py`**: 41 nuovi test per i wrapper degli scanner (`run_semgrep`, `run_trivy_fs`, `run_trivy_image`, `run_gitleaks`, `run_checkov`, `run_syft`), utilizzando mock per simulare l'esecuzione dei comandi e gestire i codici di uscita.
  - **`test_db_adapter.py`**: 25 nuovi test per il modulo `db_adapter`, validando le classi wrapper per connessione e cursore in modalità SQLite.
- **Diagramma di architettura aggiornato**: Creato un nuovo diagramma di flusso con Mermaid per rappresentare in modo più chiaro le interazioni tra i componenti.

### Changed

- **Test Coverage Orchestratore**: Aumentata la test coverage del modulo orchestratore dal **72.13%** all'**86.76%**.
- **Totale Test**: Il numero totale di test per l'intero progetto è ora di **359** (194 per il dashboard + 165 per l'orchestratore).

### Removed

- **Endpoint Deprecati**: Rimossi gli endpoint `/api/findings/by-status` e `/api/findings/stats-by-status` che erano stati sostituiti dalla paginazione basata su cursore.

### Fixed

- **Test `test_semgrep_rate_limit_raises`**: Corretto il test per gestire correttamente l'eccezione `tenacity.RetryError` sollevata dopo il fallimento dei tentativi di retry, garantendo la robustezza del test.

---

## [1.4.0] — 2026-03-10

Questa release è il risultato di un secondo audit maniacale completo della codebase, focalizzato su sicurezza, qualità del codice, test coverage e edge case. Sono stati corretti 5 bug critici di sicurezza e 6 problemi di qualità del codice.

### Security (S)

- **S1 — Aggiunto Subresource Integrity (SRI) per i CDN**: Aggiunti hash `integrity` ai tag `<script>` per Vue.js e Chart.js, prevenendo il caricamento di risorse compromesse (XSS).
- **S2 — Aggiunto `Permissions-Policy` header**: Limita l'accesso a feature sensibili del browser (es. `geolocation=()`, `microphone=()`), riducendo la superficie d'attacco.
- **S3 — Encoding email nel link unsubscribe**: L'email dell'utente viene ora codificata con `urllib.parse.quote_plus` prima di essere inserita nel link, prevenendo problemi con caratteri speciali.
- **S4 — Validazione `sort_by` in `BasePaginator`**: Aggiunta una whitelist di colonne valide per prevenire SQL injection nel `ORDER BY`.
- **S5 — Cookie di sessione `HttpOnly`**: Il cookie di sessione è ora `HttpOnly` di default, prevenendo l'accesso da JavaScript (XSS).

### Code Quality (Q)

- **Q1 — Workspace cleanup nell'orchestratore**: Aggiunto un blocco `try...finally` in `prepare_target` per garantire che la directory di lavoro temporanea venga sempre rimossa, anche in caso di errore durante il clone git.
- **Q2 — Catch silenzioso in `evaluate_policy`**: Aggiunto un log `warning` quando il file di policy non viene trovato, invece di fallire silenziosamente.
- **Q3 — Timeout globale per `fetch`**: Aggiunto un timeout di 30 secondi a tutte le chiamate `fetch` nel frontend tramite `AbortController`, prevenendo richieste bloccate a tempo indeterminato.
- **Q4 — Catch silenziosi nel frontend**: Corretti 3 `catch` silenziosi in `app.js` aggiungendo `console.debug` per loggare gli errori in modalità debug.
- **Q5 — Test coverage gaps**: Aggiunti 15 nuovi test in `test_coverage_gaps.py` per coprire le aree non testate di `db.py`, `finding_management.py` e gli endpoint non coperti di `app.py`.
- **Q6 — Dipendenze di test non pinnate**: Aggiunto `requirements-test.in` all'orchestratore per pinnare anche le dipendenze di test.

---

## [1.3.0] — 2026-03-10

Questa release risolve **11 bug** scoperti durante un audit maniacale completo della codebase (backend, frontend, orchestratore, Docker, CI). Il container è ora self-contained con tutti gli scanner installati.

### Fixed

- **B1 — `AttributeError` a runtime in `api_update_finding_status`**: il parametro Form `status` collideva con il modulo `fastapi.status` importato nello stesso scope. Rinominato in `status_value`.
- **B2 — `scan_id` dichiarato `int` invece di `str` (UUID)**: il database usa UUID come TEXT; il tipo errato causava zero risultati per qualsiasi filtro per scan. Corretto in `app.py` (route export e paginate) e in `pagination.py`.
- **B3 — Pulsante "Findings" nella lista scansioni non funzionava**: `viewScanFindings()` impostava `findingsFilter.search` invece di `findingsFilter.scan_id`; l'endpoint `/api/findings/paginated` non accettava il parametro `scan_id`. Entrambi corretti.
- **B4 — `triggerScan()` inviava JSON invece di `FormData`**: il backend usa `Form(...)` per tutti i parametri; il frontend inviava `Content-Type: application/json` causando 422 Unprocessable Entity.
- **B5 — Modal "Nuova scansione" non si chiudeva** dopo il trigger riuscito. Aggiunto `this.showScanModal = false` nel callback di successo.
- **B6 — `findingsSort` non definito in `data()`**: `sortTable()` falliva silenziosamente con `TypeError`. Aggiunto `findingsSort: { column: 'id', order: 'ASC' }` in `data()`.
- **B7 — Default `enabled=True` per scanner non presenti in `settings.yaml`**: scanner non installati venivano chiamati e fallivano. Cambiato default a `False` in `orchestrator/main.py`.
- **B8 — `unzip` mancante nell'immagine Docker slim**: il layer di installazione di nuclei falliva con `unzip: not found`. Aggiunto `unzip` alle dipendenze apt.
- **B9 — Container Docker non includeva i binari scanner**: tutte le scansioni risultavano `PARTIAL_FAILED`. Il Dockerfile ora installa gitleaks v8.30.0, trivy v0.69.3, syft v1.42.2, grype v0.109.1, nuclei v3.7.1 (versioni pinnate) e semgrep + checkov via pip.
- **B10 — `settings.yaml` con tutti gli scanner disabilitati**: ripristinato con `enabled: true` per tutti gli scanner; `owasp_zap` rimane `false` per default con commento esplicativo sui prerequisiti.
- **B11 — CI workflow usava `context: ./dashboard`**: il Dockerfile aggiornato copia `orchestrator/` dalla root del progetto; il context del build è stato aggiornato a `.` (root).

### Added

- Badge `scan_id` nella barra filtri della pagina Findings: mostra l'UUID troncato con pulsante ✕ per rimuovere il filtro; visibile solo quando il filtro scan è attivo.
- CSS per `.filter-scan-id`, `.scan-id-badge`, `.btn-icon-sm`.

---

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

[Unreleased]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/3n1gm496/security-scanning-platform/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/3n1gm496/security-scanning-platform/releases/tag/v1.0.0
