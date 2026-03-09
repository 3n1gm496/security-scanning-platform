# Integrazione GitLab Enterprise CI/CD

Questa guida descrive come integrare la Security Scanning Platform in una pipeline GitLab Enterprise, sia come **piattaforma da deployare** (il progetto stesso) sia come **strumento di scansione** da invocare da altri repository.

---

## Indice

1. [Prerequisiti](#prerequisiti)
2. [Struttura della pipeline](#struttura-della-pipeline)
3. [Configurazione variabili CI/CD](#configurazione-variabili-cicd)
4. [Deploy della piattaforma su GitLab](#deploy-della-piattaforma-su-gitlab)
5. [Integrare la scansione in altri repository](#integrare-la-scansione-in-altri-repository)
6. [GitLab Ultimate: template SAST nativi](#gitlab-ultimate-template-sast-nativi)
7. [Scansioni programmate (nightly)](#scansioni-programmate-nightly)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisiti

| Requisito | Versione minima |
| :--- | :--- |
| GitLab | 16.0 (Enterprise o Community) |
| GitLab Runner | 16.0 con executor `docker` o `kubernetes` |
| Docker | 24.0 |
| Docker Compose | v2.20 |
| Python | 3.11 |

Il runner deve avere accesso a:
- **GitLab Container Registry** (per push/pull delle immagini)
- **Host di deployment** via SSH (per lo stage `deploy`)
- **URL della piattaforma** (per lo stage `scan-self`)

---

## Struttura della pipeline

Il file `.gitlab-ci.yml` nella root del progetto definisce sei stage in sequenza:

```
lint → test → security → build → scan-self → deploy
```

| Stage | Job | Descrizione |
| :--- | :--- | :--- |
| `lint` | `lint:orchestrator`, `lint:dashboard` | flake8 (errori critici + full) e black check |
| `test` | `test:orchestrator`, `test:dashboard` | pytest con coverage Cobertura e report JUnit |
| `security` | `sast:bandit` | Bandit SAST su orchestrator e dashboard |
| `build` | `build:orchestrator`, `build:dashboard` | Docker build + push al GitLab Container Registry |
| `scan-self` | `scan-self`, `nightly:scan` | Scansione del repository tramite la piattaforma stessa |
| `deploy` | `deploy:staging`, `deploy:production` | Deploy SSH con `docker compose pull && up` |

I job `deploy:staging` e `deploy:production` richiedono rispettivamente trigger automatico su `develop` e approvazione manuale su `main`.

---

## Configurazione variabili CI/CD

Vai su **Settings → CI/CD → Variables** nel progetto GitLab e aggiungi:

### Variabili obbligatorie

| Variabile | Tipo | Descrizione |
| :--- | :--- | :--- |
| `SECURITY_SCANNER_URL` | Variable | URL base della dashboard, es. `https://scanner.example.com` |
| `SECURITY_SCANNER_API_KEY` | Variable (masked) | Bearer token con ruolo `operator` o `admin` |
| `DEPLOY_SSH_KEY` | Variable (masked, protected) | Chiave privata SSH per il deployment |
| `DEPLOY_HOST` | Variable | Hostname o IP del server di deployment |

### Variabili opzionali

| Variabile | Default | Descrizione |
| :--- | :--- | :--- |
| `PYTHON_VERSION` | `3.11` | Versione Python per i job di test e lint |
| `DEPLOY_USER` | `deploy` | Utente SSH sul server di deployment |
| `DEPLOY_PATH` | `/opt/security-scanning-platform` | Path del progetto sul server |
| `SECURITY_SCAN_FAIL_ON_BLOCK` | `true` | Se `true`, la pipeline fallisce quando la policy restituisce `BLOCK` |

### Creare una API key per la CI

Usa `ops.sh` per creare una chiave con ruolo `operator`:

```bash
./scripts/ops.sh api-key create --name gitlab-ci --role operator --expires-days 365
```

Copia il valore della chiave nella variabile `SECURITY_SCANNER_API_KEY` su GitLab (tipo: **masked**).

---

## Deploy della piattaforma su GitLab

### 1. Clonare il repository su GitLab

```bash
# Mirroring da GitHub (opzionale)
git clone https://github.com/3n1gm496/security-scanning-platform.git
cd security-scanning-platform
git remote add gitlab https://gitlab.example.com/security/security-scanning-platform.git
git push gitlab main
```

### 2. Configurare il GitLab Container Registry

Il `.gitlab-ci.yml` usa automaticamente `$CI_REGISTRY`, `$CI_REGISTRY_USER` e `$CI_REGISTRY_PASSWORD` — variabili predefinite di GitLab. Non è necessaria alcuna configurazione aggiuntiva se il Container Registry è abilitato nel progetto.

### 3. Configurare il server di deployment

Sul server di deployment, prepara l'ambiente:

```bash
# Creare l'utente deploy
sudo useradd -m -s /bin/bash deploy
sudo usermod -aG docker deploy

# Aggiungere la chiave pubblica SSH
sudo -u deploy mkdir -p /home/deploy/.ssh
echo "ssh-ed25519 AAAA... gitlab-ci" | sudo -u deploy tee -a /home/deploy/.ssh/authorized_keys
sudo chmod 600 /home/deploy/.ssh/authorized_keys

# Clonare il progetto
sudo mkdir -p /opt/security-scanning-platform
sudo chown deploy:deploy /opt/security-scanning-platform
sudo -u deploy git clone https://gitlab.example.com/security/security-scanning-platform.git \
  /opt/security-scanning-platform

# Configurare .env
cd /opt/security-scanning-platform
sudo -u deploy cp .env.example .env
sudo -u deploy vim .env  # Imposta DASHBOARD_PASSWORD, SECRET_KEY, ecc.
```

### 4. Primo avvio

```bash
sudo -u deploy bash /opt/security-scanning-platform/scripts/ops.sh up
```

---

## Integrare la scansione in altri repository

Per invocare la piattaforma da un qualsiasi altro repository GitLab, aggiungi questo snippet al `.gitlab-ci.yml` del progetto target:

```yaml
include:
  - project: 'security/security-scanning-platform'
    ref: main
    file: '/templates/gitlab-scan-template.yml'
```

In alternativa, copia direttamente il job:

```yaml
security:scan:
  stage: security
  image: alpine:3.19
  before_script:
    - apk add --no-cache curl jq --quiet
  script:
    - |
      set -euo pipefail

      SCAN_RESPONSE=$(curl \
        --fail-with-body --silent --show-error --max-time 300 \
        -X POST "${SECURITY_SCANNER_URL}/api/scan/trigger" \
        -H "Authorization: Bearer ${SECURITY_SCANNER_API_KEY}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "target_type=git" \
        -d "target=${CI_PROJECT_URL}" \
        -d "name=${CI_PROJECT_PATH}" \
        -d "async_mode=false")

      echo "${SCAN_RESPONSE}" | jq .
      POLICY_STATUS=$(echo "${SCAN_RESPONSE}" | jq -r '.output.results[0].policy_status // "UNKNOWN"')

      if [ "${POLICY_STATUS}" = "BLOCK" ]; then
        echo "Security scan BLOCKED: critical findings detected"
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - scan-results.json
    expire_in: 30 days
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

Le variabili `SECURITY_SCANNER_URL` e `SECURITY_SCANNER_API_KEY` possono essere definite a livello di **gruppo GitLab** (Settings → CI/CD → Variables) per renderle disponibili a tutti i repository del gruppo senza doverle ripetere.

---

## GitLab Ultimate: template SAST nativi

Se si dispone di GitLab Ultimate, è possibile abilitare i template SAST nativi decommentando le righe nel `.gitlab-ci.yml`:

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
```

I risultati saranno visibili nella **Security Dashboard** di GitLab e nelle Merge Request come commenti automatici.

> **Nota**: i template GitLab Ultimate e il job `sast:bandit` personalizzato sono complementari. Il primo copre un insieme più ampio di linguaggi; il secondo offre controllo granulare sulle regole Bandit specifiche per questo progetto.

---

## Scansioni programmate (nightly)

Configura una scansione notturna in **CI/CD → Schedules**:

| Campo | Valore |
| :--- | :--- |
| Description | Nightly Security Scan |
| Interval Pattern | `0 2 * * *` (ogni giorno alle 02:00 UTC) |
| Target Branch | `main` |
| Variables | (nessuna aggiuntiva, usa quelle di progetto) |

Il job `nightly:scan` viene eseguito solo quando `$CI_PIPELINE_SOURCE == "schedule"` e ha `allow_failure: true` per non bloccare la pipeline principale in caso di errori transitori dello scanner.

---

## Troubleshooting

### La pipeline fallisce con "Scanner response is not valid JSON"

Verifica che `SECURITY_SCANNER_URL` punti all'URL corretto e che la piattaforma sia raggiungibile dal runner. Testa manualmente:

```bash
curl -v "${SECURITY_SCANNER_URL}/health"
```

### Il job `build:*` fallisce con "unauthorized"

Assicurati che il runner abbia accesso al Container Registry. Se usi un runner self-hosted, verifica che `CI_REGISTRY_USER` e `CI_REGISTRY_PASSWORD` siano iniettati correttamente (sono variabili predefinite di GitLab, non richiedono configurazione manuale).

### Il deploy SSH fallisce con "Host key verification failed"

Il `before_script` del template deploy esegue `ssh-keyscan` per aggiungere l'host a `known_hosts`. Se il server usa una porta SSH non standard, aggiungi:

```yaml
variables:
  DEPLOY_SSH_PORT: "2222"
before_script:
  - ssh-keyscan -p "${DEPLOY_SSH_PORT}" -H "${DEPLOY_HOST}" >> ~/.ssh/known_hosts
```

### La scansione restituisce BLOCK inaspettatamente

Controlla le policy in `config/policies.yaml`. Per disabilitare temporaneamente il blocco senza modificare le policy, imposta la variabile CI/CD:

```
SECURITY_SCAN_FAIL_ON_BLOCK = false
```

Questo permette alla pipeline di continuare ma registra comunque il risultato `BLOCK` negli artefatti.
