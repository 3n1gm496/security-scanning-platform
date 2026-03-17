# GitLab Enterprise Integration

This guide explains how to integrate the platform with GitLab in two modes:
- deploying the platform itself from GitLab
- invoking the platform from other GitLab repositories as a reusable security gate

The content here is aligned with the current repository state, including the remote-or-fallback security scan behavior.

---

## Prerequisites

| Requirement | Minimum |
|---|---|
| GitLab | 16.x |
| GitLab Runner | Docker executor recommended |
| Docker | 24+ |
| Docker Compose | v2.20+ |
| Python | 3.11+ |

The runner should be able to reach:
- the target GitLab repository
- the platform URL for remote scans
- the deployment host if you automate deploys

---

## What the repository already provides

Relevant files:
- `.gitlab-ci.yml`
- `templates/gitlab-scan-template.yml`
- `docs/gitlab-integration.md` (this document)

Typical GitLab stage flow:

```text
lint -> test -> security -> build -> scan-self -> deploy
```

Use this as a starting point, not as an immutable contract. The GitHub Actions workflows are the most actively maintained CI source of truth for this repository, so keep your GitLab pipeline aligned with the current API and runtime behavior.

---

## Required variables

Add these under **Settings -> CI/CD -> Variables**.

### Remote scan mode

| Variable | Required | Description |
|---|---|---|
| `SECURITY_SCANNER_URL` | yes | Base URL of the deployed dashboard, e.g. `https://scanner.example.com` |
| `SECURITY_SCANNER_API_KEY` | yes | API key with `operator` or `admin` role |

### Deploy mode

| Variable | Required | Description |
|---|---|---|
| `DEPLOY_SSH_KEY` | if deploying | SSH private key for the deploy host |
| `DEPLOY_HOST` | if deploying | Hostname or IP of the target server |
| `DEPLOY_USER` | optional | SSH user, default `deploy` |
| `DEPLOY_PATH` | optional | Remote path, default `/opt/security-scanning-platform` |

### Optional control variables

| Variable | Default | Description |
|---|---|---|
| `SECURITY_SCAN_FAIL_ON_BLOCK` | `true` | Fails the job when the platform returns `BLOCK` |
| `PYTHON_VERSION` | `3.11` | Test/lint Python version |

---

## Creating the API key for CI

Use the platform itself:

```bash
./scripts/ops.sh api-key create --name gitlab-ci --role operator --expires-days 365
```

Store the resulting `ssp_...` token in `SECURITY_SCANNER_API_KEY`.

---

## Deploying the platform from GitLab

### 1. Mirror or push the repository

```bash
git clone https://github.com/3n1gm496/security-scanning-platform.git
cd security-scanning-platform
git remote add gitlab https://gitlab.example.com/security/security-scanning-platform.git
git push gitlab main
```

### 2. Prepare the target server

```bash
sudo useradd -m -s /bin/bash deploy || true
sudo usermod -aG docker deploy

sudo mkdir -p /opt/security-scanning-platform
sudo chown deploy:deploy /opt/security-scanning-platform

sudo -u deploy git clone https://gitlab.example.com/security/security-scanning-platform.git \
  /opt/security-scanning-platform
```

### 3. Configure `.env`

At minimum set:
- `DASHBOARD_PASSWORD`
- `DASHBOARD_SESSION_SECRET`
- `DASHBOARD_HTTPS_ONLY=1` if TLS is terminated upstream
- optional SMTP settings
- optional `DATABASE_URL` if using PostgreSQL

### 4. Start the stack

```bash
cd /opt/security-scanning-platform
sudo -u deploy cp .env.example .env
sudo -u deploy mkdir -p data/{reports,workspaces,cache/trivy,backups}
sudo -u deploy docker compose build
sudo -u deploy docker compose up -d
```

Health checks:

```bash
curl -fsS http://localhost:8080/api/health
curl -fsS http://localhost:8080/api/ready
```

---

## Calling the platform from another GitLab repository

The simplest pattern is a job that triggers `/api/scan/trigger` with `async_mode=false`.

```yaml
security:scan:
  stage: security
  image: alpine:3.19
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      set -euo pipefail

      SCAN_RESPONSE="$(curl \
        --fail-with-body \
        --silent \
        --show-error \
        --max-time 300 \
        -X POST "${SECURITY_SCANNER_URL}/api/scan/trigger" \
        -H "Authorization: Bearer ${SECURITY_SCANNER_API_KEY}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "target_type=git" \
        -d "target=${CI_PROJECT_URL}" \
        -d "name=${CI_PROJECT_PATH}" \
        -d "async_mode=false")"

      echo "${SCAN_RESPONSE}" | jq .

      SCAN_STATUS="$(echo "${SCAN_RESPONSE}" | jq -r '.status // "unknown"')"
      POLICY_STATUS="$(echo "${SCAN_RESPONSE}" | jq -r '.output.results[0].policy_status // .policy_status // "UNKNOWN"')"

      if [ "${SCAN_STATUS}" = "error" ] || [ "${SCAN_STATUS}" = "failed" ]; then
        echo "Scanner returned an error status"
        exit 1
      fi

      if [ "${SECURITY_SCAN_FAIL_ON_BLOCK:-true}" = "true" ] && [ "${POLICY_STATUS}" = "BLOCK" ]; then
        echo "Security policy blocked the pipeline"
        exit 1
      fi
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

This snippet matches the current API shape used by the repository's own remote scan workflow.

---

## Current security scan workflow behavior

The repository's reusable security scan workflow currently behaves like this:

1. If `SECURITY_SCANNER_URL` and `SECURITY_SCANNER_API_KEY` exist, it runs a remote platform scan.
2. If they do not exist, it runs a local Gitleaks fallback and still uploads `scan-results.json`.

Important consequence:
- a green pipeline can mean "remote platform scan succeeded"
- or "local fallback scan succeeded"

If you want GitLab to behave like a hard remote gate, make the remote variables mandatory in your GitLab project/group and fail the pipeline when they are missing.

---

## Runner and registry notes

For Docker-based build jobs:
- use a Docker executor
- enable privileged mode if you build images with Docker-in-Docker
- pre-pull or mirror base images if your instance is air-gapped

Example runner fragment:

```toml
[[runners]]
  name = "security-scanner-runner"
  executor = "docker"
  [runners.docker]
    image = "python:3.11-slim"
    privileged = true
    volumes = ["/cache", "/certs/client"]
```

If your environment is air-gapped, mirror:
- `python:3.11-slim`
- `docker` / `docker:dind`
- `alpine`
- any internal registry dependencies you need

---

## Scheduled scans

Typical nightly schedule:

| Field | Value |
|---|---|
| Description | Nightly Security Scan |
| Interval Pattern | `0 2 * * *` |
| Target Branch | `main` |

For scheduled scans, decide whether you want:
- remote platform scan only
- or fallback-acceptable behavior

That is an operational policy choice, not a repository limitation.

---

## Troubleshooting

### Invalid JSON from the platform

Check the platform URL directly:

```bash
curl -v "${SECURITY_SCANNER_URL}/api/health"
```

### Pipeline passes but did not run the remote scan

Verify:
- `SECURITY_SCANNER_URL`
- `SECURITY_SCANNER_API_KEY`
- the workflow/job summary text

Remember that the current workflow falls back locally when the remote secrets are missing.

### Remote scan returns `BLOCK`

Review:
- `config/policies.yaml`
- the scan response payload
- whether `SECURITY_SCAN_FAIL_ON_BLOCK` should stay enabled for that project

### Deploy fails over SSH

Check:
- host key trust
- `DEPLOY_HOST`
- `DEPLOY_USER`
- `DEPLOY_PATH`
- that the `deploy` user has Docker access

### Dashboard starts but sessions are insecure

Ensure production `.env` sets:
- a real `DASHBOARD_PASSWORD`
- a strong `DASHBOARD_SESSION_SECRET`
- `DASHBOARD_HTTPS_ONLY=1` behind TLS
