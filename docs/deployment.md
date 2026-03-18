# Deployment Guide

This guide covers the currently supported deployment shapes.

---

## Recommended path: Docker Compose

Files:
- `docker-compose.yml`
- `docker-compose.dev.yml`
- `docker-compose.ci.yml`

Typical production-like startup:

```bash
cp .env.example .env
mkdir -p data/{reports,workspaces,cache/trivy,backups}
docker compose build
docker compose up -d
```

The dashboard listens on:
- `8080` inside the container
- `${DASHBOARD_PORT:-8080}` on the host

---

## Compose services

### `dashboard`

Responsibilities:
- serves the SPA
- exposes API endpoints
- owns auth/session/RBAC/webhook/notification/export/analytics logic
- triggers orchestrator work through subprocess execution
- reads SQLite from `DASHBOARD_DB_PATH` when `DATABASE_URL` is unset

### `orchestrator`

Responsibilities:
- scanner execution and report generation
- typically run manually or through scan trigger paths
- reads SQLite from `ORCH_DB_PATH` when `DATABASE_URL` is unset

### `postgres`

Optional service:
- enabled through the `postgres` profile
- only needed when you want DB lifecycle outside shared SQLite

### `zap`

Optional internal-only DAST service:
- reachable on the internal network by dashboard/orchestrator
- not meant to be exposed publicly

---

## Reverse proxy and HTTPS

Recommended production posture:
- terminate TLS in Nginx, Caddy, or another reverse proxy
- forward to the dashboard on `127.0.0.1:8080`
- set `DASHBOARD_HTTPS_ONLY=1`
- override `DASHBOARD_CSP_ALLOW_UNSAFE_EVAL=0` unless your runtime actually needs the compatibility default from Compose

Reverse proxy should pass:
- `Host`
- `X-Real-IP`
- `X-Forwarded-For`
- `X-Forwarded-Proto`

---

## Local development

For hot-reload-oriented work:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

For non-Docker local work:
- use the local `venv`
- run tests directly
- use `node scripts/browser_smoke.mjs` for UI verification

---

## CI and image build notes

Current GitHub Actions flow builds:
- `orchestrator/Dockerfile`
- `dashboard/Dockerfile`

It also primes shared scanner tooling with:
- `docker/scanner-tools.Dockerfile`

Security-focused build notes:
- `trivy` is compiled from source in the build pipeline with the required patched dependency
- `gitleaks` is compiled from source with a patched Go toolchain
- `nuclei` is also compiled from source and intentionally not overwritten later by release-binary fetch steps

Current CI/image expectations:
- both runtime images build on GitHub Actions
- both images are scanned with Trivy at `CRITICAL,HIGH`
- a green image-scan result means the built images passed Trivy in CI, not just that the Dockerfiles parsed locally

---

## Database deployment choices

### SQLite

Use when:
- you want the simplest single-host deployment
- file-backed local persistence is enough

### PostgreSQL

Use when:
- you want an external DB lifecycle
- you need more concurrent write/read headroom
- you want integration with broader infra tooling

Enable with:
- `DATABASE_URL`
- `docker compose --profile postgres up -d`

SQLite path notes:
- `DASHBOARD_DB_PATH` controls the dashboard-side SQLite path
- `ORCH_DB_PATH` controls the orchestrator-side SQLite path
- for shared SQLite deployments, point both at the same file

---

## Systemd

The repository includes systemd unit files in `systemd/`.

Use them when:
- you want service/timer integration outside Docker Compose automation
- you want host-level scheduled execution

Always verify that the deployment path referenced by the units matches your actual installation path.

---

## Deployment checklist

- `.env` configured with real secrets
- storage directories created
- dashboard health and readiness green
- authenticated metrics reachable
- browser smoke green against the candidate build if UI changed
- CI green on the commit being deployed
