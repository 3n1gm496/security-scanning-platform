# Operations Guide

This document covers day-to-day operation of the platform outside of feature development.

---

## Main runtime paths

Key paths in the default Docker layout:
- database: `/data/security_scans.db`
- reports: `/data/reports`
- workspaces: `/data/workspaces`
- Trivy cache: `/data/cache/trivy`
- backups: `/data/backups`

Main variables:
- `ORCH_DB_PATH`
- `DASHBOARD_DB_PATH`
- `REPORTS_DIR`
- `WORKSPACE_DIR`
- `TRIVY_CACHE_DIR`

---

## Primary `ops.sh` commands

Stack:
- `./scripts/ops.sh up`
- `./scripts/ops.sh down`
- `./scripts/ops.sh restart`
- `./scripts/ops.sh ps`
- `./scripts/ops.sh logs dashboard`
- `./scripts/ops.sh health`
- `./scripts/ops.sh open`

Scans:
- `./scripts/ops.sh scan demo`
- `./scripts/ops.sh scan local --path <path> --name <name>`
- `./scripts/ops.sh scan git --url <url> --name <name> [--ref <ref>]`
- `./scripts/ops.sh scan image --image <image> --name <name>`
- `./scripts/ops.sh scan batch --file config/targets.yaml`

Maintenance:
- `./scripts/ops.sh backup`
- `RESTORE_YES=1 ./scripts/restore.sh data/backups/<archive>.tar.gz`
- `./scripts/ops.sh retention --days 30`
- `./scripts/ops.sh cache clear-trivy`

Development helpers:
- `./scripts/ops.sh test`
- `./scripts/ops.sh lint`
- `./scripts/ops.sh deps-compile`
- `./scripts/ops.sh api-key create --name <n> --role <r>`

---

## Health checks

Recommended checks:

```bash
curl -fsS http://localhost:8080/api/health
curl -fsS http://localhost:8080/api/ready
curl -fsS http://localhost:8080/metrics
```

Use `ops.sh health` for a quick combined stack + dashboard check.

---

## Backups

The project provides:

```bash
./scripts/ops.sh backup
```

This backs up:
- the SQLite database, or a PostgreSQL dump when PostgreSQL is active
- report artifacts as a tarball
- the tracked config directory

Behavior details:
- SQLite backups prefer `sqlite3 .backup` for a consistent live snapshot and fall back to plain copy only if `sqlite3` is unavailable
- the scripts honor `DASHBOARD_DB_PATH` when the dashboard DB lives outside the default `/data/security_scans.db`

Backup destination:
- `${DATA_DIR}/backups`

Restore:

```bash
RESTORE_YES=1 ./scripts/restore.sh data/backups/<archive>.tar.gz
```

Restore behavior:
- stops the Compose stack before applying data
- restores the configured SQLite path or PostgreSQL dump
- replaces the current reports directory before extracting the archived one
- restores config contents without creating nested `config/config` paths

---

## Retention

```bash
./scripts/ops.sh retention --days 30
```

Use this to trim historical data and keep storage bounded.

Current `ops.sh retention` cleanup scope:
- reports
- workspaces
- Trivy cache

Retention policy behavior depends on configuration and current data layout, so validate the resulting reports and backup posture before using aggressive values.

---

## Email and webhook operations

Email notifications:
- require SMTP configuration
- are managed through Settings -> Notifications

Webhooks:
- are managed through Settings -> Webhooks
- support event-driven delivery with retries and HMAC signatures
- are subject to SSRF validation and delivery controls

---

## PostgreSQL vs SQLite

SQLite:
- default path
- simplest deployment
- good for single-host usage

PostgreSQL:
- enable with `DATABASE_URL` and the Compose `postgres` profile
- preferred when concurrency or external DB operations matter more

The dashboard and orchestrator both support PostgreSQL-aware SQL adaptation through the shared adapter layers.

---

## Troubleshooting checklist

### Dashboard does not start

Check:
- `DASHBOARD_PASSWORD`
- `DASHBOARD_SESSION_SECRET`
- DB path writability
- `docker compose logs dashboard`

### Scans remain `RUNNING`

Check:
- watchdog settings
- orchestrator subprocess logs
- scanner binary availability
- report directory permissions

### Analytics or charts look stale

Check:
- browser console
- API responses from analytics endpoints
- browser smoke screenshots against the latest build

### Remote CI scans behave differently than expected

Check whether the current workflow used:
- remote platform scan
- or local Gitleaks fallback

This distinction matters operationally.
