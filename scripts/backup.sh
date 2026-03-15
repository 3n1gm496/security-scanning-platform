#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# backup.sh — Back up the Security Scanning Platform database and reports.
#
# Usage:
#   ./scripts/backup.sh                          # default: backs up to ./backups/
#   ./scripts/backup.sh /mnt/backups             # custom destination
#   BACKUP_RETAIN_DAYS=30 ./scripts/backup.sh    # auto-prune backups older than 30 days
#
# Supports both SQLite and PostgreSQL (auto-detected).
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BACKUP_DIR="${1:-${BACKUP_DIR:-$PROJECT_ROOT/backups}}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_NAME="ssp-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"
RETAIN_DAYS="${BACKUP_RETAIN_DAYS:-0}"
INCLUDE_DOT_ENV="${BACKUP_INCLUDE_DOT_ENV:-0}"

# Paths
DATA_DIR="${PROJECT_ROOT}/data"
DB_FILE="${DATA_DIR}/security_scans.db"
REPORTS_DIR="${DATA_DIR}/reports"

# PostgreSQL env vars (from .env or environment)
PG_URL="${DATABASE_URL:-}"
PG_USER="${POSTGRES_USER:-security}"
PG_DB="${POSTGRES_DB:-security_scans}"

mkdir -p "${BACKUP_PATH}"

echo "=== SSP Backup — ${TIMESTAMP} ==="
echo "Destination: ${BACKUP_PATH}"

# ── Database backup ──────────────────────────────────────────────────────────

if [ -n "${PG_URL}" ]; then
    echo "[db] PostgreSQL detected — running pg_dump..."
    # Extract connection components from DATABASE_URL
    # Format: postgresql://user:pass@host:port/dbname
    if command -v pg_dump >/dev/null 2>&1; then
        pg_dump "${PG_URL}" --format=custom --file="${BACKUP_PATH}/database.pgdump" 2>&1
        echo "[db] PostgreSQL dump saved: database.pgdump ($(du -h "${BACKUP_PATH}/database.pgdump" | cut -f1))"
    else
        echo "[db] WARNING: pg_dump not found — attempting via docker..."
        docker compose -f "${PROJECT_ROOT}/docker-compose.yml" exec -T postgres \
            pg_dump -U "${PG_USER}" -Fc "${PG_DB}" > "${BACKUP_PATH}/database.pgdump" 2>/dev/null \
            && echo "[db] PostgreSQL dump saved via docker" \
            || echo "[db] ERROR: Could not dump PostgreSQL database"
    fi
elif [ -f "${DB_FILE}" ]; then
    echo "[db] SQLite detected — creating online backup..."
    # Use .backup command for a consistent snapshot (safe even while the app is running)
    sqlite3 "${DB_FILE}" ".backup '${BACKUP_PATH}/security_scans.db'" 2>&1
    echo "[db] SQLite backup saved: security_scans.db ($(du -h "${BACKUP_PATH}/security_scans.db" | cut -f1))"
else
    echo "[db] WARNING: No database found at ${DB_FILE} and DATABASE_URL is not set"
fi

# ── Reports backup ──────────────────────────────────────────────────────────

if [ -d "${REPORTS_DIR}" ] && [ "$(ls -A "${REPORTS_DIR}" 2>/dev/null)" ]; then
    echo "[reports] Archiving reports directory..."
    tar -czf "${BACKUP_PATH}/reports.tar.gz" -C "${DATA_DIR}" reports 2>&1
    echo "[reports] Reports archived: reports.tar.gz ($(du -h "${BACKUP_PATH}/reports.tar.gz" | cut -f1))"
else
    echo "[reports] No reports directory found — skipping"
fi

# ── Config backup ────────────────────────────────────────────────────────────

if [ -d "${PROJECT_ROOT}/config" ]; then
    cp -r "${PROJECT_ROOT}/config" "${BACKUP_PATH}/config"
    echo "[config] Configuration copied"
fi

if [ -f "${PROJECT_ROOT}/.env" ] && [ "${INCLUDE_DOT_ENV}" = "1" ]; then
    cp "${PROJECT_ROOT}/.env" "${BACKUP_PATH}/dot-env"
    echo "[config] .env copied (as dot-env) because BACKUP_INCLUDE_DOT_ENV=1"
elif [ -f "${PROJECT_ROOT}/.env" ]; then
    echo "[config] Skipping .env backup by default to avoid archiving plaintext secrets"
fi

# ── Compress the backup ─────────────────────────────────────────────────────

echo "[archive] Compressing backup..."
tar -czf "${BACKUP_PATH}.tar.gz" -C "${BACKUP_DIR}" "${BACKUP_NAME}" 2>&1
rm -rf "${BACKUP_PATH}"
FINAL_SIZE="$(du -h "${BACKUP_PATH}.tar.gz" | cut -f1)"
echo "[archive] Final backup: ${BACKUP_PATH}.tar.gz (${FINAL_SIZE})"

# ── Retention pruning ────────────────────────────────────────────────────────

if [ "${RETAIN_DAYS}" -gt 0 ]; then
    echo "[retention] Pruning backups older than ${RETAIN_DAYS} days..."
    PRUNED=$(find "${BACKUP_DIR}" -name 'ssp-backup-*.tar.gz' -mtime "+${RETAIN_DAYS}" -print -delete | wc -l)
    echo "[retention] Removed ${PRUNED} old backup(s)"
fi

echo "=== Backup complete ==="
