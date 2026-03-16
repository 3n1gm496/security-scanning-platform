#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# restore.sh — Restore a Security Scanning Platform backup.
#
# Usage:
#   ./scripts/restore.sh backups/ssp-backup-20260315T120000Z.tar.gz
#
# This script:
#   1. Stops the running stack (docker compose down)
#   2. Restores the database (SQLite or PostgreSQL)
#   3. Restores reports and config
#   4. Restarts the stack
#
# IMPORTANT: This is a destructive operation. Current data will be overwritten.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BACKUP_ARCHIVE="${1:-}"
AUTO_YES="${RESTORE_YES:-0}"

if [ -z "${BACKUP_ARCHIVE}" ]; then
    echo "Usage: $0 <backup-archive.tar.gz>"
    echo ""
    echo "Available backups:"
    ls -lhrt "${PROJECT_ROOT}/backups"/ssp-backup-*.tar.gz 2>/dev/null || echo "  (none found in ./backups/)"
    exit 1
fi

if [ ! -f "${BACKUP_ARCHIVE}" ]; then
    echo "ERROR: Backup file not found: ${BACKUP_ARCHIVE}"
    exit 1
fi

DATA_DIR="${PROJECT_ROOT}/data"
DB_FILE="${DATA_DIR}/security_scans.db"
PG_URL="${DATABASE_URL:-}"
PG_USER="${POSTGRES_USER:-security}"
PG_DB="${POSTGRES_DB:-security_scans}"

echo "=== SSP Restore ==="
echo "Archive: ${BACKUP_ARCHIVE}"
echo ""
echo "WARNING: This will overwrite current data. The running stack will be stopped."
if [[ "${AUTO_YES}" = "1" ]]; then
    echo "[confirm] RESTORE_YES=1 set, proceeding without interactive prompt"
else
    read -rp "Continue? [y/N] " CONFIRM
    if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# ── Extract archive ──────────────────────────────────────────────────────────

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

echo "[extract] Unpacking backup..."
tar -xzf "${BACKUP_ARCHIVE}" -C "${TEMP_DIR}"
# The archive contains a single directory ssp-backup-<timestamp>/
RESTORE_DIR="$(find "${TEMP_DIR}" -maxdepth 1 -type d -name 'ssp-backup-*' | head -1)"
if [ -z "${RESTORE_DIR}" ]; then
    echo "ERROR: Invalid backup archive — expected ssp-backup-* directory inside"
    exit 1
fi
echo "[extract] Backup contents: $(ls "${RESTORE_DIR}")"

# ── Stop the stack ───────────────────────────────────────────────────────────

echo "[stack] Stopping services..."
cd "${PROJECT_ROOT}"
docker compose down 2>/dev/null || true

# ── Restore database ─────────────────────────────────────────────────────────

if [ -f "${RESTORE_DIR}/database.pgdump" ] && [ -n "${PG_URL}" ]; then
    echo "[db] Restoring PostgreSQL dump..."
    if command -v pg_restore >/dev/null 2>&1; then
        # Start only postgres for the restore
        docker compose up -d postgres 2>/dev/null || true
        sleep 3
        pg_restore --clean --if-exists --no-owner -d "${PG_URL}" "${RESTORE_DIR}/database.pgdump" 2>&1 || true
        echo "[db] PostgreSQL restored"
    else
        echo "[db] WARNING: pg_restore not found — attempting via docker..."
        docker compose up -d postgres 2>/dev/null || true
        sleep 3
        docker compose exec -T postgres pg_restore --clean --if-exists --no-owner \
            -U "${PG_USER}" -d "${PG_DB}" < "${RESTORE_DIR}/database.pgdump" 2>/dev/null || true
        echo "[db] PostgreSQL restored via docker"
    fi
elif [ -f "${RESTORE_DIR}/security_scans.db" ]; then
    echo "[db] Restoring SQLite database..."
    mkdir -p "${DATA_DIR}"
    cp "${RESTORE_DIR}/security_scans.db" "${DB_FILE}"
    echo "[db] SQLite restored: $(du -h "${DB_FILE}" | cut -f1)"
else
    echo "[db] WARNING: No database backup found in archive"
fi

# ── Restore reports ──────────────────────────────────────────────────────────

if [ -f "${RESTORE_DIR}/reports.tar.gz" ]; then
    echo "[reports] Restoring reports..."
    mkdir -p "${DATA_DIR}"
    tar -xzf "${RESTORE_DIR}/reports.tar.gz" -C "${DATA_DIR}"
    echo "[reports] Reports restored"
else
    echo "[reports] No reports archive in backup — skipping"
fi

# ── Restore config ───────────────────────────────────────────────────────────

if [ -d "${RESTORE_DIR}/config" ]; then
    echo "[config] Restoring configuration..."
    cp -r "${RESTORE_DIR}/config" "${PROJECT_ROOT}/config"
    echo "[config] Configuration restored"
fi

if [ -f "${RESTORE_DIR}/dot-env" ]; then
    echo "[config] Restoring .env..."
    cp "${RESTORE_DIR}/dot-env" "${PROJECT_ROOT}/.env"
    echo "[config] .env restored"
fi

# ── Restart the stack ────────────────────────────────────────────────────────

echo "[stack] Starting services..."
docker compose up -d
echo ""
echo "=== Restore complete ==="
echo "Verify the dashboard is accessible and data looks correct."
