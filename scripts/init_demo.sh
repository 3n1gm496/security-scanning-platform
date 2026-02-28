#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${BASE_DIR}"

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

mkdir -p data/reports data/workspaces data/cache/trivy
docker compose build
docker compose up -d dashboard orchestrator

./scripts/run_scan.sh --target-type local --target "${BASE_DIR}/demo/demo-app" --target-name demo-local-app --fail-on-policy-block || true

echo "Demo pronta. Dashboard: http://localhost:${DASHBOARD_PORT:-8080}"
echo "Utente/password: valori definiti nel file .env"
