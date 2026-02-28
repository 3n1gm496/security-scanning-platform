#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${BASE_DIR}"

LOG_DIR="${BASE_DIR}/data/logs"
mkdir -p "${LOG_DIR}"

./scripts/run_scan.sh --retention-only --settings config/settings.yaml | tee -a "${LOG_DIR}/scheduled-retention.log"
