#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${BASE_DIR}"

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

mkdir -p data/reports data/workspaces data/cache/trivy

ARGS=("$@")
EXTRA_VOLUMES=()

# Mount entire project read-only to make demo/local usage painless
EXTRA_VOLUMES+=(--volume "${BASE_DIR}:${BASE_DIR}:ro")

TARGET_TYPE=""
TARGET_VALUE=""
HAS_SETTINGS="0"

for ((i=0; i<${#ARGS[@]}; i++)); do
  case "${ARGS[$i]}" in
    --target-type)
      TARGET_TYPE="${ARGS[$((i+1))]}"
      ;;
    --target)
      TARGET_VALUE="${ARGS[$((i+1))]}"
      ;;
    --settings)
      HAS_SETTINGS="1"
      ;;
  esac
done

if [[ "${TARGET_TYPE}" == "local" && -n "${TARGET_VALUE}" ]]; then
  ABS_TARGET="$(realpath "${TARGET_VALUE}")"
  EXTRA_VOLUMES+=(--volume "${ABS_TARGET}:${ABS_TARGET}:ro")
fi

# Add default settings file if not specified
if [[ "${HAS_SETTINGS}" == "0" && -f "${BASE_DIR}/config/settings.yaml" ]]; then
  ARGS+=(--settings config/settings.yaml)
fi

docker compose run --rm \
  "${EXTRA_VOLUMES[@]}" \
  orchestrator \
  "${ARGS[@]}"
