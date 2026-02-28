#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

COMPOSE="docker compose"
DATA_DIR="${ROOT_DIR}/data"
DB_FILE="${DATA_DIR}/security_scans.db"
REPORTS_DIR="${DATA_DIR}/reports"
WORKSPACES_DIR="${DATA_DIR}/workspaces"
CACHE_DIR="${DATA_DIR}/cache"
TRIVY_CACHE_DIR="${CACHE_DIR}/trivy"
BACKUP_DIR="${DATA_DIR}/backups"
TMP_DIR="${DATA_DIR}/tmp"

# ------------------------------
# Colors (ASCII-safe, no Unicode UI)
# ------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_CYAN=""
fi

line() {
  printf '%*s\n' "${COLUMNS:-90}" '' | tr ' ' '-'
}

header() {
  echo
  line
  echo -e "${C_BOLD}${C_CYAN}$1${C_RESET}"
  line
}

info() {
  echo -e "${C_GREEN}[INFO]${C_RESET} $*"
}

warn() {
  echo -e "${C_YELLOW}[WARN]${C_RESET} $*" >&2
}

error() {
  echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2
}

die() {
  error "$*"
  exit 1
}

pause() {
  if [[ -t 0 ]]; then
    echo
    read -r -p "Premi INVIO per continuare..." _
  fi
}

banner() {
  clear 2>/dev/null || true
  cat <<EOF
Security Scanning Platform - Ops Console
Open Source | CI-agnostic
EOF
  line
}

usage() {
  banner
  cat <<EOF

USO
  ./scripts/ops.sh <comando> [opzioni]

COMANDI PRINCIPALI
  up                           Build + start stack
  down                         Stop stack
  restart                      Restart stack
  ps                           Stato container
  logs [service] [--follow]    Log stack o servizio
  health                       Check rapido stack + dashboard
  open                         Apre la dashboard nel browser
  menu                         Menu interattivo

SCAN
  scan demo
  scan local --path PATH --name NAME [--fail] [--json-out FILE]
  scan git   --url URL --name NAME [--ref REF] [--fail] [--json-out FILE]
  scan image --image IMG --name NAME [--fail] [--json-out FILE]
  scan batch --file FILE [--fail] [--json-out FILE]

DB / REPORT
  db tables
  db counts
  db last [N]
  reports list
  reports find-normalized
  reports latest

MANUTENZIONE
  backup
  retention [--days N]
  cache clear-trivy
  reset --yes

DEBUG
  shell orchestrator|dashboard
  versions
  curl

ESEMPI
  ./scripts/ops.sh up
  ./scripts/ops.sh open
  ./scripts/ops.sh scan demo
  ./scripts/ops.sh scan local --path "\$PWD/demo/demo-app" --name demo
  ./scripts/ops.sh scan git --url https://github.com/apache/airflow.git --name airflow --ref main
  ./scripts/ops.sh scan image --image nginx:1.27-alpine --name nginx
  ./scripts/ops.sh db counts
  ./scripts/ops.sh backup

EOF
}

# ------------------------------
# Common helpers
# ------------------------------
ensure_dirs() {
  mkdir -p "${REPORTS_DIR}" "${WORKSPACES_DIR}" "${TRIVY_CACHE_DIR}" "${BACKUP_DIR}" "${TMP_DIR}"
}

ensure_env() {
  if [[ ! -f "${ROOT_DIR}/.env" ]]; then
    if [[ -f "${ROOT_DIR}/.env.example" ]]; then
      cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
      info "Creato .env da .env.example"
    else
      die "Manca .env e anche .env.example"
    fi
  fi
}

require_compose() {
  command -v docker >/dev/null 2>&1 || die "docker non trovato"
  ${COMPOSE} version >/dev/null 2>&1 || die "docker compose non disponibile"
}

require_run_scan() {
  [[ -x "${ROOT_DIR}/scripts/run_scan.sh" ]] || die "scripts/run_scan.sh non trovato o non eseguibile"
}

dashboard_url() {
  local port
  port="$(grep -E '^DASHBOARD_PORT=' "${ROOT_DIR}/.env" 2>/dev/null | cut -d= -f2 || true)"
  [[ -n "${port}" ]] || port="8080"
  echo "http://localhost:${port}"
}

open_url() {
  local url="$1"
  if command -v wslview >/dev/null 2>&1; then
    wslview "${url}" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${url}" >/dev/null 2>&1 || true
  else
    warn "Nessun opener disponibile. Apri manualmente: ${url}"
  fi
}

db_exec_python() {
  local code="$1"
  require_compose
  ${COMPOSE} exec -T dashboard python -c "${code}"
}

latest_summary_report() {
  find "${REPORTS_DIR}" -maxdepth 2 -name summary.json -type f 2>/dev/null | sort | tail -n 1
}

# ------------------------------
# Scan summary
# ------------------------------
render_scan_summary() {
  local json_file="$1"
  [[ -s "${json_file}" ]] || {
    warn "Summary JSON non trovato o vuoto: ${json_file}"
    return 0
  }

  python3 - "$json_file" <<'PY'
import json, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

results = data.get("results", [])
if not results:
    print("Nessun risultato disponibile.")
    sys.exit(0)

for r in results:
    sev = r.get("severity_counts", {}) or {}
    print()
    print("SCAN SUMMARY")
    print("------------")
    print(f"Target        : {r.get('target_name','-')} ({r.get('target_type','-')})")
    print(f"Scan ID       : {r.get('scan_id','-')}")
    print(f"Status        : {r.get('status','UNKNOWN')}")
    print(f"Policy        : {r.get('policy_status','UNKNOWN')}")
    print(f"Findings      : total={len(r.get('findings', []))}  "
          f"critical={sev.get('CRITICAL',0)}  high={sev.get('HIGH',0)}  "
          f"medium={sev.get('MEDIUM',0)}  low={sev.get('LOW',0)}  info={sev.get('INFO',0)}")
    print(f"Normalized    : {r.get('normalized_report_path','-')}")
    if r.get("raw_report_dir"):
        print(f"Raw dir       : {r.get('raw_report_dir')}")
    tools = r.get("tools", [])
    if tools:
        print("Tools:")
        for t in tools:
            status = "OK" if t.get("success") else "ERR"
            print(f"  - {t.get('tool','-'):<12} {status:<3} exit={t.get('exit_code','-')} findings={t.get('finding_count',0)}")
    if r.get("error_message"):
        print(f"Error         : {r.get('error_message')}")
PY
}

run_scan_and_summarize() {
  local label="$1"
  shift

  ensure_dirs

  local ts host_json container_json
  ts="$(date +%Y%m%d-%H%M%S)-$$"
  host_json="${TMP_DIR}/ops-summary-${ts}.json"
  container_json="/data/tmp/ops-summary-${ts}.json"

  header "${label}"
  "$@" --json-output "${container_json}" || true

  if [[ -s "${host_json}" ]]; then
    render_scan_summary "${host_json}"
  else
    warn "Nessun summary prodotto. Controlla i report in ${REPORTS_DIR}"
  fi
}

# ------------------------------
# Stack commands
# ------------------------------
cmd_up() {
  require_compose
  ensure_env
  ensure_dirs
  header "Avvio stack"
  ${COMPOSE} up -d --build
  info "Dashboard: $(dashboard_url)"
}

cmd_down() {
  require_compose
  header "Stop stack"
  ${COMPOSE} down
}

cmd_restart() {
  require_compose
  header "Restart stack"
  ${COMPOSE} restart
}

cmd_ps() {
  require_compose
  header "Container status"
  ${COMPOSE} ps
}

cmd_logs() {
  require_compose
  local svc=""
  local follow="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --follow|-f)
        follow="1"
        shift
        ;;
      *)
        if [[ -z "${svc}" ]]; then
          svc="$1"
          shift
        else
          die "Argomento non valido per logs: $1"
        fi
        ;;
    esac
  done

  if [[ "${follow}" == "1" ]]; then
    header "Logs follow ${svc:-stack}"
    if [[ -n "${svc}" ]]; then
      ${COMPOSE} logs -f "${svc}"
    else
      ${COMPOSE} logs -f
    fi
  else
    header "Logs snapshot ${svc:-stack}"
    if [[ -n "${svc}" ]]; then
      ${COMPOSE} logs --tail 120 "${svc}"
    else
      ${COMPOSE} logs --tail 120
    fi
  fi
}

cmd_health() {
  require_compose
  header "Health check"
  ${COMPOSE} ps
  echo
  info "Dashboard endpoint: $(dashboard_url)"
  curl -I -sS "$(dashboard_url)/" | head -n 10 || true
}

cmd_open() {
  header "Open dashboard"
  local url
  url="$(dashboard_url)"
  info "URL: ${url}"
  open_url "${url}"
}

# ------------------------------
# Scan commands
# ------------------------------
cmd_scan_demo() {
  require_run_scan
  run_scan_and_summarize \
    "Demo scan" \
    ./scripts/run_scan.sh \
    --target-type local \
    --target "${ROOT_DIR}/demo/demo-app" \
    --target-name "demo-local-app"
}

cmd_scan_local() {
  require_run_scan
  ensure_dirs

  local path="" name="" fail="0" json_out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path) path="${2:-}"; shift 2 ;;
      --name) name="${2:-}"; shift 2 ;;
      --fail) fail="1"; shift ;;
      --json-out) json_out="${2:-}"; shift 2 ;;
      *) die "Argomento sconosciuto per scan local: $1" ;;
    esac
  done

  [[ -n "${path}" ]] || die "Manca --path"
  [[ -n "${name}" ]] || die "Manca --name"
  [[ -e "${path}" ]] || die "Path locale non trovato: ${path}"

  if [[ -n "${json_out}" ]]; then
    header "Scan local"
    ./scripts/run_scan.sh \
      --target-type local \
      --target "${path}" \
      --target-name "${name}" \
      ${fail:+--fail-on-policy-block} \
      --json-output "${json_out}" || true
  else
    if [[ "${fail}" == "1" ]]; then
      run_scan_and_summarize \
        "Scan local" \
        ./scripts/run_scan.sh \
        --target-type local \
        --target "${path}" \
        --target-name "${name}" \
        --fail-on-policy-block
    else
      run_scan_and_summarize \
        "Scan local" \
        ./scripts/run_scan.sh \
        --target-type local \
        --target "${path}" \
        --target-name "${name}"
    fi
  fi
}

cmd_scan_git() {
  require_run_scan
  ensure_dirs

  local url="" name="" ref="" fail="0" json_out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --url) url="${2:-}"; shift 2 ;;
      --name) name="${2:-}"; shift 2 ;;
      --ref) ref="${2:-}"; shift 2 ;;
      --fail) fail="1"; shift ;;
      --json-out) json_out="${2:-}"; shift 2 ;;
      *) die "Argomento sconosciuto per scan git: $1" ;;
    esac
  done

  [[ -n "${url}" ]] || die "Manca --url"
  [[ -n "${name}" ]] || die "Manca --name"

  if [[ -n "${json_out}" ]]; then
    header "Scan git"
    local args=(--target-type git --target "${url}" --target-name "${name}")
    [[ -n "${ref}" ]] && args+=(--ref "${ref}")
    [[ "${fail}" == "1" ]] && args+=(--fail-on-policy-block)
    args+=(--json-output "${json_out}")
    ./scripts/run_scan.sh "${args[@]}" || true
  else
    local args=(./scripts/run_scan.sh --target-type git --target "${url}" --target-name "${name}")
    [[ -n "${ref}" ]] && args+=(--ref "${ref}")
    [[ "${fail}" == "1" ]] && args+=(--fail-on-policy-block)
    run_scan_and_summarize "Scan git" "${args[@]}"
  fi
}

cmd_scan_image() {
  require_run_scan
  ensure_dirs

  local image="" name="" fail="0" json_out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --image) image="${2:-}"; shift 2 ;;
      --name) name="${2:-}"; shift 2 ;;
      --fail) fail="1"; shift ;;
      --json-out) json_out="${2:-}"; shift 2 ;;
      *) die "Argomento sconosciuto per scan image: $1" ;;
    esac
  done

  [[ -n "${image}" ]] || die "Manca --image"
  [[ -n "${name}" ]] || die "Manca --name"

  if [[ -n "${json_out}" ]]; then
    header "Scan image"
    local args=(--target-type image --target "${image}" --target-name "${name}")
    [[ "${fail}" == "1" ]] && args+=(--fail-on-policy-block)
    args+=(--json-output "${json_out}")
    ./scripts/run_scan.sh "${args[@]}" || true
  else
    local args=(./scripts/run_scan.sh --target-type image --target "${image}" --target-name "${name}")
    [[ "${fail}" == "1" ]] && args+=(--fail-on-policy-block)
    run_scan_and_summarize "Scan image" "${args[@]}"
  fi
}

cmd_scan_batch() {
  require_run_scan
  ensure_dirs

  local file="" fail="0" json_out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --file) file="${2:-}"; shift 2 ;;
      --fail) fail="1"; shift ;;
      --json-out) json_out="${2:-}"; shift 2 ;;
      *) die "Argomento sconosciuto per scan batch: $1" ;;
    esac
  done

  [[ -n "${file}" ]] || die "Manca --file"
  [[ -f "${file}" ]] || die "File target non trovato: ${file}"

  if [[ -n "${json_out}" ]]; then
    header "Batch scan"
    local args=(--targets-file "${file}")
    [[ "${fail}" == "1" ]] && args+=(--fail-on-policy-block)
    args+=(--json-output "${json_out}")
    ./scripts/run_scan.sh "${args[@]}" || true
  else
    local args=(./scripts/run_scan.sh --targets-file "${file}")
    [[ "${fail}" == "1" ]] && args+=(--fail-on-policy-block)
    run_scan_and_summarize "Batch scan" "${args[@]}"
  fi
}

# ------------------------------
# DB / Reports
# ------------------------------
cmd_db_tables() {
  header "Tabelle SQLite"
  db_exec_python 'import sqlite3; c=sqlite3.connect("/data/security_scans.db"); print(c.execute("SELECT name FROM sqlite_master WHERE type='\''table'\'' ORDER BY name").fetchall())'
}

cmd_db_counts() {
  header "Conteggi DB"
  db_exec_python 'import sqlite3; c=sqlite3.connect("/data/security_scans.db"); scans=c.execute("select count(*) from scans").fetchone()[0]; findings=c.execute("select count(*) from findings").fetchone()[0]; print({"scans": scans, "findings": findings})'
}

cmd_db_last() {
  local limit="${1:-10}"
  header "Ultime ${limit} scansioni"
  db_exec_python "import sqlite3; c=sqlite3.connect('/data/security_scans.db'); rows=c.execute('select id,target_name,status,policy_status,created_at from scans order by created_at desc limit ${limit}').fetchall(); [print(r) for r in rows]"
}

cmd_reports_list() {
  header "Cartelle report"
  ls -la "${REPORTS_DIR}" || true
}

cmd_reports_find_normalized() {
  header "Normalized reports"
  find "${REPORTS_DIR}" -maxdepth 3 -name normalized_findings.json -print || true
}

cmd_reports_latest() {
  header "Latest summary"
  local latest
  latest="$(latest_summary_report || true)"
  if [[ -z "${latest}" ]]; then
    warn "Nessun summary.json trovato"
    return 0
  fi
  info "File: ${latest}"
  python3 -m json.tool "${latest}" | head -n 100 || cat "${latest}"
}

# ------------------------------
# Maintenance
# ------------------------------
cmd_backup() {
  ensure_dirs
  header "Backup"

  local ts db_backup reports_backup
  ts="$(date +%Y%m%d-%H%M%S)"
  db_backup="${BACKUP_DIR}/security_scans-${ts}.db"
  reports_backup="${BACKUP_DIR}/reports-${ts}.tgz"

  if [[ -f "${DB_FILE}" ]]; then
    cp "${DB_FILE}" "${db_backup}"
    info "DB backup: ${db_backup}"
  else
    warn "DB non trovato: ${DB_FILE}"
  fi

  tar -czf "${reports_backup}" -C "${DATA_DIR}" reports
  info "Reports backup: ${reports_backup}"
}

cmd_retention() {
  ensure_dirs
  local days="${1:-30}"
  [[ "${days}" =~ ^[0-9]+$ ]] || die "Il parametro days deve essere numerico"

  header "Retention cleanup"
  info "Cancello report più vecchi di ${days} giorni"
  find "${REPORTS_DIR}" -mindepth 1 -maxdepth 1 -type d -mtime "+${days}" -exec rm -rf {} \; || true
  info "Cleanup completato"
}

cmd_cache_clear_trivy() {
  ensure_dirs
  header "Pulizia cache Trivy"
  rm -rf "${TRIVY_CACHE_DIR:?}/"* || true
  info "Cache pulita"
}

cmd_reset() {
  local confirm="${1:-}"
  [[ "${confirm}" == "--yes" ]] || die "Per reset serve: reset --yes"

  require_compose
  header "RESET COMPLETO"
  warn "Sto cancellando DB, report e workspace"

  ${COMPOSE} down || true
  rm -rf "${DB_FILE}" "${REPORTS_DIR}" "${WORKSPACES_DIR}"
  ensure_dirs
  ${COMPOSE} up -d --build

  info "Reset completato"
}

# ------------------------------
# Debug
# ------------------------------
cmd_shell() {
  require_compose
  local svc="${1:-}"
  [[ -n "${svc}" ]] || die "Specifica il servizio: orchestrator o dashboard"
  header "Shell su ${svc}"
  ${COMPOSE} exec "${svc}" sh
}

cmd_versions() {
  require_compose
  header "Versioni tool"
  ${COMPOSE} run --rm --entrypoint sh orchestrator -lc '
    echo "semgrep:" && semgrep --version &&
    echo "bandit:" && bandit --version &&
    echo "nuclei:" && nuclei -version || true &&
    echo "trivy:" && trivy --version &&
    echo "gitleaks:" && gitleaks version &&
    echo "checkov:" && checkov --version &&
    echo "grype:" && grype version || true &&
    echo "zap-cli:" && zap-cli --version || true &&
    echo "syft:" && syft version
  '
}

cmd_curl() {
  header "HTTP check dashboard"
  curl -i -sS "$(dashboard_url)/" | head -n 20 || true
}

# ------------------------------
# Interactive menus
# ------------------------------
menu_scan() {
  while true; do
    banner
    cat <<EOF
SCAN MENU
1) Demo scan
2) Scan local path
3) Scan Git remoto
4) Scan immagine container
5) Scan batch da targets file
0) Torna al menu principale
EOF
    echo
    read -r -p "Seleziona: " choice

    case "${choice}" in
      1)
        cmd_scan_demo
        pause
        ;;
      2)
        local path name
        read -r -p "Path locale: " path
        read -r -p "Nome target: " name
        cmd_scan_local --path "${path}" --name "${name}"
        pause
        ;;
      3)
        local url name ref
        read -r -p "URL repo Git: " url
        read -r -p "Nome target: " name
        read -r -p "Ref (invio per default): " ref
        if [[ -n "${ref}" ]]; then
          cmd_scan_git --url "${url}" --name "${name}" --ref "${ref}"
        else
          cmd_scan_git --url "${url}" --name "${name}"
        fi
        pause
        ;;
      4)
        local image name
        read -r -p "Image ref: " image
        read -r -p "Nome target: " name
        cmd_scan_image --image "${image}" --name "${name}"
        pause
        ;;
      5)
        local file
        read -r -p "Targets file: " file
        cmd_scan_batch --file "${file}"
        pause
        ;;
      0) return 0 ;;
      *) warn "Scelta non valida"; sleep 1 ;;
    esac
  done
}

menu_db() {
  while true; do
    banner
    cat <<EOF
DB / REPORT MENU
1) Conteggi DB
2) Ultime 10 scansioni
3) Tabelle SQLite
4) Lista cartelle report
5) Cerca normalized reports
6) Mostra latest summary
0) Torna al menu principale
EOF
    echo
    read -r -p "Seleziona: " choice
    case "${choice}" in
      1) cmd_db_counts; pause ;;
      2) cmd_db_last 10; pause ;;
      3) cmd_db_tables; pause ;;
      4) cmd_reports_list; pause ;;
      5) cmd_reports_find_normalized; pause ;;
      6) cmd_reports_latest; pause ;;
      0) return 0 ;;
      *) warn "Scelta non valida"; sleep 1 ;;
    esac
  done
}

menu_maintenance() {
  while true; do
    banner
    cat <<EOF
MANUTENZIONE MENU
1) Backup DB + reports
2) Retention cleanup
3) Clear Trivy cache
4) Reset completo
0) Torna al menu principale
EOF
    echo
    read -r -p "Seleziona: " choice
    case "${choice}" in
      1) cmd_backup; pause ;;
      2)
        local days
        read -r -p "Cancella report più vecchi di quanti giorni? [30]: " days
        [[ -n "${days}" ]] || days="30"
        cmd_retention "${days}"
        pause
        ;;
      3) cmd_cache_clear_trivy; pause ;;
      4)
        read -r -p "Sei sicuro? Digita YES per confermare: " confirm
        if [[ "${confirm}" == "YES" ]]; then
          cmd_reset --yes
        else
          warn "Reset annullato"
        fi
        pause
        ;;
      0) return 0 ;;
      *) warn "Scelta non valida"; sleep 1 ;;
    esac
  done
}

menu_debug() {
  while true; do
    banner
    cat <<EOF
DEBUG MENU
1) Logs dashboard (snapshot)
2) Logs orchestrator (snapshot)
3) Tool versions
4) Health check
5) Open dashboard
0) Torna al menu principale
EOF
    echo
    read -r -p "Seleziona: " choice
    case "${choice}" in
      1) cmd_logs dashboard; pause ;;
      2) cmd_logs orchestrator; pause ;;
      3) cmd_versions; pause ;;
      4) cmd_health; pause ;;
      5) cmd_open; pause ;;
      0) return 0 ;;
      *) warn "Scelta non valida"; sleep 1 ;;
    esac
  done
}

cmd_menu() {
  while true; do
    banner
    cat <<EOF
MAIN MENU
1) Avvia stack
2) Stato container
3) Scan
4) DB / Reports
5) Manutenzione
6) Debug
7) Apri dashboard
8) Help
0) Esci
EOF
    echo
    read -r -p "Seleziona: " choice

    case "${choice}" in
      1) cmd_up; pause ;;
      2) cmd_ps; pause ;;
      3) menu_scan ;;
      4) menu_db ;;
      5) menu_maintenance ;;
      6) menu_debug ;;
      7) cmd_open; pause ;;
      8) usage; pause ;;
      0) clear 2>/dev/null || true; exit 0 ;;
      *) warn "Scelta non valida"; sleep 1 ;;
    esac
  done
}

# ------------------------------
# Router
# ------------------------------
main() {
  local cmd="${1:-menu}"
  shift || true

  case "${cmd}" in
    help|-h|--help)
      usage
      ;;
    menu)
      cmd_menu
      ;;
    up)
      cmd_up
      ;;
    down)
      cmd_down
      ;;
    restart)
      cmd_restart
      ;;
    ps)
      cmd_ps
      ;;
    logs)
      cmd_logs "$@"
      ;;
    health)
      cmd_health
      ;;
    open)
      cmd_open
      ;;
    scan)
      local sub="${1:-}"; shift || true
      case "${sub}" in
        demo) cmd_scan_demo ;;
        local) cmd_scan_local "$@" ;;
        git) cmd_scan_git "$@" ;;
        image) cmd_scan_image "$@" ;;
        batch) cmd_scan_batch "$@" ;;
        *) die "Sottocomando scan non valido: ${sub}" ;;
      esac
      ;;
    db)
      local sub="${1:-}"; shift || true
      case "${sub}" in
        tables) cmd_db_tables ;;
        counts) cmd_db_counts ;;
        last) cmd_db_last "${1:-10}" ;;
        *) die "Sottocomando db non valido: ${sub}" ;;
      esac
      ;;
    reports)
      local sub="${1:-}"; shift || true
      case "${sub}" in
        list) cmd_reports_list ;;
        find-normalized) cmd_reports_find_normalized ;;
        latest) cmd_reports_latest ;;
        *) die "Sottocomando reports non valido: ${sub}" ;;
      esac
      ;;
    backup)
      cmd_backup
      ;;
    retention)
      if [[ "${1:-}" == "--days" ]]; then
        cmd_retention "${2:-30}"
      else
        cmd_retention "30"
      fi
      ;;
    cache)
      local sub="${1:-}"; shift || true
      case "${sub}" in
        clear-trivy) cmd_cache_clear_trivy ;;
        *) die "Sottocomando cache non valido: ${sub}" ;;
      esac
      ;;
    reset)
      cmd_reset "${1:-}"
      ;;
    shell)
      cmd_shell "${1:-}"
      ;;
    versions)
      cmd_versions
      ;;
    curl)
      cmd_curl
      ;;
    *)
      die "Comando non valido: ${cmd}. Usa ./scripts/ops.sh help"
      ;;
  esac
}

main "$@"
