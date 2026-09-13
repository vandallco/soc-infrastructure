#!/usr/bin/env bash
# Comprueba salud de todos los servicios del SOC Lab
set -uo pipefail

check() {
  local name=$1 url=$2 pattern=${3:-.}
  printf "  %-14s -> " "$name"
  if curl -sk --max-time 5 "$url" 2>/dev/null | grep -q "$pattern"; then
    echo "OK"
  else
    echo "FAIL"
    return 1
  fi
}

echo "[+] Health-check SOC Lab"
echo ""

check "Splunk Web"    "http://localhost:8000/en-US/account/login"  "Splunk"
check "Splunk API"    "https://localhost:8089/services/server/info" "build"
check "TheHive"       "http://localhost:9000/api/status"           "versions"
check "Cortex"        "http://localhost:9001/api/status"           "versions"
check "MISP"          "https://localhost:8443/users/login"         "MISP"
check "DVWA"          "http://localhost:8080/login.php"            "Damn Vulnerable"

echo ""
echo "[+] Contenedores:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep soc-
