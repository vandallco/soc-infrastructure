#!/usr/bin/env bash
# =====================================================================
#  SOC Lab — despliegue completo
# =====================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/docker"

echo "[+] Verificando dependencias..."
for cmd in docker; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Falta $cmd"; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "Falta docker compose plugin"; exit 1; }

if [[ ! -f .env ]]; then
  echo "[!] .env no encontrado. Copiando .env.example..."
  cp .env.example .env
  echo "[!] Edita docker/.env y vuelve a ejecutar."
  exit 1
fi

echo "[+] Ajustando límites de kernel (requiere sudo)..."
sudo sysctl -w vm.max_map_count=524288 >/dev/null
sudo sysctl -w fs.file-max=131072 >/dev/null

echo "[+] Levantando el stack..."
docker compose pull
docker compose up -d

echo "[+] Esperando salud de Splunk (puede tardar 3-5 min la primera vez)..."
for i in $(seq 1 60); do
  if curl -sk https://localhost:8089/services/server/info | grep -q build; then
    echo "[+] Splunk arriba."
    break
  fi
  sleep 10
done

echo "[+] Ejecutando health-check..."
"${ROOT}/scripts/health-check.sh"

cat <<EOF

===============================================================
  SOC Lab desplegado.

  Splunk    : http://localhost:8000   (admin / <SPLUNK_PASSWORD>)
  TheHive   : http://localhost:9000
  Cortex    : http://localhost:9001
  MISP      : https://localhost:8443  (admin@admin.test / admin)
  DVWA      : http://localhost:8080   (admin / password)

  Próximos pasos:
    1. Abrir Cortex, crear org + user, obtener API key.
    2. Actualizar CORTEX_API_KEY en docker/.env y reiniciar TheHive.
    3. Importar la app soc_app en Splunk (ya está montada).
    4. Correr: scripts/generate-test-events.sh
===============================================================
EOF
