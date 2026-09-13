#!/usr/bin/env bash
# Bootstrap inicial: valida requisitos, prepara .env, genera secretos.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/docker/.env"

echo "[+] SOC Lab — setup inicial"

# 1. Chequeo básico
for cmd in docker openssl curl; do
  command -v "$cmd" >/dev/null || { echo "  falta $cmd"; exit 1; }
done
docker compose version >/dev/null || { echo "  falta docker compose"; exit 1; }

# 2. RAM check
mem_gb=$(free -g 2>/dev/null | awk '/^Mem:/ {print $2}')
if [[ -n "${mem_gb:-}" && "$mem_gb" -lt 16 ]]; then
  echo "  [!] Solo ${mem_gb}GB RAM detectados. Recomendado 16GB+."
fi

# 3. Generar .env si no existe
if [[ ! -f "$ENV_FILE" ]]; then
  cp "${ROOT}/docker/.env.example" "$ENV_FILE"
  echo "[+] .env creado desde template"

  # Generar secretos
  splunk_pw=$(openssl rand -base64 12 | tr -d '=+/' | head -c 16)
  hec_token=$(uuidgen 2>/dev/null || openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
  hive_secret=$(openssl rand -base64 64 | tr -d '\n' | head -c 64)
  misp_key=$(openssl rand -hex 20)
  misp_root=$(openssl rand -base64 16 | tr -d '=+/')
  misp_user=$(openssl rand -base64 16 | tr -d '=+/')
  misp_admin=$(openssl rand -base64 12 | tr -d '=+/')

  sed -i.bak \
    -e "s|ChangeMe-Splunk-Str0ng!|${splunk_pw}|" \
    -e "s|00000000-0000-0000-0000-000000000000|${hec_token}|" \
    -e "s|change-me-thehive-secret-64-chars-min|${hive_secret}|" \
    -e "s|ChangeMe-Root-MISP!|${misp_root}|" \
    -e "s|ChangeMe-Misp-User!|${misp_user}|" \
    -e "s|ChangeMe-MISP-Admin!|${misp_admin}|" \
    -e "s|REPLACE_WITH_40_CHAR_RANDOM_STRING_XXXXXX|${misp_key}|" \
    "$ENV_FILE"
  rm -f "${ENV_FILE}.bak"

  cat <<EOF

  Credenciales generadas — guárdalas en un lugar seguro:

    Splunk admin        : ${splunk_pw}
    Splunk HEC token    : ${hec_token}
    MISP admin password : ${misp_admin}
    MISP admin key      : ${misp_key}

  Todo está en docker/.env (NO commitees este archivo).

EOF
else
  echo "[+] .env ya existe — no se sobreescribe"
fi

chmod +x "${ROOT}/scripts/"*.sh

echo "[+] Setup listo. Ejecuta: scripts/deploy.sh"
