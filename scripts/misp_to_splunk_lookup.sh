#!/usr/bin/env bash
# =====================================================================
#  Sincroniza IoCs de MISP → lookup CSV de Splunk
#  Ejecutar por cron cada 30 min.
# =====================================================================
set -euo pipefail

MISP_URL=${MISP_URL:-https://localhost:8443}
MISP_KEY=${MISP_KEY:-$(grep MISP_ADMIN_KEY ../docker/.env | cut -d= -f2)}
LOOKUP=${LOOKUP:-../splunk/apps/soc_app/lookups/misp_iocs.csv}

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "value,type,threat_type,category,ioc_confidence,source,first_seen" > "$TMP"

for T in ip-dst domain md5 sha256; do
  echo "[+] Descargando type=$T"
  curl -sk -X POST "${MISP_URL}/attributes/restSearch" \
    -H "Authorization: ${MISP_KEY}" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{\"returnFormat\":\"json\",\"type\":\"${T}\",\"to_ids\":1}" | \
  jq -r --arg type "$T" '
    .response.Attribute[]? |
    [ .value,
      $type,
      (.Tag[]? | select(.name | startswith("threat-type=")).name | sub("threat-type="; "")),
      (.category // "unknown"),
      (.to_ids // 50),
      "misp",
      (.first_seen // .timestamp | tonumber | strftime("%Y-%m-%d"))
    ] | @csv' >> "$TMP"
done

# Deduplicar por value
awk -F, '!seen[$1]++' "$TMP" > "$LOOKUP"

echo "[+] $(wc -l < "$LOOKUP") IoCs escritos a $LOOKUP"
