# Playbook — Tráfico saliente sospechoso / C2 beacon

**Owner:** SOC L2
**Trigger:** UC-004 (DNS exfil), UC-007 (MISP IoC), Suricata SID 90000xx

## 1. Triaje

1. Identificar `src_ip` (host) + proceso responsable (Sysmon EID 3 / EDR).
2. Enriquecer destino: reputación, WHOIS, resolución histórica (PDNS).
3. Analizar patrón: frecuencia, jitter, tamaño → indicador de beacon.

## 2. Contención

- Bloquear el destino en NGFW y DNS RPZ.
- Aislar host origen.

## 3. Erradicación

- Identificar y remover el implante.
- Rotar credenciales potencialmente exfiltradas.

## 4. Threat Intel

- Publicar el IoC en MISP con TLP:AMBER + sightings.
- Notificar a peer-SOC / ISAC si aplica.

## 5. Métricas

- Volumen bytes exfiltrados (estimación bruta).
- Duración del beacon antes de detección.
- Vector inicial (a rastrear).
