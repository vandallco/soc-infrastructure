# Reporte de Incidente IR-2026-001

| Campo | Valor |
|-------|-------|
| ID | IR-2026-001 |
| Título | Fuerza bruta SSH masiva contra bastión-01 |
| Severidad | High |
| Estado | Contenido / Cerrado |
| Reportado por | Correlation search `SOC - UC-001 SSH Brute Force` |
| Fecha detección | 2026-08-14 03:12 UTC |
| Fecha resolución | 2026-08-14 04:47 UTC |
| Analista L1 | jperez |
| Analista L2 | mlopez |
| Playbook usado | `brute-force-response.md` |
| Caso TheHive | #TH-2026-118 |

## Resumen ejecutivo

Se detectaron 1.243 intentos fallidos de autenticación SSH provenientes de la IP `193.32.162.157` (categorizada como *mass-scanner* en MISP) contra `bastion-01.soc.lab` (172.30.0.5) entre las 03:04 y 03:41 UTC. Ningún intento fue exitoso. Se bloqueó la IP en el firewall perimetral y se añadió a la lista negra permanente.

## Kill-chain observada

| Etapa | Actividad |
|-------|-----------|
| Reconocimiento | Escaneo TCP/22 previo desde el mismo /24 (Suricata SID 9000001, 03:02 UTC). |
| Weaponization | N/A (uso directo de wordlist genérica) |
| Delivery | Conexiones TCP directas al puerto 22. |
| Exploitation | Intentos con usuarios `root`, `admin`, `oracle`, `postgres`, `git`, `ubuntu`. |
| Installation | No lograda. |

## Timeline

| UTC | Evento |
|-----|--------|
| 03:02 | Suricata detecta escaneo SYN masivo (SID 9000001). |
| 03:04 | Primer intento SSH fallido. |
| 03:12 | Splunk dispara alerta UC-001 (10+ fallos en 5 min). |
| 03:14 | L1 jperez acepta caso #TH-2026-118. |
| 03:19 | Cortex confirma IP en AbuseIPDB (score 100/100). |
| 03:22 | Escalado a L2. |
| 03:34 | Bloqueo perimetral aplicado (ACL en NGFW). |
| 03:41 | Últimos intentos observados. |
| 04:47 | Caso cerrado con lecciones aprendidas. |

## Evidencias

- Consulta SPL: `index=soc_endpoints src_ip=193.32.162.157 status=Failed earliest=-6h`
- Cantidad de intentos: **1.243**
- Usuarios probados: 47 únicos (top 5: `root`, `admin`, `test`, `ubuntu`, `oracle`)
- Tasa: ~40 intentos/min

## Contención aplicada

1. `iptables -A INPUT -s 193.32.162.157 -j DROP` en bastión (temporal).
2. Bloqueo ACL en NGFW perimetral (permanente).
3. IP añadida a `soc_app/lookups/blocked_ips.csv`.

## Erradicación y recuperación

No aplicable — no hubo compromiso. Se validó que `fail2ban` estaba activo y funcionando (bloqueó 4 IPs adicionales durante la campaña).

## Lecciones aprendidas

1. **MTTD (5 min) dentro de SLA.** MTTR total (1h35m) también dentro de SLA.
2. **Hallazgo:** el bastión permitía login con `PermitRootLogin yes`. Se corrigió a `prohibit-password`.
3. **Acción de mejora:** el whitelist de escaneres autorizados no incluía la IP corporativa de Qualys — se generó un falso positivo la semana previa. Actualizado.

## IoCs

| Tipo | Valor | Fuente |
|------|-------|--------|
| ip | 193.32.162.157 | AbuseIPDB, MISP |
| user-agent | libssh_0.9.4 | Suricata |
