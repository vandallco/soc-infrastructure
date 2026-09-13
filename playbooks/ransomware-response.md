# Playbook — Respuesta a Ransomware

**Owner:** IR Lead + CSIRT (crisis mode)
**SLA MTTA:** ≤ 5 min · **MTTR contención inicial:** ≤ 30 min
**Trigger:** UC-006 (canary), UC-013 (nota de rescate detectada), reporte usuario

> **NO negociar ni pagar rescate.** Notificar a legal y a las autoridades competentes.

## 1. Detección

- Alerta UC-006 en Splunk.
- Volumen anómalo de renames/writes en shares.
- Notas de rescate (`README.txt`, `HOW_TO_DECRYPT.html`) detectadas por file monitoring.
- Reporte de usuario ("no puedo abrir mis archivos").

## 2. Contención — 0 a 30 min

1. **Aislar hosts afectados** — quarantine VLAN, desconectar NIC, o `Disable-NetAdapter *`.
2. **Bloquear cuentas comprometidas** en AD / IdP.
3. **Congelar snapshots** de todo storage compartido (impedir replicación destructiva).
4. **Cortar accesos VPN** de usuarios sospechosos.
5. **Activar war-room** — canal dedicado (Slack #ir-crisis, puente Zoom).

## 3. Erradicación — 30 min a 8 h

| Paso | Acción |
|------|--------|
| 3.1 | Identificar cepa: hash del binario, extension añadida, nota → **ID-Ransomware**. |
| 3.2 | Buscar vector inicial: phishing (últimos 72h), RDP expuesto, vuln parcheable. |
| 3.3 | Enumerar TODAS las cuentas usadas para desplegar (Sysmon EID 4624/4688). |
| 3.4 | Barrer red: IoCs, hashes, C2 → bloquear en NGFW, DNS RPZ, EDR. |
| 3.5 | Cambiar KRBTGT dos veces (si evidencia de Golden Ticket). |

## 4. Recuperación

1. **Solo desde backups offline validados** — NUNCA restaurar sin escanear.
2. Reconstruir hosts críticos desde imagen limpia.
3. Rotar TODAS las credenciales privilegiadas.
4. Restaurar servicios por tiers (crítico → importante → normal).

## 5. Comunicación

| Audiencia | Cuándo | Canal | Responsable |
|-----------|--------|-------|-------------|
| CISO | Inmediato | Llamada | IR Lead |
| CEO / Junta | ≤ 1 h | Presencial | CISO |
| Legal | ≤ 1 h | Correo + puente | CISO |
| Comunicaciones | ≤ 2 h | Reunión | CEO |
| Autoridad (ej. Fiscalía, CERT nacional) | ≤ 72 h | Reporte formal | Legal |
| Usuarios afectados | Cuando esté controlado | Correo interno | Comunicaciones |

## 6. Post-mortem (≤ 14 días)

- Timeline detallado (kill-chain).
- Controles que fallaron / faltaban.
- Costo total (downtime, recovery, respuesta).
- Plan de mitigación con owners y deadlines.
