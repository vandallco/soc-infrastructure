# Reporte de Incidente IR-2026-003

| Campo | Valor |
|-------|-------|
| ID | IR-2026-003 |
| Título | Detección temprana de ransomware — canary file trigger |
| Severidad | Critical |
| Estado | Contenido — evento controlado |
| Reportado por | Correlation search `SOC - UC-006 Ransomware Canary File Mod` |
| Fecha detección | 2026-09-05 22:04 UTC |
| Fecha resolución | 2026-09-06 06:20 UTC |
| Analistas | L1 sguarin, L2 mlopez, L3 fgarcia, CSIRT |
| Playbook | `ransomware-response.md` (crisis mode) |
| Caso TheHive | #TH-2026-234 |

## Resumen ejecutivo

El servidor de archivos `FS-01` sufrió un intento de despliegue de ransomware (variante LockBit-like) originado desde `WKS-115`. Los canary files ubicados en el share `\\FS-01\Compartido\_canary_do_not_touch\` dispararon la alerta UC-006 a los **90 segundos** del inicio del cifrado. Se aisló el host origen y se detuvieron los servicios SMB antes de que el ransomware alcanzara los directorios de negocio. Impacto: **~1.100 archivos cifrados** en el árbol canary (todos señuelos). Ningún dato productivo se vio afectado.

## Kill-chain reconstruida

| Fase | Evidencia |
|------|-----------|
| Acceso inicial | RDP expuesto de `WKS-115` — brute force exitoso 4 días antes (no detectado por gap en logging). |
| Ejecución | `powershell.exe -EncodedCommand` desplegando el binario (UC-003 disparado, pero no escalado). |
| Elevación | Uso de token de admin local reutilizado (LAPS no desplegado en la máquina). |
| Movimiento lateral | SMB mounts a FS-01, FS-02. |
| Impacto | Cifrado iniciado 22:03:12 UTC. Canary trigger 22:04:41 UTC. |

## Timeline

| UTC | Evento |
|-----|--------|
| 22:03:12 | Inicio del cifrado en `\\FS-01\Compartido\_canary_do_not_touch\` |
| 22:04:41 | 47 files renombrados a `.LOCKED` — Splunk dispara UC-006. |
| 22:04:45 | Webhook a TheHive crea caso Critical #TH-2026-234. |
| 22:05:20 | L1 acepta caso; escala inmediatamente a L2 y activa war-room. |
| 22:07 | Se identifica origen: `WKS-115` (172.31.0.115). |
| 22:09 | Aislamiento EDR + `stop-service LanmanServer` en FS-01 y FS-02. |
| 22:11 | Cifrado detenido — 1.100 archivos canary comprometidos, 0 productivos. |
| 22:30 | Snapshot storage congelado (Netapp SnapMirror pausado). |
| 23:15 | Identificado binario `ryuk-clone.exe` en `%TEMP%` de WKS-115. |
| 00:30 | Análisis inicial: variante custom, no coincide firma pública. |
| 03:00 | CSIRT confirma erradicación en WKS-115 (reimagen). |
| 06:20 | Servicios restaurados, caso en post-mortem. |

## Contención

1. EDR quarantine WKS-115 (aislamiento total).
2. `Stop-Service LanmanServer` en FS-01 y FS-02.
3. NetApp snapshot congelado (protege contra replicación del cifrado).
4. Cuenta local `.\admin` deshabilitada en WKS-115.

## Erradicación

1. Reimagen completa de WKS-115.
2. Rotación de credenciales de admin local (política LAPS forzada en todo el parque).
3. Cierre del acceso RDP directo — todo pasa por bastión con MFA a partir de 2026-09-10.

## Recuperación

- 1.100 archivos canary destruidos → sin impacto de negocio (eran señuelos).
- Servicios SMB restaurados a 06:15 UTC tras validación forense.

## Lecciones aprendidas

1. **El canary funcionó — MTTD 90 segundos, MTTR 8 minutos hasta contención.** Salvó la operación.
2. **Gap crítico: brute force RDP no fue detectado** porque la alerta UC-001 no cubría RDP. Se creó UC-011.
3. **LAPS no estaba desplegado en workstations.** Roll-out inmediato.
4. **AppLocker no impedía PowerShell EncodedCommand desde `%TEMP%`.** Política emitida.
5. **Simulacro trimestral de ransomware confirmado** — próximo 2026-10-15.

## Métricas del incidente

| KPI | Valor |
|-----|-------|
| MTTD | 90 s |
| MTTA (analista) | 39 s |
| MTTC (contención) | 8 min |
| MTTR (total) | 8 h 16 min |
| Archivos productivos afectados | 0 |
| Costo estimado (respuesta + downtime) | USD 12.400 |
