# Mapeo MITRE ATT&CK — Cobertura del SOC Lab

Este documento mapea cada detección implementada al framework MITRE ATT&CK v14 y muestra la cobertura del SOC por táctica.

## Cobertura por táctica

| Táctica | UCs cubiertos | Cobertura |
|---------|---------------|-----------|
| Initial Access (TA0001) | (parcial via UC-007 phishing chain) | ●○○ |
| Execution (TA0002) | UC-003 | ●●○ |
| Persistence (TA0003) | UC-005 | ●●○ |
| Privilege Escalation (TA0004) | — | ○○○ |
| Defense Evasion (TA0005) | UC-003 (parcial) | ●○○ |
| Credential Access (TA0006) | UC-001 | ●●○ |
| Discovery (TA0007) | UC-008 | ●●○ |
| Lateral Movement (TA0008) | UC-002 | ●●○ |
| Collection (TA0009) | — | ○○○ |
| Command and Control (TA0011) | UC-007 | ●●● |
| Exfiltration (TA0010) | UC-004 | ●●○ |
| Impact (TA0040) | UC-006 | ●●● |

## Detalle por técnica

| Técnica | Nombre | Detección | Fuente | Confianza |
|---------|--------|-----------|--------|-----------|
| T1046 | Network Service Discovery | UC-008 + Suricata SID 9000001 | eve.json alert | Alta |
| T1053.005 | Scheduled Task | UC-005 | Windows Sec 4698/4702 | Media |
| T1059.001 | PowerShell | UC-003 | Sysmon 1 + Suricata SID 9000030 | Alta |
| T1071.001 | Web Protocols (C2) | UC-007 | Suricata HTTP + MISP lookup | Muy alta |
| T1021.002 | SMB/Admin Shares | UC-002 | Windows Sec 4624 t3 + Suricata SID 9000060 | Media |
| T1048.003 | Exfil Non-C2 (DNS) | UC-004 | Suricata DNS SID 9000021 | Media |
| T1110.001 | Password Guessing | UC-001 | linux:auth + Suricata SID 9000010 | Alta |
| T1190 | Exploit Public Web | (Suricata SID 9000050) | eve.json | Media |
| T1486 | Data Encrypted for Impact | UC-006 | File monitoring canary | Muy alta |
| T1505.003 | Web Shell | (Suricata SID 9000031) | HTTP alerts | Media |
| T1041 | Exfil over C2 | (Suricata SID 9000040) | flow logs | Baja |
| T1071 | App Layer Protocol | (Suricata SID 9000020) | HTTP UA | Baja |

## Roadmap de nuevos casos de uso

Prioridad para el próximo trimestre:

1. **T1078** — Cuentas válidas: detectar logins geo-imposibles.
2. **T1003** — OS Credential Dumping: alertas por acceso a `lsass.exe`.
3. **T1552** — Credentials in Files: hunt por AWS keys / GitHub tokens en logs.
4. **T1204** — User Execution: correlacionar clic en URL sospechosa → download.
5. **T1547** — Boot/Logon Autostart: monitorear registro Run keys.
6. **T1055** — Process Injection (Sysmon EID 8/10).

## Referencias externas

- [MITRE ATT&CK v14](https://attack.mitre.org)
- [ATT&CK Navigator layer](https://mitre-attack.github.io/attack-navigator/)
- [SplunkBase — MITRE ATT&CK App](https://splunkbase.splunk.com/app/4617)
- [Sigma rules — SigmaHQ](https://github.com/SigmaHQ/sigma)
