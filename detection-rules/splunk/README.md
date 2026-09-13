# Reglas de detección — Splunk

Las correlation searches viven en [splunk/apps/soc_app/default/savedsearches.conf](../../splunk/apps/soc_app/default/savedsearches.conf). Este directorio contiene copias standalone en formato SPL para revisión de código, versionado y traducción a otros SIEMs.

| Archivo | Caso de uso | MITRE |
|---------|-------------|-------|
| [uc001_ssh_brute_force.spl](uc001_ssh_brute_force.spl) | Brute force SSH | T1110.001 |
| [uc002_lateral_smb.spl](uc002_lateral_smb.spl) | Lateral movement SMB | T1021.002 |
| [uc003_powershell_enc.spl](uc003_powershell_enc.spl) | PowerShell ofuscado | T1059.001 |
| [uc004_dns_tunneling.spl](uc004_dns_tunneling.spl) | Exfiltración DNS | T1048.003 |
| [uc005_scheduled_task.spl](uc005_scheduled_task.spl) | Persistencia tarea | T1053.005 |
| [uc006_ransomware_canary.spl](uc006_ransomware_canary.spl) | Ransomware | T1486 |
| [uc007_c2_beacon_misp.spl](uc007_c2_beacon_misp.spl) | Beacon C2 | T1071.001 |
| [uc008_nmap_scan.spl](uc008_nmap_scan.spl) | Nmap discovery | T1046 |
