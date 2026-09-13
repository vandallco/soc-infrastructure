# Casos de uso — MITRE ATT&CK

Ocho casos de uso operacionales del SOC. Cada ficha incluye:
1. Contexto y superficie de ataque
2. Táctica y técnica MITRE ATT&CK
3. Fuentes de datos requeridas
4. Lógica de detección (SPL / regla)
5. Respuesta esperada del analista (nivel L1/L2/L3)
6. Falsos positivos conocidos
7. Cómo simular / testear la detección

| ID | Nombre | Táctica | Técnica | Severidad |
|----|--------|---------|---------|-----------|
| [UC-001](UC-001-ssh-brute-force.md) | SSH Brute Force | Credential Access | T1110.001 | High |
| [UC-002](UC-002-lateral-movement-smb.md) | Lateral Movement SMB | Lateral Movement | T1021.002 | High |
| [UC-003](UC-003-powershell-obfuscated.md) | PowerShell ofuscado | Execution | T1059.001 | High |
| [UC-004](UC-004-dns-exfiltration.md) | Exfiltración DNS | Exfiltration | T1048.003 | High |
| [UC-005](UC-005-scheduled-task-persistence.md) | Scheduled Task | Persistence | T1053.005 | Medium |
| [UC-006](UC-006-ransomware-canary.md) | Ransomware — canary file | Impact | T1486 | Critical |
| [UC-007](UC-007-c2-beacon-misp.md) | C2 Beacon vs MISP IoC | C2 | T1071.001 | Critical |
| [UC-008](UC-008-internal-nmap-scan.md) | Nmap discovery interno | Discovery | T1046 | Medium |
