# Reglas Suricata custom

Las reglas activas están en [docker/suricata/rules/custom.rules](../../docker/suricata/rules/custom.rules).

Rango SID reservado: **9000000 – 9099999** (evita colisión con reglas ET/OISF).

| SID | Firma | MITRE |
|-----|-------|-------|
| 9000001 | Nmap TCP SYN scan | T1046 |
| 9000002 | ICMP sweep | T1018 |
| 9000010 | SSH brute force | T1110.001 |
| 9000011 | HTTP login brute force | T1110.001 |
| 9000020 | User-Agent sospechoso (curl/python) | T1071.001 |
| 9000021 | DNS tunneling — query larga | T1048.003 |
| 9000030 | PowerShell EncodedCommand por HTTP | T1059.001 |
| 9000031 | Web shell PHP | T1505.003 |
| 9000040 | Exfiltración > 50MB | T1041 |
| 9000050 | SQLi UNION SELECT | T1190 |
| 9000060 | SMB scan interno | T1021.002 |

## Testeo

```bash
# Validar sintaxis
docker exec soc-suricata suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/custom.rules

# Reload en caliente
docker exec soc-suricata kill -USR2 1
```
