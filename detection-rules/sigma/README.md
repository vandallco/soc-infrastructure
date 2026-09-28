# Reglas de detección: Sigma

Versión portable de los 8 casos de uso, en formato [Sigma](https://sigmahq.io/). Se pueden convertir a Splunk, Elastic, Microsoft Sentinel, QRadar y otros SIEMs con `sigma-cli`.

Las detecciones por umbral (fuerza bruta, movimiento lateral, túnel DNS, ransomware y escaneo) usan **reglas de correlación de Sigma v2**: una regla base describe el evento y una regla de correlación (`event_count` o `value_count`) define la ventana de tiempo, la agrupación y el umbral.

| Archivo | Caso de uso | Tipo | MITRE |
|---------|-------------|------|-------|
| [uc001_ssh_brute_force.yml](uc001_ssh_brute_force.yml) | Fuerza bruta SSH | Correlación `event_count` ≥ 10 en 5 min | T1110.001 |
| [uc002_lateral_movement_smb.yml](uc002_lateral_movement_smb.yml) | Movimiento lateral SMB | Correlación `value_count` ≥ 5 hosts en 10 min | T1021.002 |
| [uc003_powershell_encoded.yml](uc003_powershell_encoded.yml) | PowerShell ofuscado | Regla simple | T1059.001 |
| [uc004_dns_tunneling.yml](uc004_dns_tunneling.yml) | Túnel / exfiltración DNS | Correlación `event_count` > 20 en 15 min | T1048.003, T1071.004 |
| [uc005_scheduled_task_persistence.yml](uc005_scheduled_task_persistence.yml) | Persistencia con tarea programada | Regla simple | T1053.005 |
| [uc006_ransomware_canary.yml](uc006_ransomware_canary.yml) | Ransomware sobre archivos canary | Correlación `event_count` > 3 en 10 min | T1486 |
| [uc007_c2_beacon_misp_ioc.yml](uc007_c2_beacon_misp_ioc.yml) | Conexión a IoC de C2 (MISP) | Regla simple con lista de IoCs | T1071.001 |
| [uc008_internal_port_scan.yml](uc008_internal_port_scan.yml) | Escaneo de puertos interno | Correlación `value_count` ≥ 15 puertos en 15 min | T1046 |

## Validar y convertir

```bash
pip install sigma-cli pysigma-backend-splunk
sigma check detection-rules/sigma/
sigma convert -t splunk --without-pipeline detection-rules/sigma/
```

El workflow [validate.yml](../../.github/workflows/validate.yml) corre ambos comandos en cada push.

> **UC-007:** Sigma no soporta lookups, así que la regla incluye la lista de IoCs de
> [baseline_iocs.csv](../../threat-intel/iocs/baseline_iocs.csv). En Splunk, la búsqueda
> equivalente usa el lookup `misp_iocs.csv`, que se actualiza desde MISP.
