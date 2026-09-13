# UC-007 — Beacon C2 correlacionado con IoC MISP

| Campo | Valor |
|-------|-------|
| ID | UC-007 |
| Táctica MITRE | Command and Control (TA0011) |
| Técnica | T1071.001 — Web Protocols |
| Severidad | Critical |
| Fuentes | Suricata event_type=http, MISP feed vía lookup `misp_iocs.csv` |
| Dueño | SOC L2 |

## 1. Contexto

Este caso valida el ciclo completo **Threat Intel → SIEM**. MISP publica IoCs (IPs/dominios asociados a Emotet, Cobalt Strike, TrickBot, etc.), que se importan periódicamente al lookup de Splunk. Cualquier tráfico HTTP saliente hacia un IoC dispara alerta crítica.

## 2. Detección

```spl
index=soc_suricata sourcetype=suricata:eve suricata.event_type=http
| rename suricata.dest_ip as dest_ip suricata.http.hostname as host_header
| lookup misp_iocs.csv value AS dest_ip OUTPUT threat_type category ioc_confidence
| where isnotnull(threat_type)
| eval mitre_technique="T1071.001", severity="critical"
```

## 3. Sincronización MISP → Splunk

Script `scripts/misp_to_splunk_lookup.sh` (ver [scripts/](../scripts/)) que:

1. Consulta MISP REST API: `/attributes/restSearch/`
2. Filtra por `type: ip-dst`, `type: domain`, `to_ids: true`.
3. Escribe `misp_iocs.csv` en `$SPLUNK_HOME/etc/apps/soc_app/lookups/`.

Cron: cada 30 min.

## 4. Respuesta

### L1
1. Confirmar volumen del beacon (frecuencia, jitter → indicador de C2 vs falso positivo).
2. Identificar proceso origen en host (Sysmon EID 3 network connection).
3. Correlacionar con eventos DNS previos hacia el mismo host.

### L2
1. Aislar host.
2. Bloquear IP/dominio en firewall + proxy.
3. Full triage forense: memoria, disco, timeline.
4. Escalar a CTI para posible atribución (¿comparte infra con APT conocido?).

### L3
1. Añadir el IoC al bloqueo permanente si `ioc_confidence ≥ 80`.
2. Escribir regla YARA sobre el binario.
3. Reportar a MISP con `Sighting` para retroalimentar la comunidad.

## 5. Simulación

Añadir un IoC de prueba a `misp_iocs.csv`:

```csv
198.51.100.42,ip,c2,test-beacon,100,soc-lab-test,2026-09-01
```

Desde el host víctima:

```bash
while true; do curl -s http://198.51.100.42/beacon; sleep 60; done
```

## 6. Falsos positivos

- IoCs con `ioc_confidence < 60` sin corroborar.
- Servicios legítimos alojados en la misma IP (hosting compartido).
- Feed MISP no depurado → siempre revisar TLP y aging.
