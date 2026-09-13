# Arquitectura del SOC Lab

## Vista lógica

```mermaid
flowchart TB
  subgraph Analistas
    A1[Analista L1]
    A2[Analista L2/L3]
    IR[IR Lead / CSIRT]
  end

  subgraph Presentación
    SPWEB[Splunk Web<br/>:8000]
    THWEB[TheHive UI<br/>:9000]
    CORWEB[Cortex UI<br/>:9001]
    MISPWEB[MISP UI<br/>:8443]
  end

  subgraph Núcleo
    SPLUNK[(Splunk Enterprise<br/>SIEM)]
    THEHIVE[(TheHive<br/>Casos IR)]
    CORTEX[(Cortex<br/>Analyzers)]
    MISP[(MISP<br/>Threat Intel)]
    ES[(Elasticsearch)]
    CASS[(Cassandra)]
  end

  subgraph Ingesta
    HEC[Splunk HEC<br/>:8088]
    UF[Universal Forwarder]
    FB[Filebeat]
    SYS[Syslog<br/>:9514]
  end

  subgraph Sensores
    SUR[Suricata NIDS<br/>af-packet]
    RSY[rsyslog víctimas]
    SYSMON[Sysmon<br/>Windows víctimas]
  end

  subgraph Víctimas
    VLIN[victim-linux]
    VWIN[victim-win]
    DVWA[DVWA<br/>web vuln]
  end

  A1 & A2 & IR --> SPWEB & THWEB & CORWEB & MISPWEB

  SPWEB --> SPLUNK
  THWEB --> THEHIVE
  CORWEB --> CORTEX
  MISPWEB --> MISP

  THEHIVE --> CASS & ES
  CORTEX  --> ES
  THEHIVE <--> CORTEX
  CORTEX  <--> MISP
  MISP    -->|CSV lookup 30m| SPLUNK
  SPLUNK  -->|webhook alerta| THEHIVE

  SUR --> FB --> HEC --> SPLUNK
  RSY --> SYS --> SPLUNK
  SYSMON --> UF --> SPLUNK

  VLIN --> RSY
  VWIN --> SYSMON
  DVWA -.tráfico.-> SUR
  VLIN -.tráfico.-> SUR
  VWIN -.tráfico.-> SUR
```

## Vista de flujo de una alerta

```mermaid
sequenceDiagram
  participant V as Víctima (WKS-042)
  participant SU as Suricata
  participant SP as Splunk
  participant TH as TheHive
  participant C as Cortex
  participant M as MISP
  participant A as Analista L2

  V->>SU: HTTP GET malware-tracker.evil
  SU->>SP: eve.json (via Filebeat+HEC)
  Note over SP: Correlation search UC-007<br/>hace lookup en misp_iocs.csv
  SP->>TH: POST /api/alert (severity=critical)
  TH->>A: Notificación
  A->>C: Analizar IoC (VirusTotal)
  C-->>A: Score 45/72 — Emotet
  A->>M: Añadir Sighting
  A->>TH: Cerrar caso con timeline + IoCs
```

## Vista de red

```mermaid
flowchart LR
  subgraph "soc-net (172.30.0.0/24)"
    SPLUNK[splunk<br/>172.30.0.10]
    THEHIVE[thehive<br/>172.30.0.20]
    CORTEX[cortex<br/>172.30.0.21]
    ES[elasticsearch]
    CASS[cassandra]
    MISP[misp<br/>172.30.0.30]
    FB[filebeat]
  end
  subgraph "victim-net (172.31.0.0/24)"
    VLIN[victim-linux<br/>172.31.0.10]
    DVWA[dvwa<br/>172.31.0.11]
  end
  SUR[suricata<br/>host-net] -.escucha eth0.-> VLIN & DVWA
  VLIN <---> SPLUNK
```

## Puertos expuestos al host

| Servicio | Puerto host | Protocolo |
|----------|-------------|-----------|
| Splunk Web | 8000 | HTTP |
| Splunk HEC | 8088 | HTTP |
| Splunk API | 8089 | HTTPS |
| Splunk Fwd | 9997 | TCP |
| TheHive | 9000 | HTTP |
| Cortex | 9001 | HTTP |
| MISP | 8443 | HTTPS |
| DVWA | 8080 | HTTP |

## Volúmenes persistentes

- `splunk-var`, `splunk-etc` — índices, configs
- `cassandra-data`, `elasticsearch-data` — TheHive backend
- `thehive-data`, `cortex-data` — attachments, jobs
- `misp-db`, `misp-files` — DB y evidencias
- `suricata-logs` — eve.json, fast.log
