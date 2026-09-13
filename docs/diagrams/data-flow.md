# Flujo de datos — Ingesta y correlación

```mermaid
flowchart LR
  subgraph Sources
    S1[Suricata eve.json]
    S2[Linux rsyslog]
    S3[Windows Sysmon]
    S4[MISP IoCs CSV]
  end

  subgraph Shippers
    F[Filebeat]
    U[Universal Forwarder]
    C[Cron sync MISP]
  end

  subgraph Splunk
    HEC[HEC :8088]
    FWD[:9997]
    IDX[(Indexers)]
    LKP[(Lookups)]
    SS[Saved Searches<br/>UC-001..UC-008]
  end

  subgraph Response
    TH[TheHive Alert API]
    A[Analista L1/L2]
  end

  S1 --> F --> HEC
  S2 -->|syslog :9514| IDX
  S3 --> U --> FWD --> IDX
  S4 --> C --> LKP

  HEC --> IDX
  IDX --> SS
  LKP --> SS
  SS -->|webhook| TH --> A
```

## Volumen esperado (baseline lab)

| Fuente | EPS típico | Volumen diario |
|--------|-----------|-----------------|
| Suricata | 5-50 | 50-500 MB |
| linux:auth | < 1 | ~5 MB |
| Sysmon | 20-200 | 200 MB - 2 GB |
| MISP lookup | 0 (batch) | 1-5 MB |

Total esperado: **~2 GB/día** (dentro del límite de Splunk Free de 500 MB/día NO, requiere Trial de 60 días o licencia comercial).

## Retención

| Índice | Hot | Cold | Frozen |
|--------|-----|------|--------|
| soc_suricata | 7d | 30d | delete |
| soc_endpoints | 30d | 90d | delete |
| soc_windows | 30d | 90d | delete |
| soc_threatintel | 90d | 365d | delete |
