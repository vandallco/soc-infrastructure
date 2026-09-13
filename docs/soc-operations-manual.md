# Manual de Operaciones — SOC

## 1. Modelo de servicio

SOC-LAB opera en modelo **24×7** con turnos rotativos y tres niveles:

| Nivel | Rol | Responsabilidad principal | MTTA objetivo |
|-------|-----|---------------------------|---------------|
| L1 | Triaje | Recibe, clasifica y escala alertas | 15 min (High), 5 min (Critical) |
| L2 | Investigación | Correlación multi-fuente, contención | 30 min |
| L3 | Threat Hunting / IR | Casos complejos, forensia, mejora continua | Bajo demanda |
| CSIRT | Crisis | Ransomware, brechas mayores, notificación regulatoria | Inmediato |

## 2. Flujo de trabajo estándar

```
Correlation Search  ─►  TheHive (alerta)  ─►  Analista L1 (triaje)
     ▲                        │
     │                        ├─►  Falso positivo  ─►  Whitelist + cierre
     │                        │
     │                        ├─►  Verdadero positivo bajo  ─►  Playbook + cierre
     │                        │
     │                        └─►  Verdadero positivo medio+  ─►  Escala a L2
     │                                                              │
     └────  Post-mortem / lecciones  ◄──  Cierre  ◄──  Contención + Erradicación
```

## 3. Priorización de casos

Matriz **severidad × impacto**:

| ↓ Severidad / Impacto → | Bajo | Medio | Alto | Crítico |
|-------------------------|------|-------|------|---------|
| **Info**     | P4 | P4 | P3 | P2 |
| **Low**      | P4 | P3 | P3 | P2 |
| **Medium**   | P3 | P2 | P2 | P1 |
| **High**     | P2 | P2 | P1 | P0 |
| **Critical** | P1 | P1 | P0 | P0 |

**P0**: guerra room inmediato. **P1**: contención en 1h. **P2**: contención en 4h. **P3**: 24h. **P4**: 7d o cierre por rutina.

## 4. Herramientas del analista

| Necesidad | Herramienta | URL |
|-----------|-------------|-----|
| Buscar logs | Splunk | http://localhost:8000 |
| Casos IR | TheHive | http://localhost:9000 |
| Enriquecimiento | Cortex | http://localhost:9001 |
| Feeds TI | MISP | https://localhost:8443 |
| Referencia MITRE | attack.mitre.org | https://attack.mitre.org |
| Malware sandbox | Cortex analyzer `AnyRun` / local | (configurar en Cortex) |

## 5. SPL útiles del día a día

```spl
# ¿Qué disparó alertas hoy?
index=_internal source=*savedsearches.log savedsearch_name="SOC - *" action="alert fired"
| stats count by savedsearch_name | sort - count

# Top IPs origen en logs de auth
index=soc_endpoints sourcetype=linux:auth
| stats count by src_ip | sort - count | head 20

# Timeline de un host
`soc_indexes` host=WKS-042 earliest=-24h
| timechart span=5m count by sourcetype

# Rastrear una IP en todo el SOC
`soc_indexes` (src_ip=X.X.X.X OR dest_ip=X.X.X.X)
| stats count by sourcetype | sort - count
```

## 6. Procedimientos operativos

### 6.1. Turno de guardia (handover)

1. Revisar dashboard SOC — alertas abiertas, EPS anómalos, health.
2. Leer notas del turno saliente en el canal `#soc-handover`.
3. Confirmar casos escalados sin dueño y asignarlos.
4. Actualizar el registro de guardia (planilla).

### 6.2. Manejo de un caso en TheHive

1. Aceptar el caso (asignarse como dueño).
2. Añadir observables (IPs, hashes, URLs, usuarios).
3. Correr analyzers relevantes.
4. Documentar hallazgos en tasks.
5. Aplicar playbook correspondiente.
6. Al cerrar: escribir resolution summary + IoCs finales.

### 6.3. Escalado

- Escala **inmediata** a L2 si: severidad ≥ High, cuenta privilegiada, host crítico, evidencia de exfiltración.
- Escala a **L3/CSIRT** si: ransomware, brecha confirmada, ≥ 10 hosts afectados, exposición pública.

## 7. KPIs del SOC (mensuales)

| KPI | Definición | Objetivo |
|-----|-----------|----------|
| MTTA | Mean Time To Acknowledge | < 15 min (High), < 5 min (Critical) |
| MTTD | Mean Time To Detect | < 30 min desde el evento inicial |
| MTTR | Mean Time To Respond | < 4h (High), < 30 min (Critical) |
| False Positive Rate | Casos cerrados como FP / total | < 20% |
| Coverage MITRE | Técnicas ATT&CK con detección | > 60% de las TOP-30 |
| EPS por indexer | Events per second promedio | Nominal ± 20% |

## 8. Ciclo de mejora continua

- **Semanal:** revisión de FP → ajuste de umbrales / whitelists.
- **Quincenal:** review de casos P0/P1 con L3.
- **Mensual:** reporte de KPIs a la gerencia.
- **Trimestral:** simulacros (tabletop + purple team con Atomic Red Team).
- **Anual:** revisión del modelo de amenazas y prioridades del SOC.

## 9. Referencias

- NIST SP 800-61r2 (Incident Handling)
- MITRE ATT&CK ([attack.mitre.org](https://attack.mitre.org))
- FIRST — Traffic Light Protocol
- SANS Reading Room — SOC playbooks
