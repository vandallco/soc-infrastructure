# SOC Infrastructure Lab

Laboratorio completo de Security Operations Center (SOC) construido con herramientas open source y Splunk como SIEM central. Desplegable en Docker Compose, orientado a fines académicos, entrenamiento de analistas Blue Team y demostración de casos de uso alineados a MITRE ATT&CK.

---

## Arquitectura

```
                        ┌─────────────────────────┐
                        │    Analista SOC (Web)   │
                        └───────────┬─────────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
     ┌───────▼────────┐   ┌─────────▼────────┐    ┌────────▼────────┐
     │   Splunk SIEM  │   │  TheHive (SOAR)  │    │  MISP (CTI)     │
     │   8000/8089    │   │   9000           │    │   443           │
     └───────▲────────┘   └─────────▲────────┘    └────────▲────────┘
             │                      │                      │
             │                ┌─────┴──────┐               │
             │                │   Cortex   │───────────────┘
             │                │  9001      │
             │                └─────▲──────┘
             │                      │
     ┌───────┴───────────────────────────────────┐
     │        Pipeline de ingestión               │
     │  Filebeat / Splunk UF / Syslog / HEC       │
     └───────▲───────▲───────▲───────▲───────────┘
             │       │       │       │
       ┌─────┴──┐ ┌──┴───┐ ┌─┴────┐ ┌┴──────────┐
       │Suricata│ │Wazuh │ │Linux │ │  Windows  │
       │  IDS   │ │Agent │ │Víct. │ │  Sysmon   │
       └────────┘ └──────┘ └──────┘ └───────────┘
```

Ver diagrama detallado en [docs/diagrams/architecture.md](docs/diagrams/architecture.md).

---

## Componentes

| Capa | Herramienta | Puerto | Rol |
|------|-------------|--------|-----|
| SIEM | **Splunk Enterprise** (trial 60 días / free) | 8000, 8089, 9997 | Correlación, dashboards, alertas |
| NIDS | **Suricata** | — | Detección de tráfico malicioso |
| SOAR | **TheHive 5** | 9000 | Gestión de casos e incidentes |
| Analizador | **Cortex** | 9001 | Enriquecimiento y observables |
| CTI | **MISP** | 443 | Feeds de IoCs y threat sharing |
| Ingesta | **Filebeat / Splunk UF** | 5044 | Envío de logs a Splunk |
| Endpoints | **Ubuntu + Windows Server** | — | Víctimas monitoreadas |

---

## Despliegue rápido

**Requisitos**
- Docker Engine 24+ y Docker Compose v2
- 16 GB RAM mínimo (32 GB recomendado)
- 60 GB disco
- Linux/WSL2/macOS (Windows nativo funciona con ajustes)

**Pasos**

```bash
# 1. Clonar repo
git clone https://github.com/<tu-usuario>/soc-infrastructure.git
cd soc-infrastructure

# 2. Preparar variables de entorno
cp docker/.env.example docker/.env
# Editar contraseñas y tokens en docker/.env

# 3. Ajuste de límites de kernel (obligatorio para Elasticsearch/MISP)
sudo sysctl -w vm.max_map_count=524288
sudo sysctl -w fs.file-max=131072

# 4. Levantar el stack
cd docker
docker compose up -d

# 5. Verificar salud
../scripts/health-check.sh
```

Guía completa en [docs/deployment-guide.md](docs/deployment-guide.md).

---

## URLs de acceso

Una vez desplegado:

- Splunk Web: <http://localhost:8000> (admin / ver `.env`)
- TheHive: <http://localhost:9000>
- Cortex: <http://localhost:9001>
- MISP: <https://localhost:443> (admin@admin.test / admin)

---

## Casos de uso incluidos (MITRE ATT&CK)

| ID | Caso de uso | Táctica | Técnica |
|----|-------------|---------|---------|
| UC-001 | SSH Brute Force | Credential Access | T1110.001 |
| UC-002 | Lateral Movement vía SMB | Lateral Movement | T1021.002 |
| UC-003 | PowerShell ofuscado | Execution | T1059.001 |
| UC-004 | Exfiltración DNS | Exfiltration | T1048.003 |
| UC-005 | Persistencia scheduled task | Persistence | T1053.005 |
| UC-006 | Ransomware simulado (canary) | Impact | T1486 |
| UC-007 | Beacon C2 hacia IoC MISP | Command & Control | T1071.001 |
| UC-008 | Enumeración interna Nmap | Discovery | T1046 |

Fichas detalladas en [use-cases/](use-cases/).

---

## Estructura del repositorio

```
soc-infrastructure/
├── docker/                  # docker-compose y configs por servicio
├── splunk/                  # App custom + inputs + correlation searches
├── detection-rules/         # Reglas Splunk, Suricata, Sigma
├── playbooks/               # SOPs de respuesta a incidentes
├── use-cases/               # Fichas MITRE ATT&CK
├── threat-intel/            # IoCs y feeds pre-cargados
├── scripts/                 # Automatización (deploy, health, generación de eventos)
├── docs/                    # Arquitectura, manual SOC, reportes IR
└── README.md
```

---

## Manual de operaciones SOC

- [Manual del analista](docs/soc-operations-manual.md)
- [Guía de despliegue](docs/deployment-guide.md)
- [Mapeo MITRE ATT&CK](docs/mitre-attack-mapping.md)
- [Reportes de incidentes simulados](docs/incident-reports/)

---

## Roadmap

- [x] Splunk + Suricata + TheHive + Cortex + MISP
- [x] 8 casos de uso mapeados a MITRE
- [x] Playbooks para 4 escenarios
- [ ] Integración Wazuh HIDS
- [ ] Feed automatizado MISP → Splunk lookup
- [ ] Dashboards ejecutivos (KPI SOC)
- [ ] Módulo purple team (Atomic Red Team)

---

## Licencia

MIT — ver [LICENSE](LICENSE). Splunk se rige por su propia licencia (Enterprise Trial / Free).

## Aviso legal

Este laboratorio está diseñado para uso educativo en entornos aislados. **NO** desplegar en redes de producción sin hardening adicional. Los IoCs simulados y payloads incluidos son inertes o benignos.
