# Guía de Despliegue — SOC Lab

## 0. Requisitos

### Hardware / VM

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| CPU | 4 vCPU | 8 vCPU |
| RAM | 16 GB | 32 GB |
| Disco | 60 GB | 120 GB SSD |
| Red | 1 GbE | 1 GbE |

### Software

- **Docker Engine ≥ 24.x**
- **Docker Compose v2** (plugin, no `docker-compose` legacy)
- **Linux** (Ubuntu 22.04 / Debian 12), macOS con Docker Desktop, o Windows con **WSL2**
- **git** para clonar el repositorio
- **jq**, **curl**, **openssl** para scripts auxiliares

## 1. Clonar el repositorio

```bash
git clone https://github.com/<tu-usuario>/soc-infrastructure.git
cd soc-infrastructure
```

## 2. Setup inicial (genera secretos)

```bash
bash scripts/setup.sh
```

Este script:
- Valida dependencias.
- Genera `docker/.env` con contraseñas y tokens aleatorios.
- **Guarda las credenciales generadas** — se muestran en pantalla una única vez.

## 3. Ajustes de kernel (Linux/WSL2)

Elasticsearch y MISP requieren límites elevados:

```bash
sudo sysctl -w vm.max_map_count=524288
sudo sysctl -w fs.file-max=131072

# Persistente:
echo "vm.max_map_count=524288" | sudo tee -a /etc/sysctl.conf
echo "fs.file-max=131072"      | sudo tee -a /etc/sysctl.conf
```

## 4. Desplegar el stack

```bash
bash scripts/deploy.sh
```

El primer arranque tarda 5-10 minutos (pull de imágenes ≈ 6 GB, init de Splunk ≈ 2 min, TheHive/Cassandra ≈ 3 min).

## 5. Post-despliegue

### 5.1. Cortex — obtener API key

1. Abrir <http://localhost:9001>.
2. **Superadmin login inicial:** `admin / thehive1234` (cambiar inmediatamente).
3. Crear organización `SOC-LAB`.
4. Crear usuario `thehive-integration` con rol `orgAdmin`.
5. Generar API key y copiarla.
6. Editar `docker/.env` → `CORTEX_API_KEY=<clave>`.
7. Reiniciar TheHive:

   ```bash
   docker compose restart thehive
   ```

### 5.2. Splunk — verificar índices y app

1. Abrir <http://localhost:8000> (usuario `admin`, contraseña de `.env`).
2. **Settings → Indexes** — deben existir: `soc_suricata`, `soc_endpoints`, `soc_windows`, `soc_threatintel`.
3. **Apps** — `SOC Lab` (soc_app) debe estar visible.
4. **Data Inputs → HTTP Event Collector** — activar y verificar token.
5. **Data Inputs → TCP** — crear input :9514 con sourcetype `linux:auth` para el syslog de víctimas.

### 5.3. MISP — habilitar feeds públicos

1. Abrir <https://localhost:8443>. Login: `admin@admin.test / admin` → cambiar.
2. **Sync Actions → List Feeds** → habilitar:
   - CIRCL OSINT Feed
   - abuse.ch URLhaus
   - abuse.ch Feodo Tracker
3. **Cache all feeds** → esperar 5-10 min → **Fetch all**.
4. Ejecutar sincronización a Splunk:

   ```bash
   bash scripts/misp_to_splunk_lookup.sh
   ```

   Añadir a crontab:
   ```
   */30 * * * * /path/to/soc-infrastructure/scripts/misp_to_splunk_lookup.sh
   ```

### 5.4. TheHive — configurar webhook con Splunk

En **TheHive → Admin → Organisations → SOC-LAB → Webhook**, no aplica: TheHive recibe alertas vía su API `/api/alert`. Las correlation searches de Splunk ya están configuradas para llamarla.

## 6. Validación end-to-end

```bash
bash scripts/generate-test-events.sh all
```

Esperado (dentro de 5-10 min):
- Splunk: alertas UC-001, UC-003, UC-004, UC-007, UC-008 disparadas (Settings → Searches).
- TheHive: 5 casos nuevos con severidad alta/crítica.
- Cortex: si ejecutas analyzers manualmente sobre IoCs, deberían devolver resultados.

## 7. Troubleshooting

| Síntoma | Causa probable | Solución |
|---------|----------------|----------|
| Splunk no arranca | Falta `SPLUNK_START_ARGS=--accept-license` | Verificar `docker-compose.yml` |
| Elasticsearch crash | `vm.max_map_count` bajo | `sysctl -w vm.max_map_count=524288` |
| TheHive muestra "No index" | Cassandra no lista aún | `docker logs soc-cassandra` — esperar 2 min |
| Cortex 500 error en analyzer | Falta imagen Docker del analyzer | `docker pull cortexneurons/<analyzer>` |
| MISP admin pw no cambió | Init flag no corrió | `docker exec soc-misp /var/www/MISP/app/Console/cake User change_pw admin@admin.test <newpw>` |
| Alerta no llega a TheHive | Token/URL incorrecto en savedsearch | Revisar `action.webhook.param.url` |
| Filebeat no envía a Splunk | HEC token distinto | Alinear `SPLUNK_HEC_TOKEN` en `.env` y en Splunk UI |

## 8. Desmontar

```bash
cd docker
docker compose down          # Preserva volúmenes
docker compose down -v       # Borra TODO (¡destructivo!)
```

## 9. Hardening opcional para uso extendido

- HTTPS con Traefik / nginx reverse proxy (Let's Encrypt).
- Segregar red pública vs interna con overlay Docker.
- Backup automático de volúmenes con restic.
- Rotación de logs con `logrotate` en el host.
- MFA en Splunk (SAML / LDAP).
