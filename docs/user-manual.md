# Manual de uso del SOC Lab

Guía práctica para usar cada herramienta del laboratorio, qué anotar cuando hagas pruebas y qué información realmente vale la pena capturar. Escrito para un analista SOC L1 que ya tiene el stack levantado.

---

## Índice

1. [Cómo se conectan las herramientas](#0-cómo-se-conectan)
2. [Splunk — el SIEM](#1-splunk--siem)
3. [Suricata — NIDS](#2-suricata--nids)
4. [Vector — shipper](#3-vector--shipper)
5. [TheHive — gestión de casos](#4-thehive--gestión-de-casos)
6. [Cortex — analyzers de IoCs](#5-cortex--analyzers)
7. [MISP — Threat Intelligence](#6-misp--threat-intel)
8. [Víctimas — DVWA y linux-victim](#7-víctimas)
9. [Qué anotar durante una prueba](#8-qué-anotar)
10. [Información valiosa por herramienta](#9-información-valiosa)
11. [Flujo típico de un caso de principio a fin](#10-flujo-completo)

---

## 0. Cómo se conectan

```
[Víctimas]  →  [Suricata]  →  [Vector]  →  [Splunk (SIEM)]
                                              │
                                              │ webhook alerta
                                              ▼
[MISP (IoCs)]  ←─lookup cada 30min────┐  [TheHive (caso)]
                                       │        │
                                       │        │ observable
                                       │        ▼
                                       └──→  [Cortex] ← analyzers → [MISP, VT, AbuseIPDB]
```

**Regla mental:** todo evento entra por Splunk. Todo lo que amerite trabajo humano se convierte en caso en TheHive. Todo lo que necesite enriquecimiento se manda a Cortex. Todo IoC nuevo que valga la pena se publica a MISP.

---

## 1. Splunk — SIEM

**URL:** http://localhost:8000
**Login:** `admin` / (ver `docker/.env` → `SPLUNK_PASSWORD`)

### Para qué sirve

Es tu centro de operaciones. Aquí llegan **todos** los logs (Suricata, endpoints, Windows, MISP lookups) y aquí corren las 8 correlation searches que disparan las alertas. Es donde harás el 70 % de tu trabajo.

### Cómo usarlo — 5 acciones fundamentales

#### 1.1 Buscar (Search & Reporting → New Search)

El lenguaje se llama **SPL**. Estructura básica:

```
index=<qué índice> [filtros] | <transformación> | <output>
```

Ejemplos prácticos:

```spl
# Últimos 20 eventos de Suricata
index=soc_suricata | head 20

# Solo alertas críticas hoy
index=soc_suricata suricata.event_type=alert suricata.alert.severity=1 earliest=@d

# Contar auth fallidos por IP en las últimas 6 horas
index=soc_endpoints sourcetype=linux:auth status=Failed earliest=-6h
| stats count by src_ip
| sort - count

# Timeline de un host específico
`soc_indexes` host=WKS-042 earliest=-24h
| timechart span=15m count by sourcetype

# Rastrear una IP en todos los índices
`soc_indexes` (src_ip=192.168.1.50 OR dest_ip=192.168.1.50)
| stats count by sourcetype, index
```

**Tip:** siempre acotá con `earliest=-XX` y `latest=now` — sin ventana temporal, Splunk barre TODO el índice.

#### 1.2 Dashboards (Apps → SOC Lab → Panel de Operaciones)

Panel único que muestra:
- Alertas por severidad (24h)
- Top 10 firmas Suricata
- IoCs MISP alcanzados
- Distribución MITRE ATT&CK
- EPS por índice (salud)
- Últimas 20 alertas SOC

**Úsalo al principio de cada turno**, es tu radar.

#### 1.3 Ver qué alertas están configuradas (Settings → Searches, reports, and alerts)

Filtrá por `Owner: nobody` + `App: soc_app`. Ves las 8 correlation searches:
- `SOC - UC-001 SSH Brute Force`
- `SOC - UC-002 Lateral Movement SMB`
- `SOC - UC-003 PowerShell EncodedCommand`
- ...etc.

Click en cualquiera → **Edit** para ver la SPL exacta, el schedule (`cron_schedule`), y la ventana temporal.

#### 1.4 Ver qué alertas se dispararon (auditlog)

```spl
index=_internal source=*savedsearches.log action="alert fired" savedsearch_name="SOC - *"
| table _time savedsearch_name result_count
| sort - _time
```

#### 1.5 Comprobar salud del pipeline

```spl
# ¿Cuántos EPS estamos recibiendo?
| tstats count where `soc_indexes` by index _time span=1m
| stats avg(count) as eps by index

# ¿Hace cuánto no llega nada de una fuente?
| metadata type=hosts index=soc_suricata
| eval minutes_since=(now()-recentTime)/60
| table host recentTime minutes_since
```

Si algún host lleva > 10 min sin enviar → problema de shipper o del propio host.

### Índices que existen y qué contienen

| Índice | Qué contiene | Fuente |
|--------|-------------|--------|
| `soc_suricata` | alertas NIDS, http, dns, tls, ssh, flow | Vector desde `eve.json` |
| `soc_endpoints` | syslog Linux (auth, sudo, cron) | rsyslog desde `victim-linux` |
| `soc_windows` | Security event log + Sysmon (cuando hay víctima Win) | Universal Forwarder |
| `soc_threatintel` | IoCs enriquecidos | MISP sync |
| `_internal` | logs del propio Splunk (útil para debugging) | interno |
| `_audit` | acciones auditadas (alertas disparadas, logins) | interno |

---

## 2. Suricata — NIDS

**Interfaz:** no tiene UI. Se administra por archivos de config.

### Para qué sirve

Es el "sensor de red". Ve **todo el tráfico** de las víctimas (`victim-net` + `soc-net`) y aplica ~30.000 reglas ET Open + 11 reglas custom del laboratorio (SID 9000001–9000060). Cada match produce una línea JSON en `/var/log/suricata/eve.json` que Vector envía a Splunk.

### Cómo verificar que está funcionando

```bash
# ¿Está viendo tráfico?
docker exec soc-suricata suricatasc -c "iface-stat eth0"

# Tail de alertas en vivo
docker exec soc-suricata tail -f /var/log/suricata/fast.log

# Contar alertas por firma
docker exec soc-suricata sh -c "grep -c 'SOC-LAB' /var/log/suricata/fast.log"
```

### Reglas custom (rango SID 9000000-9099999)

| SID | Detecta | UC vinculado |
|-----|---------|--------------|
| 9000001 | Nmap TCP SYN scan | UC-008 |
| 9000010 | SSH brute force | UC-001 |
| 9000020 | User-Agent sospechoso (curl/python) | — |
| 9000021 | DNS query > 60 chars (tunneling) | UC-004 |
| 9000030 | PowerShell EncodedCommand en HTTP | UC-003 |
| 9000050 | SQL Injection (UNION SELECT) | — |
| 9000060 | SMB scan lateral | UC-002 |

Ver todas: [docker/suricata/rules/custom.rules](../docker/suricata/rules/custom.rules).

### Modificar reglas y recargar

1. Editar `docker/suricata/rules/custom.rules`
2. Validar sintaxis: `docker exec soc-suricata suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/custom.rules`
3. Recargar en caliente: `docker exec soc-suricata kill -USR2 1`

---

## 3. Vector — shipper

**No tiene UI.** Corre en background.

### Para qué sirve

Vector es un pipeline moderno que:
1. Lee `/var/log/suricata/eve.json` línea por línea
2. Parsea el JSON, añade `sourcetype=suricata:eve` y `index=soc_suricata`
3. Envía al Splunk HEC (`http://splunk:8088`) con el token del `.env`

**Reemplaza a Filebeat/Logstash** — es más ligero y tiene sink nativo para Splunk HEC.

### Verificar que está enviando

```bash
# Logs de Vector
docker logs soc-vector --tail 20

# Métricas propias
docker exec soc-vector vector top   # si el binario lo tiene, si no:
docker logs soc-vector | grep -i "healthcheck\|sink"
```

En Splunk:
```spl
index=soc_suricata earliest=-5m | stats count by sourcetype
```
Debería mostrar `suricata:eve` con conteo > 0.

### Cuándo tocarlo

Rara vez. Si querés añadir otra fuente de logs, editás `docker/vector/vector.toml` y añadís otro `[sources.xxx]` + transform + sink.

---

## 4. TheHive — gestión de casos

**URL:** http://localhost:9000
**Login:** (creaste en primer arranque)

### Para qué sirve

**El "ticketing system" del SOC.** Cada alerta que amerita trabajo humano se convierte en un caso. Cada caso tiene:
- **Observables** (IPs, hashes, URLs, usuarios, dominios) — lo que el atacante tocó.
- **Tasks** — pasos concretos a realizar (asignables, con estado).
- **TTPs** — técnicas MITRE ATT&CK detectadas.
- **Timeline** — cronología de eventos.

### Cómo usarlo — flujo de un caso

#### 4.1 Recibir alerta

Cuando Splunk dispara una correlation search, hace POST a `/api/alert` de TheHive. Va a **Alerts** (icono campana). Cada alerta muestra:
- Fecha, tipo, severidad
- Descripción de la SPL que la disparó
- Datos crudos (event count, hosts, IPs)

#### 4.2 Triaje inicial (5-10 min)

Abrir alerta → decidir:
- **Convertir en caso** (`Import as case`): amerita investigación. Elegís template.
- **Ignorar** (marcar false positive): documentar por qué.

#### 4.3 Trabajar el caso

Dentro del caso:
1. **Summary:** describí en una frase qué está pasando.
2. **Observables:** añadí IPs, hashes, dominios, usuarios afectados. Marcar TLP e IOC.
3. **Tasks:** desglosá el trabajo:
   - "Verificar reputación de IP X en Cortex"
   - "Aislar host Y en firewall"
   - "Rotar credenciales del user Z"
   - "Buscar más ocurrencias en Splunk"
4. **TTPs:** click en "Add TTP" → seleccionar técnica MITRE (ya vienen 246 templates).

#### 4.4 Enriquecer observables con Cortex

Click en un observable → **Analyzers** → seleccionar cuáles correr (AbuseIPDB, VirusTotal, MISP). Los resultados aparecen ahí mismo.

#### 4.5 Cerrar caso

Cambiar **Status** a `Resolved`. Elegir resolución:
- `TruePositive` (fue real, contenido)
- `FalsePositive` (no era amenaza)
- `Duplicated`
- `Other`

Escribir **Summary de cierre** con: qué pasó, qué se hizo, lecciones.

### Templates de caso incluidos

TheHive importó 246 templates de Cortex (respuestas típicas). Los más útiles para el lab:
- `Malware analysis`
- `Phishing analysis`
- `Suspicious network activity`
- `Compromised account`

---

## 5. Cortex — analyzers

**URL:** http://localhost:9001

### Para qué sirve

Es un **motor de enriquecimiento**. Le pasás un observable (una IP, un hash, un dominio) y corre "analyzers" contra fuentes externas: VirusTotal, AbuseIPDB, MISP, URLhaus, Shodan, MalwareBazaar, etc. Devuelve un reporte agregado con verdicts (`safe`, `suspicious`, `malicious`) y score.

### Analyzers útiles y qué esperar

| Analyzer | Qué hace | Cuándo usarlo | Requiere |
|----------|----------|---------------|----------|
| `AbuseIPDB` | reputación de IP (score 0-100) | Cualquier IP externa sospechosa | API key (free) |
| `VirusTotal_GetReport` | reputación de hash/URL/domain | Malware, C2 sospechoso | API key (free) |
| `MISP_2` | busca IoC en tu propio MISP | Todo observable | ya integrado |
| `URLhaus_2` | URLs asociadas a malware | URLs y dominios | público |
| `MalwareBazaar` | busca sample por hash | Hashes de binarios | público |
| `Shodan_Host` | metadata de host (puertos, banners) | IP objetivo de escaneos | API key |
| `Hashdd_Detail` | reputación de hash | Archivos | público |

### Configurar analyzers

En Cortex → **Organization → Analyzers**:
1. Click al analyzer que querés activar → **Enable**
2. Meter API keys donde aplique
3. **Save**

Los analyzers sin API key (MISP, URLhaus, MalwareBazaar) funcionan out-of-the-box.

### Correr manual (sin TheHive)

Cortex → **New Analysis** → tipo de observable → valor → seleccionar analyzers → Run.

---

## 6. MISP — Threat Intel

**URL:** https://localhost:8443 (ojo: HTTPS, aceptar cert autofirmado)
**Login:** `admin@admin.test` / `admin` (cambiar al primer login)

### Para qué sirve

Es tu **base de IoCs**. Recibe feeds públicos (URLhaus, Feodo Tracker, CIRCL OSINT, etc.) con IPs/dominios/hashes maliciosos, y cada 30 min los sincroniza al lookup `misp_iocs.csv` de Splunk. Cualquier tráfico contra un IoC dispara la alerta UC-007.

Además podés publicar tus **propios eventos** cuando detectás algo nuevo — así tu SOC contribuye a la comunidad.

### Habilitar feeds públicos (primer paso obligatorio)

1. Login → **Sync Actions → List Feeds**
2. Activar (Enable + Caching):
   - **CIRCL OSINT Feed**
   - **abuse.ch URLhaus**
   - **abuse.ch Feodo Tracker**
   - **abuse.ch ThreatFox**
3. Click **Cache all feeds** (5-10 min)
4. Click **Fetch all** (baja todos los eventos)
5. Verificar en **Events → List Events** — deberías tener cientos.

### Sincronizar IoCs → Splunk

Manual:
```bash
bash scripts/misp_to_splunk_lookup.sh
```

Cron (cada 30 min):
```
*/30 * * * * /path/to/scripts/misp_to_splunk_lookup.sh
```

### Publicar tu propio IoC (después de un incidente)

1. **Events → Add Event** → info: "C2 detectado en incidente IR-2026-XXX", TLP:AMBER, threat_level=Medium
2. Dentro del evento → **Add Attribute**:
   - type: `ip-dst` (o `domain`, `md5`, etc.)
   - category: `Network activity`
   - value: la IP
   - **to_ids: true** (para que se propague a detección)
3. **Publish** — queda disponible para otros MISPs conectados.

### Qué mirar en un evento MISP

- **Info** — descripción del contexto (fue phishing? malware? qué familia?)
- **Tags** — clasificación (tlp:xxx, misp-galaxy, threat-actor)
- **Attributes** — los IoCs con to_ids
- **Related Events** — otros eventos que comparten IoCs
- **Sightings** — cuánta gente ha visto ese IoC en el mundo

---

## 7. Víctimas

### 7.1 DVWA (Damn Vulnerable Web App)

**URL:** http://localhost:8080
**Login:** `admin` / `password`
**Setup:** al primer login → **Create/Reset Database** → click.

**Nivel de seguridad**: DVWA Security → Low (default) para pruebas fáciles.

**Módulos útiles para probar detecciones:**

| Módulo DVWA | Ataque | Detección esperada |
|-------------|--------|---------------------|
| SQL Injection | `1' UNION SELECT user,password FROM users--` | Suricata SID 9000050 |
| Command Injection | `127.0.0.1; whoami` | (no cubierto por reglas actuales — buen candidato para agregar) |
| Brute Force | wfuzz al login | Suricata SID 9000011 |
| File Upload | subir shell.php | UC-003 si el shell descarga payloads |
| XSS Reflected | `<script>alert(1)</script>` | (no cubierto) |

### 7.2 victim-linux (SSH abierto)

Container en `victim-net`. Contiene sshd con `root:VulnerableP@ss1`.

**IP interna:** obtenerla con
```bash
docker inspect soc-victim-linux --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'
```

**Simulación de brute force** (desde el host):
```bash
# necesitás hydra o similar; alternativa cruda con ssh loop:
for i in $(seq 1 20); do
  sshpass -p "wrong$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 root@172.31.0.10 exit 2>/dev/null
done
```

Debe disparar UC-001 en Splunk en < 5 min.

---

## 8. Qué anotar

Cuando estés probando (o en un incidente real), estos son los datos que **siempre** debes capturar. Escribilos en el caso de TheHive o en un cuaderno de guardia.

### Metadatos del evento
- [ ] **Timestamp UTC** de detección
- [ ] **Timestamp UTC** de primer evento observable (ojo: a veces es horas antes que la alerta)
- [ ] **Correlation search** que disparó (nombre exacto)
- [ ] **Índice y sourcetype** de origen
- [ ] **Volumen** (cuántos eventos matchearon)

### Actores
- [ ] **IP origen** (con reputación y geolocalización)
- [ ] **IP destino** (con criticidad del asset — servidor prod? DMZ?)
- [ ] **Usuario afectado** (privilegiado? cuenta de servicio?)
- [ ] **Host afectado** (rol, dueño, criticidad)
- [ ] **Proceso responsable** (si Sysmon/EDR lo captó) + parent process

### Acciones observadas
- [ ] **Comandos ejecutados** (bash history, PowerShell logs, cmdline de Sysmon)
- [ ] **Archivos creados/modificados** (path, hash, tamaño)
- [ ] **Conexiones establecidas** (destino, puerto, protocolo)
- [ ] **Autenticaciones** (fallidas y exitosas — el "exitosa" post brute-force es la joya)

### IoCs extraídos
- [ ] IPs, dominios, URLs
- [ ] Hashes MD5/SHA256
- [ ] Emails (sender, subject en phishing)
- [ ] User-Agents, JA3/JA4 fingerprints (si están)

### Contexto MITRE
- [ ] **Táctica** (Initial Access, Execution, etc.)
- [ ] **Técnica** (T-XXXX)
- [ ] **Sub-técnica** si aplica

### Métricas de respuesta
- [ ] **MTTA** (Mean Time To Acknowledge) — desde alerta hasta que la aceptaste
- [ ] **MTTD** (Mean Time To Detect) — desde primer evento hasta alerta
- [ ] **MTTC** (Mean Time To Contain) — hasta bloquear/aislar
- [ ] **MTTR** (Mean Time To Resolve) — hasta cerrar caso

### Al cerrar el caso
- [ ] **Veredicto** (TP, FP, benign true positive, inconcluso)
- [ ] **Impacto** (0 hosts afectados? datos exfiltrados? credenciales rotadas?)
- [ ] **Vector inicial** (cómo entró — phishing? RDP expuesto? vuln parcheable?)
- [ ] **Lecciones** (¿qué falló en la detección? ¿qué mejorar?)
- [ ] **Nuevas reglas/tunings** propuestos

---

## 9. Información valiosa por herramienta

Un mismo evento se ve **distinto** desde cada herramienta. Estas son las piezas de oro que aporta cada una.

### En Splunk
- **La SPL exacta** que disparó (permite reproducir la búsqueda)
- **Los eventos raw** (siempre mirá `_raw` — a veces el parseo pierde detalles)
- **Tendencia temporal** (¿es primera vez o pasa todos los martes?)
- **Correlación cross-source** (ver el mismo actor en logs de red + auth + Windows)

### En Suricata (via Splunk `sourcetype=suricata:eve`)
- **`suricata.alert.signature_id`** + `signature` — qué regla matcheó
- **`suricata.alert.severity`** (1=critical, 4=info)
- **`suricata.http.hostname`** + `url` — destino web completo
- **`suricata.dns.rrname`** — query DNS (revela dominios C2)
- **`suricata.tls.sni`** + `ja3.hash` — huella TLS del cliente (útil para atribución de familia malware)
- **`suricata.flow`** — bytes, duración, packet count (indicador de exfiltración)

### En TheHive
- **Casos abiertos** (dashboard) — no dejes >5 pendientes de triaje
- **Observables comunes entre casos** — Si la misma IP aparece en 3 casos, es campaña activa
- **Timeline del caso** — muestra el orden real de eventos
- **Tags** — usalos para clasificar (`campaign:emotet-2026`, `sector:banking`)
- **Custom fields** — buenos para reportes gerenciales (impacto, costo estimado)

### En Cortex
- **Score agregado** — no un solo analyzer, siempre correr 3+ para consenso
- **Reporte largo (Long)** — el detalle importa: contexto histórico, first-seen, tags
- **JSON crudo** — para automatizar downstream
- **Job history** — te dice quién enriqueció qué y cuándo

### En MISP
- **`to_ids: true`** — solo los IoCs con este flag son "actionable"
- **`Sightings count`** — cuántas veces se ha visto en el mundo (mayor = más real)
- **`Warninglist matches`** — MISP te dice si un IoC podría ser falso positivo (ej. Google DNS)
- **`Galaxy tags`** — atribución a actor (`APT28`, `FIN7`) o familia (`Emotet`, `TrickBot`)
- **First-seen / last-seen** — para saber si el IoC sigue activo

### En Vector (logs)
- **Eventos rechazados por el sink** (HEC saturado, token inválido)
- **Lag del file source** (si Vector no lee al ritmo que Suricata escribe = perdida de eventos)

---

## 10. Flujo completo — ejemplo end-to-end

Simulación de un incidente ficticio para entender el flujo natural.

### Escenario

Un usuario ejecutó una macro maliciosa desde un Excel. El malware inició beacons HTTP hacia un C2.

### Paso 1 — Detección en Splunk

Correlation search `SOC - UC-007 C2 Beacon vs MISP IoC` dispara a las 14:22 UTC. Splunk hace POST a TheHive.

### Paso 2 — Alerta en TheHive

Aparece Alert crítica. L1 la abre, ve:
- `src_ip=172.31.0.42` (WKS-042)
- `dest_ip=45.155.204.24` (marcado en MISP como Cobalt Strike)
- 8 requests HTTP en 5 min

**Decisión**: Import as case, template "Suspicious network activity".

### Paso 3 — Triaje en TheHive

L1 abre el caso, añade observables:
- `172.31.0.42` (internal-ip)
- `45.155.204.24` (ip)
- `malware-tracker.evil` (domain, obtenido del Host: header)

Tasks:
1. ✅ Verificar volumen y jitter del beacon en Splunk
2. ⏳ Enriquecer 45.155.204.24 con Cortex
3. ⏳ Identificar proceso responsable en el host
4. ⏳ Aislar WKS-042

### Paso 4 — Enriquecimiento en Cortex

Click en el observable `45.155.204.24` → Analyzers → seleccionar `AbuseIPDB`, `VirusTotal_GetReport`, `MISP_2`.

Resultados:
- AbuseIPDB: **97/100** confidence, "malware distribution"
- VirusTotal: 45/72 vendors la marcan
- MISP: match en evento "Emotet C2 Aug 2026"

**Verdicto**: malicious confirmado.

### Paso 5 — Investigación profunda en Splunk

L1 busca:
```spl
`soc_indexes` host=WKS-042 earliest=-2h
| sort _time
```

Encuentra un evento Sysmon EID=1 (process creation) minutos antes del primer beacon:
- `image=C:\Windows\System32\regsvr32.exe`
- `cmdline=regsvr32.exe /s C:\Users\apereira\AppData\Roaming\em.dll`
- `parent_image=EXCEL.EXE`

**Descubierto**: usuario abrió Excel con macro que descargó `em.dll`.

### Paso 6 — Contención

L2 aísla WKS-042 vía EDR. Bloquea `45.155.204.24` y `malware-tracker.evil` en firewall + DNS RPZ.

### Paso 7 — Publicar IoCs a MISP

L2 crea evento MISP:
- Info: "Emotet campaign — WKS-042 IR-2026-002"
- Attributes: IP, domain, hash del `em.dll` (todos con to_ids)
- TLP: AMBER
- Publish

### Paso 8 — Cierre del caso

TheHive: cambiar status a **Resolved**, resolution **TruePositive**. Summary:

```
IR-2026-002. Beacon Emotet detectado 14:22, contenido 14:38 (MTTC 16 min).
Vector: correo con adjunto malicioso.
Host reimaged, cuenta reset. Sin exfiltración observada.
Lecciones: EDR debe bloquear regsvr32 desde %APPDATA%.
```

### Anotaciones que quedaron capturadas

| Campo | Valor |
|-------|-------|
| MTTA | 3 min |
| MTTD | 19 min (primer beacon 14:03) |
| MTTC | 16 min desde detección |
| MTTR | 6h 53 min |
| Hosts afectados | 1 (WKS-042) |
| Cuentas afectadas | 1 (`apereira`) |
| IoCs nuevos publicados | 3 |
| Regla nueva propuesta | AppLocker: bloquear regsvr32.exe desde %APPDATA% |

---

## Cheat sheet para tu turno

```
CADA MAÑANA (5 min)
1. Dashboard SOC Lab en Splunk → radar general
2. TheHive → Alerts pendientes de triaje
3. TheHive → Cases con status "In Progress" que sean tuyos
4. MISP → últimos feeds sincronizados OK?

CADA CASO NUEVO
1. Aceptar en <15 min
2. Enriquecer 3 observables en Cortex (mínimo)
3. Documentar TTPs con MITRE
4. Escalar a L2 si: privilegiado, exfiltración, ransomware, >3 hosts

AL CERRAR
1. Veredicto claro (TP/FP)
2. Resolution summary de 2-3 líneas
3. IoCs publicados a MISP si aplica
4. Regla/tuning propuesto si detectaste hueco
```

Ver también [soc-operations-manual.md](soc-operations-manual.md) para procedimientos operativos formales y KPIs mensuales.
