# UC-008 — Discovery: Nmap Scan Interno

| Campo | Valor |
|-------|-------|
| ID | UC-008 |
| Táctica MITRE | Discovery (TA0007) |
| Técnica | T1046 — Network Service Discovery |
| Severidad | Medium |
| Fuentes | Suricata SID 9000001 (Nmap SYN scan) |
| Dueño | SOC L1 |

## 1. Contexto

Post-compromiso, el atacante enumera hosts y servicios internos para elegir el próximo objetivo. Nmap, Masscan y RustScan son los más usados. Un pico de conexiones SYN dispersas desde un mismo origen es la firma clara.

## 2. Detección

```spl
index=soc_suricata sourcetype=suricata:eve suricata.event_type=alert
  suricata.alert.signature_id=9000001
| stats count dc(suricata.dest_port) as ports values(suricata.dest_ip) as targets by src_ip
| where ports >= 15
| eval mitre_technique="T1046", severity="medium"
```

## 3. Respuesta

### L1
1. Identificar el host origen y su dueño (¿pentester autorizado? ¿scanner corporativo?).
2. Confirmar con equipo de infraestructura si hay ventana de escaneo planificada.
3. Si NO es autorizado → crear caso severidad Medium; escalar a L2.

### L2
1. Aislar host origen (posible pivot compromise).
2. Revisar procesos y binarios: `ps auxf`, `netstat -tunp`.
3. Buscar procesos Nmap/Masscan/RustScan/CrackMapExec.
4. Análisis de línea de tiempo — ¿cómo llegó al host? ¿UC-002 previo?

### L3
1. Segmentar red — limitar visibilidad L2/L3 entre subredes.
2. Whitelist explícita de escáneres corporativos con IPs fijas.
3. NAC / 802.1X para autenticar hosts.

## 4. Simulación

```bash
nmap -sS -Pn -p- --min-rate 500 172.31.0.0/24
```

## 5. Falsos positivos

- Escáner de vulnerabilidades autorizado (Nessus, Qualys).
- Herramientas de descubrimiento de red (Rumble, Lansweeper).
- Monitoreo (ping sweep, uptime checks).
