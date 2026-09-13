# UC-002 — Lateral Movement vía SMB/NTLM

| Campo | Valor |
|-------|-------|
| ID | UC-002 |
| Táctica MITRE | Lateral Movement (TA0008) |
| Técnica | T1021.002 — SMB / Windows Admin Shares |
| Severidad | High |
| Fuentes | Windows Security Log (EventCode 4624 logon_type=3), Suricata SID 9000060 |
| Dueño | SOC L2 |

## 1. Contexto

Tras comprometer un host inicial (beachhead), el atacante busca moverse a otros equipos usando credenciales robadas y compartidos administrativos (`ADMIN$`, `C$`, `IPC$`). Herramientas típicas: **PsExec**, **impacket-wmiexec**, **CrackMapExec**, **Cobalt Strike**.

## 2. Lógica de detección

```spl
index=soc_windows source="WinEventLog:Security" EventCode=4624 logon_type=3
| bin _time span=10m
| stats dc(host) as targets values(host) as target_list by _time src_ip target_user
| where targets >= 5
| eval mitre_technique="T1021.002", severity="high"
```

Se dispara si un mismo `src_ip` + `target_user` autentica por NTLM/SMB (logon_type=3) contra ≥5 equipos distintos en 10 min.

## 3. Respuesta

### L1
1. Enumerar hosts alcanzados en la ventana.
2. Correlacionar con procesos creados en cada host (Sysmon 1) alrededor del logon.
3. ¿Existe evento 4672 (Special Privileges) con la misma cuenta? Elevar prioridad.

### L2
1. Aislar el host origen (network-quarantine).
2. Deshabilitar cuenta comprometida (`Disable-ADAccount`).
3. Forzar renovación de credenciales Kerberos (KRBTGT — solo si hay evidencia de Golden Ticket).
4. Snapshots forenses de los hosts destino.

### L3
1. Habilitar SMB signing y deshabilitar SMBv1.
2. Auditar cuentas con privilegios locales de admin en múltiples máquinas.
3. Implementar LAPS.
4. Segmentar red (jump servers).

## 4. Simulación

Desde Kali con impacket:

```bash
for host in 172.31.0.10 172.31.0.11 172.31.0.12 172.31.0.13 172.31.0.14 172.31.0.15; do
  impacket-wmiexec -no-pass -hashes :aad3b435b51404eeaad3b435b51404ee \
    Administrator@$host "whoami"
done
```

## 5. Falsos positivos

- Scripts de despliegue (SCCM, Ansible)
- Backup agents que se conectan a múltiples servidores
- Cuenta de servicio de monitoreo (WMI polling)

Whitelist mantenerlas en `lookups/svc_accounts_whitelist.csv`.
