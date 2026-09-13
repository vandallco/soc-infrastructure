# Playbook — Respuesta a Fuerza Bruta

**Owner:** SOC L1 (escala a L2 si hay compromiso)
**SLA MTTA:** 15 min · **MTTR contención:** 30 min
**Trigger:** UC-001, UC-011 (RDP), UC-012 (VPN/SSO)

## 1. Preparación

- Habilitar logging de fallos en todos los servicios expuestos (SSH/RDP/VPN/SSO/O365).
- Mantener `lookups/scanners_whitelist.csv` actualizado.
- Fail2ban / Cloud Armor / IP-rate-limit configurados en perímetro.

## 2. Detección y triaje

| Paso | Acción | Herramienta |
|------|--------|-------------|
| 2.1 | Confirmar alerta en Splunk. | Splunk `soc_app` |
| 2.2 | Enriquecer IP origen. | Cortex `AbuseIPDB`, `IPVoid`, `MISP` |
| 2.3 | Verificar si algún intento fue exitoso. | `status=Accepted src_ip=<IP>` |
| 2.4 | Crear caso en TheHive con severidad correspondiente. | TheHive |

## 3. Contención

- **Sin acceso exitoso:** bloquear IP en firewall perimetral (ACL o NGFW deny).
- **Con acceso exitoso:**
  1. Deshabilitar cuenta afectada (`usermod -L <user>` / `Disable-ADAccount`).
  2. Aislar host destino de la red.
  3. Cerrar sesiones activas.

## 4. Erradicación

1. Rotar credenciales del usuario (obligatorio + MFA).
2. Auditar acciones del atacante (bash history, wtmp, sudo log, Windows 4688).
3. Buscar persistencia dejada: cron, systemd, run keys, scheduled tasks.

## 5. Recuperación

1. Reintegrar host tras validación forense.
2. Reactivar cuenta con nueva contraseña + MFA.
3. Cerrar caso en TheHive con timeline y evidencias.

## 6. Lecciones

- ¿Se detectó dentro del SLA?
- ¿Falta MFA en algún vector?
- ¿La fuente estaba en TI (MISP)? Sincronizar feed si no.

## 7. Comunicación

| Audiencia | Cuándo | Canal | Contenido |
|-----------|--------|-------|-----------|
| Analista L2 | Al confirmar acceso exitoso | TheHive @assignee | Ticket + IoCs |
| Dueño del sistema | Al iniciar contención | Correo/Slack | Ventana de indisponibilidad |
| CISO | Si involucra cuenta privilegiada | Llamada + correo | Resumen ejecutivo |
