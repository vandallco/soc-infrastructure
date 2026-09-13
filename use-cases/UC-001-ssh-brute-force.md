# UC-001 — SSH Brute Force

| Campo | Valor |
|-------|-------|
| ID | UC-001 |
| Táctica MITRE | Credential Access (TA0006) |
| Técnica | T1110.001 — Password Guessing |
| Severidad | High |
| Fuentes | `linux:auth` (rsyslog), Suricata SID 9000010 |
| Dueño | SOC L1 |

## 1. Contexto

Un atacante externo intenta obtener acceso interactivo a un servidor Linux enviando múltiples combinaciones de usuario/contraseña vía SSH. Es una de las técnicas más comunes contra activos expuestos a Internet.

## 2. Superficie de ataque

- Servidores SSH expuestos (puerto 22 público)
- Cuentas con contraseñas débiles o por defecto
- Ausencia de fail2ban / MFA

## 3. Lógica de detección (Splunk)

```spl
index=soc_endpoints sourcetype=linux:auth status=Failed
| bin _time span=5m
| stats count dc(user) as unique_users values(user) as users by _time src_ip host
| where count >= 10
| eval mitre_technique="T1110.001", severity="high"
```

Se dispara si desde una misma IP hay ≥10 intentos fallidos en 5 min.

## 4. Respuesta esperada

### L1 (triaje, ≤15 min)
1. Confirmar en Splunk el volumen y ventana temporal.
2. ¿La IP origen está en lista de escaneres conocidos? Consultar Cortex (analyzer `AbuseIPDB`).
3. Verificar si algún intento resultó exitoso: `status=Accepted src_ip=<IP>`.
4. Crear caso en TheHive con severidad High.

### L2 (contención, ≤1h)
1. Si hubo login exitoso → escalar a UC de "Access exitoso post brute force" y ejecutar Playbook `brute-force-response.md`.
2. Bloquear IP origen en firewall perimetral / hosts.deny.
3. Rotar credenciales del usuario objetivo.
4. Revisar comandos ejecutados en la sesión (histfile, `last`, `w`).

### L3 (erradicación / lecciones)
1. Habilitar MFA + `fail2ban` con jail `sshd`.
2. Confirmar que Suricata SID 9000010 detectó el evento.
3. Añadir IP a lista negra permanente si es fuente maliciosa recurrente.

## 5. Falsos positivos

- Vulnerability scanners autorizados (Nessus, OpenVAS)
- Usuarios que olvidaron su contraseña
- Automatizaciones mal configuradas (Ansible con clave incorrecta)

Mitigación: mantener whitelist de IPs de escaneo en lookup `scanners_whitelist.csv`.

## 6. Simulación

Desde el host Kali/atacante:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<VICTIM_IP> -t 4
```

O usando `nmap`:

```bash
nmap --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt -p 22 <VICTIM_IP>
```

Verificación en Splunk: la alerta debe aparecer en `savedsearches.log` dentro de 5 min.

## 7. Métricas

- MTTD objetivo: ≤ 5 min
- MTTR objetivo (contención): ≤ 30 min
- Volumen esperado: 0-3 alertas/día en entorno normal
