# UC-005 — Persistencia por Scheduled Task

| Campo | Valor |
|-------|-------|
| ID | UC-005 |
| Táctica MITRE | Persistence (TA0003) |
| Técnica | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Severidad | Medium |
| Fuentes | WinEventLog Security 4698 (task created) / 4702 (updated) |
| Dueño | SOC L1 |

## 1. Contexto

El atacante crea una tarea programada para reejecutar su implante tras reinicio o en intervalos. Usa `schtasks.exe`, PowerShell (`New-ScheduledTask`), o el API COM.

## 2. Detección

```spl
index=soc_windows source="WinEventLog:Security" (EventCode=4698 OR EventCode=4702)
| eval mitre_technique="T1053.005", severity="medium"
| table _time host user TaskName TaskContent
```

Enriquecer con lista de tareas legítimas conocidas y alertar sobre nuevas.

## 3. Respuesta

### L1
1. Extraer del XML el `<Command>` y `<Arguments>`.
2. Validar hash del binario ejecutado (`Get-FileHash`, luego consultar VirusTotal en Cortex).
3. Si el binario está en `%TEMP%`, `%APPDATA%`, o rutas de usuario → alta sospecha.

### L2
1. Deshabilitar tarea: `schtasks /Change /TN <name> /DISABLE`.
2. Aislar host.
3. Colectar el binario para análisis en Cortex sandbox.
4. Búsqueda lateral: `schtasks /query /S <host>` en hosts pares.

### L3
1. GPO auditando creación de tareas (Event 4698 forzado).
2. WDAC / AppLocker restringiendo rutas ejecutables.

## 4. Simulación

```powershell
schtasks /Create /SC MINUTE /MO 5 /TN "SOC-Lab\UC005-Test" /TR "cmd.exe /c echo persistencia" /RU SYSTEM
```

## 5. Falsos positivos

- Actualizaciones de software (Chrome, Adobe, Microsoft Update).
- Backups programados.
