# UC-003 — PowerShell ofuscado / EncodedCommand

| Campo | Valor |
|-------|-------|
| ID | UC-003 |
| Táctica MITRE | Execution (TA0002) |
| Técnica | T1059.001 — PowerShell |
| Severidad | High |
| Fuentes | Sysmon EventCode=1, PowerShell Operational (EIDs 4103/4104) |
| Dueño | SOC L1 → L2 |

## 1. Contexto

PowerShell es el intérprete de facto para post-explotación en Windows. Los atacantes usan `-EncodedCommand`, base64, y técnicas de ofuscación (Invoke-Obfuscation, PowerSploit) para eludir AV/EDR y firmas simples.

## 2. Detección

```spl
index=soc_windows sourcetype=sysmon:operational EventCode=1
  ("powershell.exe" OR "pwsh.exe")
  ("-EncodedCommand" OR "-enc " OR "FromBase64String" OR "IEX(" OR "Invoke-Expression")
| eval mitre_technique="T1059.001", severity="high"
| table _time host user image cmdline parent_image
```

## 3. Respuesta

### L1
1. Decodificar el comando base64:
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<enc>"))
   ```
2. Enviar el string decodificado a Cortex → analyzers `MalwareBazaar`, `Yara`.
3. Identificar parent process — `explorer.exe` con powershell hijo ofuscado = altamente sospechoso.

### L2
1. Aislar host.
2. Capturar volcado de memoria (`Get-Process powershell | Out-MiniDump`).
3. Buscar persistencia asociada: tareas programadas, Run keys, WMI subscriptions.
4. IoC hunting sobre `image`, `cmdline hash`.

### L3
1. Habilitar Constrained Language Mode donde aplique.
2. AppLocker/WDAC bloqueando PowerShell v2.
3. Enviar sesiones de PowerShell (ScriptBlock Logging EID 4104) a Splunk.

## 4. Simulación

```powershell
$cmd = "Write-Host 'Test SOC-Lab UC-003'"
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc
```

## 5. Falsos positivos

- Software de administración (SCCM, LabTech) que usa `-EncodedCommand` legítimamente.
- Módulos de PowerShell firmados por Microsoft.

Excepción: whitelist por `parent_image` + hash del script.
