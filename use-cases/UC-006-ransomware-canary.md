# UC-006 — Ransomware detectado por Canary Files

| Campo | Valor |
|-------|-------|
| ID | UC-006 |
| Táctica MITRE | Impact (TA0040) |
| Técnica | T1486 — Data Encrypted for Impact |
| Severidad | Critical |
| Fuentes | File-monitoring (auditd Linux, Sysmon EID 11 Windows) sobre `\canary\*` |
| Dueño | SOC L1 → escalado inmediato |

## 1. Contexto

Se colocan **archivos señuelo (canaries)** en shares y directorios de usuario. Cualquier proceso que renombre, sobrescriba o borre estos archivos es sospechoso: usuarios normales no los tocan, ransomware sí (recorre y cifra).

## 2. Detección

```spl
index=soc_endpoints (source=*canary* OR path=*canary*) ("write" OR "delete" OR "rename")
| stats count values(process) as procs by host user path
| where count > 3
| eval mitre_technique="T1486", severity="critical"
```

## 3. Respuesta — protocolo IR de crisis

### Contención (0-15 min)
1. **Aislar host inmediatamente** — quarantine VLAN o `Disable-NetAdapter`.
2. Bloquear cuenta del usuario.
3. Congelar snapshots de storage (impedir replicación destructiva).
4. Notificar a CSIRT y liderazgo (playbook `ransomware-response.md`).

### Erradicación (15 min - 4 h)
1. Identificar cepa: hash del binario + note de rescate → consultar `ID-Ransomware`.
2. Buscar cuentas comprometidas usadas para desplegar el ransomware.
3. Auditar accesos de esas cuentas en las últimas 72h.

### Recuperación
1. Restaurar desde backups offline validados.
2. NO pagar rescate (política corporativa + posibles sanciones OFAC).

### Post-mortem
1. Vector inicial (phishing / RDP expuesto / vulnerabilidad).
2. Tiempo de dwell (primer acceso → cifrado).
3. Controles que fallaron / faltaban.

## 4. Simulación (segura para lab)

```bash
# Linux — crear canaries
mkdir -p /srv/shares/canary
for i in 1 2 3 4 5; do
  cp /etc/hostname "/srv/shares/canary/DO_NOT_TOUCH_$i.txt"
done

# Simular "ransomware" (solo renombra, no cifra)
cd /srv/shares/canary
for f in *; do mv "$f" "$f.LOCKED"; done
```

Auditd config previa:

```
-w /srv/shares/canary/ -p wa -k canary_write
```

## 5. Falsos positivos

- Copias masivas legítimas (migraciones, backups full).
- Indexadores (Everything, macOS Spotlight) escaneando el directorio.

Mitigación: los canaries deben estar en rutas NO accedidas por indexers, con nombres que atraigan al ransomware (`00-DO_NOT_ENCRYPT.docx`).
