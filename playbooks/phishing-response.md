# Playbook — Phishing / Credencial comprometida

**Owner:** SOC L1
**Trigger:** Reporte usuario, alerta secure email gateway, login geo-anómalo

## 1. Triaje

1. Analizar el correo: cabeceras (SPF/DKIM/DMARC), URLs, adjuntos.
2. Detonar URLs en sandbox (Cortex `URLScan`, `AnyRun`).
3. Extraer IoCs: sender, dominios, IPs, hashes.

## 2. Contención

1. Eliminar el correo de todos los buzones (M365: `Search-Mailbox`, Google: Vault).
2. Bloquear sender/dominios en gateway.
3. Si el usuario clicó / entregó credenciales:
   - Forzar reset de contraseña.
   - Invalidar todas las sesiones/tokens activos.
   - Habilitar MFA obligatorio (si no lo estaba).

## 3. Erradicación

- Revisar reglas de forwarding creadas post-compromiso (típico de BEC).
- Auditar cambios en delegates y roles.
- Verificar accesos a Sharepoint/Drive del usuario en las últimas 30 días.

## 4. Recuperación

- Comunicación al usuario.
- Awareness targeted (retraining opcional).

## 5. Lecciones

- ¿La campaña afectó a más usuarios? Query global en logs de correo.
- ¿El SEG dejó pasar el mensaje? Ajustar reglas.
- Actualizar simulacros de phishing.
