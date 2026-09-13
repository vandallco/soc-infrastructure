# Feeds MISP recomendados

Habilitar en MISP → **Sync Actions → List Feeds** → Enable + Cache.

| Feed | Tipo | Actualización | Uso |
|------|------|---------------|-----|
| CIRCL OSINT Feed | eventos MISP | 1h | Threat intel general |
| abuse.ch URLhaus | dominios/URLs malware | 5 min | Cinéfilo de C2 web |
| abuse.ch Feodo Tracker | IPs botnet (Emotet, Dridex, TrickBot) | 5 min | C2 de banking trojans |
| abuse.ch SSL Blacklist | huellas SSL malware | 30 min | Detección TLS malicioso |
| abuse.ch ThreatFox | multi-tipo IoC | 5 min | Multi-uso |
| Botvrij.eu | eventos MISP | 1h | Enriquecimiento adicional |
| CyberCrime Tracker | URLs C2 | 4h | HTTP C2 |

## Configuración adicional

- **Aging:** desactivar IoCs con `first_seen > 180 días` sin sightings recientes.
- **TLP:** mantener eventos TLP:GREEN o superior.
- **Sightings:** cada match en Splunk debe publicar sighting de vuelta a MISP (script pendiente).
