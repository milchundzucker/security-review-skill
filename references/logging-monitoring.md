# Logging, Monitoring & Observability Security

Geladen, wenn das Projekt Logging-Code, Monitoring-Setup, oder sicherheitsrelevante Operationen enthält. Ergänzt OWASP A09 (Security Logging and Monitoring Failures).

Logging hat zwei Sicherheitsaspekte:
1. **Logs als Defense-Tool** (Detection, Forensics, Audit)
2. **Logs als Angriffsfläche** (Log Injection, PII-Leak, Log Tampering)

## 1. Pflicht-Logs (für Defense)

### Was geloggt werden MUSS

Sicherheitskritische Events:
- [ ] Authentication-Versuche (Erfolg UND Misserfolg)
- [ ] Authorization-Failures (403)
- [ ] Password-Resets, Email-Changes, MFA-Setup-Änderungen
- [ ] Privileged Operations (Admin-Aktionen, User-Delete, Role-Change)
- [ ] Geld-Transaktionen / Zahlungsverkehr
- [ ] Data Access auf sensible Daten (PII, PHI)
- [ ] Configuration-Changes
- [ ] Input-Validation-Failures (potenzielle Angriffsversuche)
- [ ] Crypto-Operations (Key-Use, Signature-Verification-Failures)

### Pflicht-Felder pro Log-Event

Strukturiertes Logging (JSON) statt freier Text:
- `timestamp` (ISO 8601, UTC)
- `event_id` / `event_type` (enum)
- `user_id` (intern, NICHT Email/Name)
- `session_id` (gehashed)
- `source_ip` (oder gehashed bei DSGVO-Strenge)
- `user_agent`
- `correlation_id` / `trace_id`
- `outcome` (success / failure)
- `resource_affected`
- Bei Failure: `failure_reason` (enum, NICHT free-text mit Details)

### Detection
```
rg "logger|logging|log\(" --type py --type js --type java -A 2
rg "logging\.getLogger|LoggerFactory|winston|pino|bunyan" -A 5
rg "audit_log|securityLog|SecurityLog" -A 3
```

---

## 2. Was NICHT geloggt werden darf

### Sensitive Inputs
- Passwörter (Klartext UND Hash bei Auth-Failures!)
- API-Keys, Tokens (auch Refresh-Tokens)
- Session-Cookies
- Credit-Card-Nummern, CVV
- PII außerhalb von Audit-Logs (sonst DSGVO-Verstoß)
- Authorization-Header (außer gehashed)
- Body von 4xx/5xx Responses, wenn Body sensitive Daten enthält

### Detection
```
rg "log.*password|logger\..*password|print.*password" -i
rg "log.*api[_-]?key|log.*token|log.*authorization" -i
rg "logger\.(info|debug)\(.*req\.body|console\.log\(.*req\.body" --type js
```

### Pitfalls
- "Wir loggen nur in Debug-Level" — Debug-Level oft in Production aktiv (`LOG_LEVEL=debug` aus Env)
- Crash-Reports (Sentry, Rollbar): sensitive Daten landen automatisch in 3rd-Party-Service
- Stack-Traces enthalten oft `repr(self)` mit allen Object-Attributes
- ORM-Logging zeigt SQL mit Parametern (incl. Passwort-Hash)

### Logger-Konfig prüfen
- Sentry: `before_send` Hook für Scrubbing aktiv?
- Django: `SAFE_LOGS_FILTER` aktiv?
- Express/Bunyan: `serializers` mit `req.body`-Filter?
- Java/Logback: `MDC` mit sensitiver Info?

---

## 3. Log Injection

**Was:** User-Input wird unescaped in Logs geschrieben → kann Log-Aggregator (Splunk, ELK) verwirren, Logs faken, oder weiter eskalieren (Log4Shell).

### Detection
```
rg "logger\..*\+.*request|logger\..*\$\{.*request" --type java
rg "logger\..*\+.*req\.|logger\.info\(.*req\." --type js
rg "logging\.info\(.*\%.*request" --type py
```

### Unsicher
```python
logger.info(f"User login: {request.form['username']}")
# Angreifer: username = "alice\n2024-01-01 INFO User login: admin"
# → fake Log-Eintrag eingeschleust
```

### Sicher
- Strukturiertes Logging (JSON) — Newlines escaped
- Sanitization: `\r\n` filtern aus User-Input
- Niemals format-strings mit User-Input (`logger.info(user_input)` statt `logger.info("...", user_input)`)

### Log4Shell-artige Issues
- `${...}`-Expansion in Log-Strings (CVE-2021-44228)
- Format-String-Bugs in C/C++ Logging
- Spring-Expression-Language in Logback-Pattern

---

## 4. Log Tampering / Integrity

### Anti-Patterns
- Logs nur lokal auf der App-Server-Disk (kann Angreifer löschen)
- Logs ohne Append-Only-Flag
- Logs mit Schreibrechten für App-User
- Keine zentrale Aggregation (App-Compromise → Logs weg)

### Sicher
- Sofortige Forwarding an externen Aggregator (Splunk, Datadog, ELK, Loki)
- Read-only Mount für Log-Verzeichnis (App schreibt nur via stdout, fluent-bit liest)
- Append-only-Flag (`chattr +a` auf Linux)
- Cryptographic Hash-Chain (jeder Log-Eintrag enthält Hash des vorigen)
- WORM-Storage für Compliance-Logs (Write-Once-Read-Many)

### Detection
```
rg "fluent|filebeat|vector|otel-collector|datadog-agent" --type yaml
rg "audit\..*signed|hmac.*log" --type py --type go
```

---

## 5. Log-Retention

### Anforderungen variieren

| Regulierung | Retention |
|-------------|-----------|
| DSGVO | "Solange notwendig" — typisch 90 Tage – 1 Jahr für Security-Logs |
| PCI-DSS | 1 Jahr online, davon 3 Monate sofort verfügbar |
| HIPAA | 6 Jahre |
| NIS2 | nach EU-Mitgliedstaat-Recht, typisch 1-3 Jahre |
| Telekom-G (DE) | 7 Tage (TKG §96) |
| SOX | 7 Jahre |

### Anti-Patterns
- Retention zu kurz (kann nicht forensisch ermitteln)
- Retention zu lang (DSGVO-Verstoß bei PII in Logs)
- Keine automatisierte Löschung — manuell vergessen

### Detection
```
rg "retention|max_age|log_retention" --type yaml --type tf -A 3
```

---

## 6. Monitoring & Alerting

### Was muss alerten

- Mehrere fehlgeschlagene Logins für gleichen User → Brute-Force
- Mehrere fehlgeschlagene Logins von gleicher IP → distributed Brute-Force
- Login von neuer Geo-Location → unusual access
- Privilege Escalation (User wird zu Admin)
- Massenhafte DELETE-Operationen
- Outbound-Connections zu Tor / bekannten C2-Servern
- Plötzlicher Traffic-Spike (DoS-Signal)
- Disk-Full (Logging stoppt sonst → Detection blind)
- Failed Backup
- Certificate-Expiry (90 days warning)

### Anti-Patterns
- Alert auf alles → Alert-Fatigue, ignoriert
- Kein Runbook pro Alert
- Alert nur via Email — Out-of-band-Mechanismus fehlt bei Email-Provider-Outage
- Alerts gehen nur an eine Person — Bus-Faktor 1

### Detection
```
rg "alert|prometheus_rule|grafana_alert" --type yaml -A 5
rg "PagerDuty|OpsGenie|VictorOps" --type yaml --type tf
```

---

## 7. Centralized Logging Pitfalls

### Datendurchsatz
- App generiert 10 GB/Tag Logs → Splunk-Lizenz $$$
- Log-Sampling für hochfrequente Events (z. B. 1% von Health-Checks)

### Datenschutz im SIEM
- SIEM-Indexer hat alle Logs → ein einziger Compromise-Point
- IAM für SIEM kritisch — Read-Access nur Need-to-Know
- DSGVO Drittland: Splunk Cloud US? Datadog US? — SCCs prüfen

### Log-Forwarding-Security
- TLS für Log-Forwarder (Fluentbit, Vector, OTel-Collector)
- mTLS für SIEM-Verbindung
- Backpressure-Handling: Logs nicht verlieren bei Burst

---

## 8. Forensik-Bereitschaft

Code sollte forensisch nachvollziehbar machen:
- Wer hat was wann mit welchem Outcome gemacht
- Welche Daten waren betroffen
- Korrelation über Service-Grenzen (Distributed Tracing)

### Was im Bericht zu prüfen

- [ ] Pro Service: Trace-Context-Propagation (W3C Trace Context, B3)?
- [ ] Cross-Service-Correlation-ID konsistent?
- [ ] Audit-Trail pro sensitivem Datensatz (Read-Audit, nicht nur Write)?
- [ ] "Tombstones" bei Hard-Delete (was war es vorher)?
- [ ] Incident-Response-Runbook für Standard-Szenarien?

---

## 9. Observability-spezifisch

### OpenTelemetry / Tracing
- Spans mit Sensitive Daten als Attributes (Passwörter, Tokens)?
- Tracing-Endpoint authentifiziert?
- Sampling-Rate für Production angemessen?

### Metrics
- Cardinality-Explosion (Metric mit user_id als Label → Millionen Series → Cost-DoS)
- Privacy: Metric-Namen verraten Geschäftsgeheimnisse

### Profiling
- Production-Profiling kann Memory-Inhalte exponieren
- Heap-Dumps enthalten Strings (auch Secrets)

---

## 10. Patterns je nach Logging-Library

### Python
- `logging` module: keine sensiblen Defaults
- Use `Filter` für Scrubbing
- Structlog für strukturierte Logs

### JavaScript/Node
- Pino, Winston: serializers + redact-options nutzen
- `pino-pretty` nicht in Production
- `req.headers.authorization` automatisch redacten

### Java
- Logback `<pattern>` ohne Format-String-Injection
- Log4j 2.17+ (gegen Log4Shell)
- Mask-Pattern in `logback-spring.xml`

### Go
- `slog` (1.21+) als Standard
- Strukturiert: `slog.Info("event", "user", id)` statt `Printf`

### Frameworks
- Spring: `MDC`-Filter für Auth-Context
- Django: `LOGGING` Config mit Filter-Klassen
- Express: Morgan mit custom-format ohne Body
- Rails: parameter_filter mit Whitelist

---

## Empfohlenes Standard-Set

Für jedes Projekt mindestens:
1. **Structured Logging** (JSON) statt freier Text
2. **Trace-Context-Propagation** für Distributed Systems
3. **Zentraler Aggregator** außerhalb des App-Servers
4. **PII-Scrubbing** vor Log-Output (Whitelist-basiert)
5. **Audit-Log getrennt** von App-Log (anderer Index, andere Retention)
6. **Alerts** auf min. 10 sicherheitskritische Events

---

## Mappings

- OWASP A09 (Security Logging and Monitoring Failures)
- CWE-117 Log Output Neutralization, CWE-532 Log of Sensitive Information, CWE-778 Insufficient Logging, CWE-779 Logging of Excessive Data
- NIST SP 800-92 (Guide to Computer Security Log Management)
- PCI-DSS Requirement 10
- ISO 27001 A.8.16 (Monitoring Activities)
