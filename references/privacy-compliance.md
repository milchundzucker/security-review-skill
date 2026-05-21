# Privacy & Compliance Mapping

Diese Referenz wird geladen, wenn das Projekt PII / personenbezogene Daten verarbeitet (Healthcare, Finanz, EU-User), oder wenn der User explizit Compliance-Mapping anfordert.

Hier werden Code-Befunde auf die Anforderungen relevanter Regelwerke gemappt:
- **DSGVO / GDPR** (EU)
- **NIS2** (EU, kritische Infrastruktur)
- **BSI IT-Grundschutz** (DE)
- **PCI-DSS** (Zahlungsverkehr)
- **HIPAA** (US Health)
- **SOC 2** (US Service Organizations)
- **ISO 27001** (international)

**Wichtig:** Compliance-Mapping ist eine Hilfe für die Priorisierung — der Skill ersetzt keine rechtliche Beratung und keinen formalen Audit. Findings im Bericht klar als "compliance-relevant" markieren, aber keine Aussagen wie "ist DSGVO-konform" treffen.

## DSGVO / GDPR

### Code-relevante Artikel

| Artikel | Anforderung | Code-Befund-Kategorie |
|---------|-------------|------------------------|
| Art. 5 | Datenminimierung | Übermäßige Datensammlung, fehlende Retention |
| Art. 6 | Rechtmäßigkeit | Fehlende Consent-Mechanismen |
| Art. 7 | Bedingungen für Einwilligung | Pre-checked Checkboxes, Dark Patterns |
| Art. 17 | Recht auf Löschung | Fehlende `DELETE`-Endpoints für User-Daten |
| Art. 20 | Datenportabilität | Fehlende Export-Funktion |
| Art. 25 | Privacy by Design | Defaults zu offen, Opt-Out statt Opt-In |
| Art. 32 | Sicherheit der Verarbeitung | Verschlüsselung, Pseudonymisierung |
| Art. 33-34 | Meldepflichten | Fehlende Audit-Logs, Incident-Response-Mechanismen |
| Art. 35 | DSFA / DPIA | Hochrisiko-Verarbeitungen ohne Folgenabschätzung |
| Art. 44+ | Drittland-Übermittlung | US-Cloud-Provider ohne SCCs |

### Konkrete Suchen

**PII identifizieren:**
```
rg -i "email|phone|address|birth.*date|ssn|tax.*id|iban|passport" --type py --type js -A 2
rg "User\.|Customer\.|Patient\." --type py -A 5  # PII-Container?
```

**Datenminimierung / Logging-Hygiene:**
```
rg "log.*user\.|log.*email|print.*password" -i  # PII in Logs
rg "logger\.(info|debug)\(.*user" --type py -A 2
rg "console\.log\(.*user\." --type js -A 2
```

**Right to be Forgotten:**
```
rg "DELETE.*FROM.*users|users\.delete\(\)" --type py --type js  # gibt's das?
rg "@router\.delete.*user|@app\.delete.*user" --type py
rg "soft.?delete|deleted_at" -A 3  # Soft-Delete-Pattern
```

**Datenexport:**
```
rg "export|portability|data_subject_request|dsar" -i --type py --type js
```

### Typische Befund-Kategorien

| Befund | DSGVO-Bezug |
|--------|-------------|
| PII in Logs | Art. 5 (Datenminimierung), Art. 32 (Sicherheit) |
| Fehlende Verschlüsselung at-rest | Art. 32 |
| Fehlende Verschlüsselung in-transit | Art. 32 |
| Fehlende Pseudonymisierung | Art. 32 |
| Daten in nicht-EU-Cloud ohne SCC/Adequacy | Art. 44 |
| Keine Datenlöschung möglich | Art. 17 |
| Keine Datenexport möglich | Art. 20 |
| Keine Audit-Logs für Zugriff auf PII | Art. 32, 33 |
| 3rd-Party-Tracker / Analytics ohne Consent | Art. 6, 7 |
| Übermäßige Datenfelder erfasst | Art. 5 |
| Default-Settings: alles aktiviert | Art. 25 |

### Spezielle Kategorien (Art. 9)

Sensible Daten (Health, Religion, Politik, sexuelle Orientierung, biometrisch, genetisch): braucht **explizite Einwilligung** + **erhöhte Schutzmaßnahmen**.

Wenn solche Daten im Code zu sehen sind, im Bericht **erhöhte Aufmerksamkeit** markieren.

---

## NIS2 (EU)

### Anwendungsbereich

NIS2 gilt für "wesentliche" und "wichtige" Einrichtungen in 18 Sektoren (Energie, Gesundheit, Banken, digitale Infrastruktur, ...). Wenn das Projekt unter NIS2 fällt, gelten erhöhte Anforderungen.

### Code-relevante Anforderungen

- **Art. 21 Risikomanagement-Maßnahmen:**
  - Verschlüsselung
  - Multi-Factor Authentication für privilegierte Konten
  - Backups + Wiederherstellungsverfahren
  - Lieferkettensicherheit (Supply Chain)
  - Vulnerability Management
  - Patch Management

- **Art. 23 Meldepflicht:**
  - "Early Warning" innerhalb 24h, Update binnen 72h, Final-Report binnen 1 Monat
  - Code muss Incident-Detection ermöglichen → Logging-Befunde sind NIS2-relevant

### Code-Befunde mit NIS2-Bezug

- Fehlende MFA für Admin → Art. 21
- Fehlende oder schwache Backup-Mechanismen → Art. 21
- Fehlende Audit-Logs → Art. 21, 23
- Supply-Chain-Schwachstellen (`cicd-supply-chain.md`) → Art. 21
- Fehlendes Vulnerability-Management (kein Dependabot, kein osv-scanner) → Art. 21

---

## BSI IT-Grundschutz

Im DACH-Raum relevant, insbesondere für Behörden und KRITIS.

### Code-relevante Bausteine

- **CON.8 Software-Entwicklung**: Secure Coding Practices
- **CON.9 Informationsaustausch**: Sichere Kommunikation
- **ORP.4 Identitäts- und Berechtigungsmanagement**: Auth-Hardening
- **NET.3 Verzeichnisdienste**: SSO/LDAP-Sicherheit
- **OPS.1 Eigenbetrieb**: Patch-Mgmt, Backup
- **APP.* Anwendungen**: spezifisch je nach Typ (Webserver, DBMS, etc.)

### Anforderungs-Stufen
- **Basis** (B) — minimum
- **Standard** (S) — typisch
- **Erhöhter Schutzbedarf** (H) — kritische Systeme

Befunde im Bericht ggf. mit BSI-Modul-ID referenzieren, z. B. "CON.8.A6 Sichere Programmierung".

---

## PCI-DSS

Wenn Zahlungsverkehr / Kreditkarten verarbeitet werden.

### Code-relevante Requirements (v4.0)

| Req | Anforderung | Code-Befund |
|-----|-------------|-------------|
| 3 | Schutz gespeicherter Kreditkartendaten | PAN unverschlüsselt, CVV gespeichert (verboten!) |
| 4 | Verschlüsselung in-transit | TLS-Konfig, schwache Cipher |
| 6 | Sichere Systeme & Anwendungen | OWASP Top 10 Findings |
| 7 | Need-to-know-Prinzip | Übermäßige IAM-Permissions |
| 8 | Eindeutige IDs + MFA | Auth-Findings |
| 10 | Logging | Audit-Logs-Befunde |
| 11 | Regelmäßige Tests | Code-Review-Etablierung |

### Critical-Befunde im PCI-Kontext
- **CVV jemals gespeichert** → automatisch Fail (Req 3.3.2)
- **PAN in Logs** → Fail (Req 3.3, 10)
- **Test-Kartendaten in Production** → Fail
- **Tokenization nicht genutzt** → Befund (für Verbesserung)

```
rg -i "cvv|cvc|card.?verification" --type py --type js -A 3
rg "credit.?card|card.?number|pan\b" -i --type py -A 3
```

---

## HIPAA (US Health)

### Code-relevante Safeguards (Security Rule)

| § | Safeguard | Code-Befund |
|---|-----------|-------------|
| 164.312(a) | Access Control | BAC-Findings auf PHI |
| 164.312(b) | Audit Controls | Logging-Findings |
| 164.312(c) | Integrity | Crypto-Hashing für PHI-Integrität |
| 164.312(d) | Person Authentication | MFA-Findings |
| 164.312(e) | Transmission Security | TLS-Findings |

PHI (Protected Health Information) entdecken:
```
rg -i "patient|diagnosis|medical|prescription|treatment" --type py --type js -A 2
```

Wenn das Projekt PHI verarbeitet, sind HIPAA-Sanctions schwerwiegend (Fines bis 1.5M USD/Jahr/Verstoß).

---

## SOC 2

Trust Services Criteria — am häufigsten **CC** (Common Criteria), **A** (Availability), **C** (Confidentiality).

Code-Befunde im Kontext SOC 2:
- Access Control → CC6
- Change Management → CC8 (Code-Review-Prozesse, Deployment-Gates)
- Risk Mitigation → CC9
- Logical Access → CC6
- System Operations → CC7 (Monitoring, Incident Response)

SOC 2 ist primär Prozess-Audit, aber Code-Schwächen sind Evidenz gegen Controls.

---

## ISO 27001 / 27002

Code-Befunde mappen auf Annex-A-Controls (ISO 27001:2022 hat 93 Controls):

- A.5 Organizational controls
- A.6 People controls
- A.7 Physical controls
- A.8 Technological controls (← hier die meisten Code-Befunde)

Wichtige A.8-Controls:
- A.8.5 Secure authentication (Auth-Findings)
- A.8.8 Management of technical vulnerabilities (Dependency-Findings)
- A.8.9 Configuration management (IaC-Findings)
- A.8.12 Data leakage prevention (Logging, PII-Findings)
- A.8.16 Monitoring activities (Audit-Logging)
- A.8.24 Use of cryptography (Crypto-Findings)
- A.8.25 Secure development life cycle (Dev-Practice-Findings)
- A.8.27 Secure system architecture (Design-Findings)
- A.8.28 Secure coding (Coding-Findings)

---

## Praktische Anwendung

### Im Bericht

Compliance-Mapping als **eigene Spalte** in der Befundtabelle oder als **separater Abschnitt** "Compliance Relevance":

```
| Finding | Severity | DSGVO | PCI | NIS2 |
|---------|----------|-------|-----|------|
| SEC-01  | Critical | Art. 32 | Req 6 | Art. 21 |
| SEC-02  | High     | Art. 5  | Req 3 | -      |
```

### Was NICHT zu tun

- **Keine "Compliant"/"Non-compliant"-Pauschalaussagen.** Compliance ist Prozess + Audit, nicht Code-Check.
- **Keine erfundenen Compliance-Bezüge.** Wenn der Bezug schwach ist: weglassen.
- **Keine rechtlichen Empfehlungen.** Auf Notwendigkeit eines Datenschutzbeauftragten/Anwalts hinweisen.

### Empfehlung für den Bericht-Abschluss

> "Diese Analyse identifiziert Code-seitige Schwachstellen, die compliance-relevant sein können. Für eine formale Konformitätsbewertung empfehlen wir eine vollständige Audit durch qualifizierte Auditoren (ISO 27001-LA, CISA, PCI-QSA, etc.) sowie Rücksprache mit dem Datenschutzbeauftragten."
