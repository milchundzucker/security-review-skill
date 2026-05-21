# Threat Modeling (STRIDE / DREAD / PASTA)

Geladen, wenn der User explizit Threat Modeling anfordert, ein Architektur-Review macht, oder die Codebase signifikante neue Features einführt, die ein DFD (Data-Flow-Diagram) brauchen.

Threat Modeling ist die strukturierte Frage: "Was kann hier schiefgehen — und wer hat die Mittel und das Motiv?" — VOR dem Code-Review.

## STRIDE — die Standard-Klassifikation

| Kategorie | Verletzt | Typische Bedrohung |
|-----------|----------|---------------------|
| **S**poofing | Authentication | Identität fälschen (Phishing, Token-Theft, Spoofed Source) |
| **T**ampering | Integrity | Daten/Code manipulieren (DB-Tampering, MITM, Code-Injection) |
| **R**epudiation | Non-Repudiation | Aktion abstreiten können (kein Audit-Log, manipulierbares Log) |
| **I**nformation Disclosure | Confidentiality | Datenleck (BOLA, SSRF, verbose Errors, PII-Logs) |
| **D**enial of Service | Availability | Verfügbarkeit zerstören (RegEx-DoS, Gas-Limit, Bandwidth) |
| **E**levation of Privilege | Authorization | Höhere Rechte erlangen (BAC, Container-Escape, RCE) |

## Wann Threat Modeling einsetzen

1. **Neue Features** mit Auth, externen Inputs, Geld-Flüssen, sensitiven Daten
2. **Architektur-Änderungen** (neue Services, neue Trust-Boundaries)
3. **Regulatorischer Anlass** (NIS2 Art. 21 verlangt Risikomanagement)
4. **Vor großen Audits** zur Aufwandsabschätzung

## Workflow (in 4 Schritten)

### Schritt 1: System-Modellierung (DFD)

Identifizieren:
- **Processes** (Komponenten, die Logik ausführen)
- **Data Stores** (DBs, Files, Caches)
- **External Entities** (User, 3rd-Party-APIs)
- **Data Flows** (Pfeile dazwischen)
- **Trust Boundaries** (gestrichelte Linien — wo wechselt Vertrauen?)

### Schritt 2: Bedrohungen identifizieren (STRIDE pro Element)

Für jedes Element die zutreffenden STRIDE-Kategorien durchgehen:

| Element-Typ | Anwendbare STRIDE |
|-------------|---------------------|
| External Entity | S, R |
| Process | S, T, R, I, D, E |
| Data Store | T, R, I, D |
| Data Flow | T, I, D |

### Schritt 3: Bewerten (DREAD oder CVSS)

DREAD (klassisch):
- **D**amage Potential
- **R**eproducibility
- **E**xploitability
- **A**ffected Users
- **D**iscoverability

Jeweils 1–10, Summe / 5 = Score.

Heute oft besser: CVSS 3.1 oder direkte Severity-Skalierung (siehe `severity-scoring.md`).

### Schritt 4: Mitigations zuordnen

Pro Bedrohung:
- **Mitigate** (Kontrolle einbauen)
- **Eliminate** (Feature/Code entfernen)
- **Transfer** (Versicherung, 3rd-Party-Dienst)
- **Accept** (mit Risikoeintrag in Risk-Register)

## STRIDE-Checklisten pro Kategorie

### Spoofing
- Auth-Mechanismus vorhanden und stark?
- MFA für privilegierte Operationen?
- Session-Hijacking-Schutz (Secure, HttpOnly, SameSite)?
- API-zu-API: mTLS, signierte Tokens?
- DNS-Spoofing-Resistenz (DNSSEC, Cert-Pinning)?
- Source-Spoofing in Logs/Emails (SPF, DKIM, DMARC)?

### Tampering
- Integritätsschutz für Daten in Transit (TLS)?
- Integritätsschutz für Daten at Rest (Checksums, HMAC)?
- Code-Signing für Artefakte?
- Audit-Log mit Hash-Chain / Tamper-Detection?
- Schutz vor Race-Conditions (siehe `race-conditions.md`)?

### Repudiation
- Audit-Log vorhanden für sicherheitsrelevante Aktionen?
- Logs zentral aggregiert (kann nicht lokal manipuliert werden)?
- Logs signiert / append-only?
- User-ID + Timestamp + Source-IP in Logs?
- Logs retention-konform (siehe `privacy-compliance.md`)?

### Information Disclosure
- Authorization auf Object- und Field-Level (siehe API3 BOPLA)?
- TLS für alle Daten in Transit?
- Verschlüsselung at Rest?
- Error-Messages reveal-nothing?
- Stack-Traces nicht zum User?
- Debug-Endpoints in Production deaktiviert?
- SSRF-Schutz (interne Services nicht erreichbar von public-facing)?

### Denial of Service
- Rate Limiting (pro IP, pro User, pro API-Key)?
- Resource-Limits (Memory, CPU, Disk, Network)?
- ReDoS-Schutz (RegEx-Timeout)?
- Pagination (kein unbounded Result-Set)?
- Schutz vor Zip-Bombs / XML-Bombs?
- Connection-Limits?
- Graceful-Degradation bei 3rd-Party-Ausfall?

### Elevation of Privilege
- Least-Privilege für Service-Accounts?
- Role-Hierarchie konsistent enforced?
- Privilege-Separation zwischen Tenants?
- Sandboxing für Untrusted Code (WASM, gVisor, Firecracker)?
- Container-Privileges minimal?
- Sudo-Konfiguration minimal?

## DFD-Beispiel (Skizze, schriftlich)

Für eine typische SaaS-App:

```
External Entities:    User (Browser), Admin (Browser), Stripe (Webhook)
Processes:            CDN, LoadBalancer, Web-App, API, Background-Worker
Data Stores:          PostgreSQL, Redis-Cache, S3-Uploads
Trust Boundaries:     [Internet | DMZ], [DMZ | Internal], [App | DB]
```

Bedrohungs-Tabelle pro Trust-Boundary-Crossing:

| Flow | Spoof | Tamper | Repud | InfoDisc | DoS | EoP |
|------|-------|--------|-------|----------|-----|-----|
| User → CDN | ✓ TLS+Auth | ✓ TLS | n/a | TLS | DDoS-Schutz | n/a |
| CDN → LB | ✓ mTLS? | ✓ mTLS? | n/a | ✓ | n/a | n/a |
| API → DB | ✓ DB-Auth | DB-TLS | ✓ DB-Audit | ✓ TLS | Connection-Pool | Least-Priv |
| API → Stripe-Webhook | ✓ Sig-Verify | ✓ HTTPS | ✓ Stripe-Log | ✓ | n/a | n/a |

Pro "?"- oder Lücke-Eintrag → potenzieller Befund.

## PASTA — Process for Attack Simulation and Threat Analysis

Für tiefere Threat-Modeling-Phasen:

1. Define Objectives (Business)
2. Define Technical Scope
3. Application Decomposition (DFD)
4. Threat Analysis (Threat Intelligence)
5. Vulnerability Analysis (technisch)
6. Attack Modeling (Attack Trees)
7. Risk & Impact Analysis

PASTA ist umfassender als STRIDE — für Code-Review meist Overkill, für Pre-Launch-Audit großer Systeme angemessen.

## Attack-Tree-Modellierung

Für hochwertige Assets (Zentrales Auth-System, Wallet, Crown-Jewels):

```
Root: "Steal $10M from Treasury"
├── 1. Compromise Admin Account
│   ├── 1.1 Phishing Admin
│   ├── 1.2 Steal Admin Cookie (XSS)
│   ├── 1.3 SIM-Swap on Admin Phone
│   └── 1.4 Insider Threat
├── 2. Exploit Smart Contract Bug
│   ├── 2.1 Reentrancy
│   ├── 2.2 Oracle Manipulation
│   └── 2.3 Logic Error
└── 3. Cloud-Account-Compromise
    ├── 3.1 IAM-Misconfig
    ├── 3.2 Compromised CI/CD
    └── 3.3 SSRF + IMDS
```

Pro Leaf-Node: Wahrscheinlichkeit, Cost-to-Attacker, vorhandene Mitigations.

## LINDDUN — Privacy-Threat-Modeling

Analog zu STRIDE, aber für Privacy:
- **L**inkability
- **I**dentifiability
- **N**on-Repudiation (negativ — User KANN nicht abstreiten)
- **D**etectability
- **D**isclosure of Information
- **U**nawareness
- **N**on-Compliance

Bei PII-intensiven Systemen LINDDUN ergänzen.

## Tooling (im Bericht erwähnen)

- **Microsoft Threat Modeling Tool** — STRIDE-fokussiert, Windows-only
- **OWASP Threat Dragon** — Web-basiert, Open Source
- **IriusRisk** — Enterprise, automatisiert
- **PyTM** — Threat-Modeling-as-Code (Python)
- **Threagile** — Threat-Modeling-as-Code (YAML)

Threat-Modeling-as-Code (PyTM, Threagile) ist gut für CI-Integration: jedes Mal, wenn DFD ändert, neue Bedrohungs-Liste regeneriert.

## Output-Format für den Bericht

```
## Threat Model (extracted)

System Scope: <kurz>
Trust Boundaries: <Liste>

| ID | Threat | Category | Element | Impact | Likelihood | Mitigation Status |
|----|--------|----------|---------|--------|------------|-------------------|
| T-01 | Stolen JWT → Account-Takeover | Spoofing | API | High | Medium | Partial: HttpOnly, fehlt: short-lived + refresh-rotation |
| T-02 | SQL Injection auf Search-API | Tampering | Web-App | Critical | High | Missing: parameterized queries |
| ... |
```

Threat-Befunde sind oft "Possible" oder "Likely" (vs. "Confirmed") — das in `severity-scoring.md`-Konfidenz reflektieren.

## Mappings

- Wikipedia / Microsoft "Threats Manifesto" für Definition
- OWASP Threat Modeling Cheat Sheet
- Adam Shostack: "Threat Modeling: Designing for Security"
- NIST SP 800-154 (Data-Centric System Threat Modeling)
