# OWASP ASVS — Application Security Verification Standard

Wird geladen, wenn ein **vollständiger Audit** (nicht nur OWASP Top 10) angefordert ist, oder bei Web-Applications mit höherem Schutzbedarf (Finanz, Healthcare, B2B-Enterprise).

ASVS v4.0/v5.0 ist der **umfassendste Web-Security-Standard von OWASP** — 280+ Anforderungen über 14 Kategorien, geordnet in drei Verifikations-Levels. Es ergänzt OWASP Top 10 um Tiefe und Breite, die für ernsthafte Audits Pflicht sind.

## Levels

| Level | Zielgruppe | Anforderungen |
|-------|-----------|----------------|
| **L1** | Alle Apps, automatisch testbar | ~80 Pflicht-Controls |
| **L2** | Sensitive Daten (Healthcare-Light, B2B, Business-Apps) | ~150 Controls |
| **L3** | High-Assurance (Finance, kritische Infrastruktur, Defense) | ~200+ Controls |

**Audit-Empfehlung:** L1 immer, L2 bei sensiblen Daten, L3 nur bei expliziter Anforderung.

---

## V1 — Architecture, Design and Threat Modeling

Strukturelle Sicherheits-Hygiene auf Architektur-Ebene.

**L1+ Checks:**
- ☐ Komponenten-Diagramm vorhanden (`README.md`, `/docs/architecture/`, etc.)
- ☐ Threat Model dokumentiert (auch informell — `THREAT_MODEL.md`, `SECURITY.md`)
- ☐ Vertrauensgrenzen klar dokumentiert
- ☐ Sicherheits-Anforderungen pro Komponente definiert
- ☐ Verifikations-Level pro Anwendung deklariert

**Code-Anzeichen für Defizite:**
- Fehlende `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY.md`
- Keine Diagramme in `/docs/`
- Kein "Security Decisions"-Log

**L2/L3-Zusätze:**
- ☐ STRIDE/PASTA/LINDDUN-Modell für sensitive Workflows
- ☐ Risiko-Register
- ☐ DPIA (DSGVO) bei PII-Verarbeitung

## V2 — Authentication

→ Tiefe Behandlung in `auth-oauth-saml.md`. ASVS-Highlights:

**L1:**
- ☐ Passwort-Mindestlänge ≥ 12 Zeichen, max ≥ 64 (Passphrasen erlauben)
- ☐ Passwort-Komplexität nicht erzwingen (NIST 800-63B), Pwned-Password-Check ja
- ☐ Argon2id / bcrypt cost ≥ 12 / scrypt — KEIN MD5/SHA1
- ☐ Brute-Force-Schutz (Rate-Limit, Lockout-mit-Vorsicht-gegen-Enumeration)
- ☐ Account-Recovery über sicheren zweiten Kanal
- ☐ Keine Default-Credentials nach Setup

**L2:**
- ☐ MFA-Option (TOTP, WebAuthn, SMS nur Fallback)
- ☐ Sichere Speicherung der MFA-Secrets (verschlüsselt, nicht in Logs)
- ☐ Re-Auth vor sensitiven Aktionen (Passwort-Change, Email-Change, Payout, Permission-Grant)

**L3:**
- ☐ MFA-Pflicht für privilegierte Accounts
- ☐ Hardware-Token-Support (FIDO2/WebAuthn)
- ☐ Credential-Stuffing-Protection (haveibeenpwned, Behavior-Analysis)
- ☐ Keine Geheimnisse in URL / Query / Referer

## V3 — Session Management

**L1:**
- ☐ Session-Token aus CSPRNG, ≥ 128 Bit Entropie
- ☐ Cookies: `Secure`, `HttpOnly`, `SameSite=Lax/Strict`
- ☐ Absolute + Idle Timeout
- ☐ Session-ID-Rotation nach Login / Privilege-Change
- ☐ Logout invalidiert Session SERVERSEITIG (nicht nur Cookie löschen)

**L2/L3:**
- ☐ Concurrent-Session-Limit / Anzeige aller aktiven Sessions
- ☐ Session-Termination aller Sessions bei Passwort-Change
- ☐ Re-Auth-Cookie separat von normalen Session-Cookie
- ☐ Keine Sessions in URLs (`?sid=...`)

```bash
rg "Set-Cookie" -i . | rg -v "HttpOnly|Secure|SameSite"  # Defizite
rg "session_destroy|destroy_session|invalidate" -i       # gut, wenn vorhanden
rg "session_regenerate_id|@session_regenerate"           # gut
```

## V4 — Access Control

→ Tiefe in `authorization-models.md`.

**L1:**
- ☐ Default-Deny (alles explizit erlauben)
- ☐ Server-seitige Autorisierung (NIE nur Client-Side)
- ☐ Direkte Objekt-Referenzen geprüft (BOLA/IDOR)
- ☐ Funktions-Level-Auth (BFLA — Admin-Routes brauchen Admin-Rolle)

**L2:**
- ☐ Multi-Tenant-Isolation (Tenant-ID in jedem Query)
- ☐ Attribute-Based Access Control wo nötig
- ☐ Audit-Log für Access-Control-Entscheidungen (zumindest Deny-Events)

**L3:**
- ☐ Row-Level Security (DB-seitig erzwungen)
- ☐ Cryptographic Sealing für kritische Resources

## V5 — Validation, Sanitization and Encoding

→ Großteil in `owasp-top10.md` A03. ASVS-Zusätze:

**L1:**
- ☐ Server-seitige Input-Validation (Client = UX, nicht Security)
- ☐ Allowlist > Denylist
- ☐ Encoding kontextspezifisch (HTML/JS/URL/CSS getrennt)
- ☐ JSON-Output mit korrektem Content-Type (`application/json`, NICHT `text/html`)
- ☐ XML-Parser mit deaktivierten DTDs (siehe `xxe-and-xml.md`)
- ☐ ReDoS-Prüfung auf alle User-steuerbaren Regex-Inputs

**L2:**
- ☐ Polyglott-Inputs gefiltert (z. B. CSV-Injection: `=cmd|...`)
- ☐ Mass-Assignment-Allowlist (Strong Parameters / Pydantic / DTOs)
- ☐ Unicode-Normalisierung vor Vergleich (NFKC)

**L3:**
- ☐ Schema-Validation für alle externen Datenformate
- ☐ Strict Mode für JSON-Parser (keine Duplicate-Keys)

```bash
rg "params\[:.*\]" --type ruby | rg -v "permit\("
rg "DocumentBuilderFactory" --type java -A 5 | rg -v "FEATURE_SECURE_PROCESSING"
```

## V6 — Cryptography

→ Tiefe in `crypto-deep-dive.md`. ASVS-Zusätze:

**L1:**
- ☐ TLS 1.2+ (besser 1.3), keine alten Ciphers (RC4, 3DES, NULL)
- ☐ Kein Self-Made-Crypto
- ☐ Key-Management: keine hardcoded Keys
- ☐ Random aus CSPRNG für alle Security-Zwecke

**L2:**
- ☐ AEAD-Verschlüsselung (AES-GCM, ChaCha20-Poly1305)
- ☐ HSM/KMS-Integration für High-Sensitivity-Keys
- ☐ Key-Rotation-Policy

**L3:**
- ☐ Cryptographic Inventory (welcher Algorithmus für was)
- ☐ Post-Quantum-Readiness-Bewertung
- ☐ Key-Ceremonies dokumentiert

## V7 — Error Handling and Logging

→ Tiefe in `logging-monitoring.md`.

**L1:**
- ☐ Keine Stack-Traces in Production-Responses
- ☐ Logging von Security-Events (Login, Auth-Changes, Privilege-Changes, Admin-Actions)
- ☐ Logs ohne Secrets (KEINE Passwörter, Tokens, PII in Logs)

**L2:**
- ☐ Strukturierte Logs (JSON für SIEM)
- ☐ Correlation-IDs / Request-IDs
- ☐ Time-Sync (NTP, UTC)
- ☐ Log-Integrität (zentrales Logging, append-only)

**L3:**
- ☐ Log-Verschlüsselung at Rest
- ☐ Tamper-Evident-Logs (Hash-Chains / Signed)
- ☐ Retention-Policy dokumentiert und durchgesetzt

## V8 — Data Protection

→ Tiefe in `privacy-compliance.md`.

**L1:**
- ☐ Sensitive Daten klassifiziert (Public / Internal / Confidential / Restricted)
- ☐ Memory-Clearing nach Crypto-Operationen (insbesondere C/C++)
- ☐ TLS-Encryption in Transit

**L2:**
- ☐ Verschlüsselung at Rest für DB / Backups
- ☐ Daten-Minimierung (DSGVO Art. 5(1)(c))
- ☐ Daten-Löschung implementiert (DSGVO Art. 17)

**L3:**
- ☐ Tokenization für hochsensible Daten (PCI: PAN)
- ☐ Client-Side-Encryption für Storage (Zero-Knowledge)
- ☐ Backup-Verschlüsselung mit separaten Keys

## V9 — Communication Security

**L1:**
- ☐ HTTPS-Pflicht (HTTP→HTTPS Redirect, HSTS Header mit `includeSubDomains; preload`)
- ☐ TLS-Cert-Validation NICHT deaktiviert (`verify=True`, `rejectUnauthorized: true`)
- ☐ Keine Mixed-Content (HTTP-Resources in HTTPS-Seite)

**L2:**
- ☐ Certificate Pinning für Mobile / kritische API-Clients (mit Rotation-Plan!)
- ☐ TLS-Configuration getestet (SSL Labs A+ oder lokales Equivalent)

**L3:**
- ☐ mTLS für Service-to-Service-Kommunikation (Zero Trust)
- ☐ Cipher-Suite-Whitelist (keine weak primitives)

```bash
rg "verify\s*=\s*False|verify\s*=\s*0" --type py
rg "rejectUnauthorized:\s*false" --type js
rg "InsecureRequestWarning|HTTPS_VERIFY=false" -i
```

## V10 — Malicious Code (Backdoors)

**L1:**
- ☐ Code-Reviews durchgeführt
- ☐ Dependencies aus vertrauenswürdigen Quellen
- ☐ Keine eval/exec von dynamischen Quellen
- ☐ Keine Debug-Backdoors

```bash
rg "if\s+.*==\s*['\"](debug|admin|test|dev|backdoor|magic)['\"]" --type py --type js
rg "TODO.*remove|FIXME.*security|HACK|XXX" -i
```

**L2/L3:**
- ☐ Signed Commits / signed Releases
- ☐ Reproducible Builds
- ☐ Two-Person-Review für kritische Komponenten

## V11 — Business Logic

→ Tiefe in `business-logic.md`.

**Alle Levels:**
- ☐ Anti-Automation (CAPTCHA, Rate-Limit) auf sensiblen Endpoints
- ☐ Workflow-Schritte können nicht übersprungen werden
- ☐ Idempotenz für kritische Operationen
- ☐ Race-Condition-Schutz auf finanziellen / quotalen Operationen
- ☐ Replay-Schutz (Timestamps, Nonces)

## V12 — File and Resources

→ Tiefe in `file-uploads-content.md`.

**L1:**
- ☐ Upload: Größe, Typ (Magic Bytes), Pfad-Validation
- ☐ Download: Authorization-Check pro Datei
- ☐ Static Files getrennt vom App-Code (nicht executable)
- ☐ Pfad-Canonicalisierung vor jedem Access

**L2:**
- ☐ AV-Scanning für User-Uploads
- ☐ Content-Disposition für Downloads
- ☐ MIME-Sniffing-Schutz (`X-Content-Type-Options: nosniff`)

**L3:**
- ☐ Sandboxing für rendering von User-Content
- ☐ Quarantäne-Bereiche für unverifizierte Uploads

## V13 — API and Web Service

→ Tiefe in `owasp-api-top10.md`. ASVS-Zusätze:

**L1:**
- ☐ JSON-/XML-Responses haben `X-Content-Type-Options: nosniff`
- ☐ HTTP-Methoden-Semantik (GET nur Read, POST/PUT/DELETE State-Changes)
- ☐ CSRF-Schutz konsistent über alle State-Changing-Endpoints
- ☐ API-Versionierung explizit

**L2:**
- ☐ GraphQL: Introspection in Prod deaktiviert, Depth-Limit, Complexity-Limit
- ☐ Webhooks: HMAC-Signatur, Replay-Schutz (Nonce + Timestamp)
- ☐ Rate-Limiting auf alle Endpoints

**L3:**
- ☐ API-Gateway mit zentralem Auth
- ☐ mTLS für interne APIs
- ☐ Schema-Registry mit Versionierung

## V14 — Configuration

**L1:**
- ☐ Hardening-Headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options/CSP-frame-ancestors, Referrer-Policy, Permissions-Policy
- ☐ Production-Mode aktiv (DEBUG=False)
- ☐ Default-Credentials geändert
- ☐ Default-Error-Pages durch generische ersetzt
- ☐ Dependencies versionspinned und aktuell

**L2:**
- ☐ Build-Reproduzierbarkeit (Lock-Files, SBOM)
- ☐ Unbenutzte Features deaktiviert
- ☐ Configuration-Drift-Detection

**L3:**
- ☐ Immutable Infrastructure
- ☐ SLSA-Level 3+ für Build-Pipeline
- ☐ Configuration-as-Code mit Audit-Trail

```bash
rg "Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options" -i .
rg "helmet\(\)|secure_headers|@SecurityHeaders" -i
rg "DEBUG\s*=\s*True|debug:\s*true" -i
```

---

## ASVS im Bericht ausweisen

Im **Deep-Audit-Modus** im Bericht-Anhang eine **ASVS-Compliance-Matrix** ergänzen:

| ASVS | Kategorie | L1-Checks | L1-Erfüllt | L2-Checks | L2-Erfüllt | Defizit-IDs |
|------|-----------|-----------|------------|-----------|------------|-------------|
| V2   | Authentication | 6 | 4 | 4 | 2 | SEC-04, SEC-05, SEC-12 |
| V3   | Session Mgmt | 5 | 3 | 4 | 4 | SEC-07, SEC-08 |
| V4   | Access Control | 4 | 2 | 3 | 2 | SEC-15, SEC-22 |
| ...  | ...      | ...| ...| ...| ...| ...                    |

So bekommt der Kunde eine **echte Compliance-Sicht** statt nur einer Bug-Liste.

---

## ASVS-Schnellanwendung im Audit-Workflow

1. **Im Recon (Phase 1):** Bestimme das ASVS-Level basierend auf Schutzbedarf:
   - Marketing-Site / Blog → L1
   - Standard-SaaS / Business-App → L2
   - Banking, Healthcare, kritische Infrastruktur → L3

2. **In Phase 2:** Bei jeder OWASP-Top-10-Pattern-Suche zusätzlich ASVS-spezifische Anforderungen prüfen, die im Top 10 fehlen (z. B. V1-Architecture, V8-Data-Classification, V14-Hardening-Headers).

3. **In Phase 5:** ASVS-Matrix als Anhang.

**Wichtig:** ASVS-Coverage ersetzt keine vollständige formale Verifikation — ein automatisierter Code-Scan kann nicht alle Anforderungen prüfen (z. B. "Threat Model dokumentiert" ist eine prozessuale Anforderung). Diese werden im Bericht als "manueller Prüfschritt empfohlen" markiert.
