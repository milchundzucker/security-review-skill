# Bericht-Template

Dieses Template definiert das Output-Format für den Security-Review-Bericht. Datei wird gespeichert als `SECURITY_REVIEW_HH:MM_YYYY-MM-DD.md` im Projekt-Root/doc.

---

# Security Review Report — {Projektname}

**Datum:** YYYY-MM-DD
**Uhrzeit:** HH:MM
**Auditor:** Claude Code (security-review skill)
**Scope:** {z. B. "Volles Repo", "Diff PR #123", "src/api/* only"}
**Frameworks:** OWASP Top 10 (2021/2025), CWE Top 25 (2024), {OWASP API Top 10}{, OWASP LLM Top 10}

---

## 1. Executive Summary

{2-5 Sätze: Was wurde geprüft, was ist der Hauptbefund, was sind die Top-Risiken.}

**Befunde nach Schwere:**

| Schwere     | Anzahl |
|-------------|--------|
| Critical    | X      |
| High        | X      |
| Medium      | X      |
| Low         | X      |
| Info        | X      |
| **Gesamt**  | **X**  |

**Befunde nach Ausnutzbarkeit:**

| Ausnutzbarkeit         | Anzahl |
|------------------------|--------|
| External-Unauth        | X      |
| External-Auth          | X      |
| Internal-Network       | X      |
| Local                  | X      |
| Supply-Chain           | X      |

**Top-3-Risiken (P0):**
1. {Befund-Titel} — {Datei:Zeile} — {Schwere} / {Ausnutzbarkeit}
2. ...
3. ...

**Gesamteinschätzung:** {z. B. "Kritische Schwachstellen vorhanden, sofortiger Hotfix erforderlich" / "Solide Grundlage mit Hardening-Bedarf" / "Keine Critical-Befunde, mehrere Medium-Findings im Bereich Auth."}

---

## 2. Scope & Methodik

**Geprüfte Bereiche:**
- {Verzeichnis 1}: {Anzahl Dateien}
- {Verzeichnis 2}: {Anzahl Dateien}

**Nicht geprüft (Begründung):**
- `tests/` — Test-Code, kein Produktionspfad
- `node_modules/` / `venv/` — Dependencies (separat geprüft)
- {weitere Ausnahmen}

**Verwendete Frameworks und Versionen:**
- OWASP Top 10 (2021 + 2025-Draft-Mapping)
- CWE Top 25 Most Dangerous Software Weaknesses (2024)
- {OWASP API Security Top 10 (2023) — wenn API-Projekt}
- {OWASP Top 10 for LLM Applications (2025) — wenn LLM-Komponenten}

**Methodik:**
1. Reconnaissance: Projektstruktur, Sprachen, Frameworks, Entry Points.
2. Pattern-Matching gegen Detection-Patterns der genannten Frameworks.
3. Kontextuelle Validation jedes Treffers (Source → Sink → Mitigation).
4. Klassifikation nach Schwere + externer Ausnutzbarkeit + Konfidenz.
5. Berichtsgenerierung mit konkreten Behebungsschritten.

**Limitierungen:**
- Statische Analyse — keine Laufzeit-Tests, keine echten Exploit-Versuche.
- Dependencies wurden gegen bekannte CVE-Liste geprüft, ohne Online-Datenbank-Abfrage. Für vollständigen CVE-Scan: `osv-scanner` / `npm audit` / `pip-audit` ausführen.
- Business-Logic-Schwachstellen, die domainspezifisches Wissen erfordern, können nur eingeschränkt erkannt werden.

---

## 3. Befundübersicht

| # | Titel | OWASP | CWE | Datei:Zeile | Schwere | Ausnutzbarkeit | Konfidenz | Prio |
|---|-------|-------|-----|-------------|---------|----------------|-----------|------|
| SEC-01 | SQL Injection in user-search endpoint | A03:2021 | CWE-89 | src/api/users.py:42 | Critical | External-Unauth | Confirmed | P0 |
| SEC-02 | IDOR in invoice fetch | API1:2023 | CWE-639 | src/api/invoices.py:88 | High | External-Auth | Confirmed | P0 |
| SEC-03 | ... | ... | ... | ... | ... | ... | ... | ... |

---

## 4. Befund-Details

### [SEC-01] SQL Injection in user-search endpoint

**OWASP:** A03:2021 — Injection
**CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command
**CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Schwere:** Critical
**Ausnutzbarkeit:** External-Unauth
**Konfidenz:** Confirmed
**Priorität:** P0

**Ort:** `src/api/users.py:42`

**Code-Evidenz:**
```python
40: @app.get("/api/users/search")
41: def search_users(name: str):
42:     query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
43:     return db.execute(query).fetchall()
```

**Beschreibung:**
Der `name`-Query-Parameter wird über f-String direkt in die SQL-Query interpoliert. Die Anwendung verwendet keinen Parameter-Binding-Mechanismus. Der Endpunkt ist unauthentifiziert und über die öffentliche API erreichbar.

**Angriffsszenario:**
Ein Angreifer ohne Account ruft auf:
```
GET /api/users/search?name=%25'--
GET /api/users/search?name=%25'+UNION+SELECT+password_hash,email,...+FROM+users--
```
Damit lassen sich beliebige Daten aus der Datenbank exfiltrieren, ggf. auch DROP TABLE ausführen, abhängig von den DB-Rechten des Service-Accounts.

**Auswirkung:**
- Vertraulichkeit: vollständige Datenbank lesbar (Critical)
- Integrität: bei Write-Rechten des DB-Users auch Manipulation möglich
- Verfügbarkeit: DoS via teure Queries oder `DROP TABLE`

**Behebung:**

```python
@app.get("/api/users/search")
def search_users(name: str):
    query = "SELECT * FROM users WHERE name LIKE :pattern"
    return db.execute(query, {"pattern": f"%{name}%"}).fetchall()
```

Zusätzlich empfohlen:
- Pydantic-Model für Input-Validation (Max-Länge, Charset-Whitelist).
- Rate-Limit auf den Endpoint (z. B. via slowapi).
- DB-User mit minimal nötigen Rechten (kein DROP, kein cross-table SELECT, wenn nicht nötig).

**Referenzen:**
- OWASP A03:2021 — Injection
- CWE-89
- OWASP Cheat Sheet — SQL Injection Prevention

---

{Wiederhole für jedes Finding. Bei sehr großen Reports kann pro Finding eine separate Datei unter `security-review/findings/SEC-XX.md` angelegt werden — in diesem Fall hier nur Titel + Link.}

---

## 5. TODO-Liste (priorisiert)

Diese Liste ist zur direkten Übernahme in das Issue-/Ticket-System geeignet.

### P0 — Sofort (Hotfix-Kandidaten)

- [ ] **[SEC-01]** SQL Injection in `src/api/users.py:42` beheben
  - Parametrisierte Query verwenden
  - Pydantic-Validation für `name`-Parameter
  - Geschätzter Aufwand: 1h
- [ ] **[SEC-02]** IDOR in `src/api/invoices.py:88` beheben
  - Owner-Check in Query: `filter_by(id=id, user_id=current_user.id)`
  - Geschätzter Aufwand: 30min
- [ ] **[SEC-03]** Hardcoded AWS Key in `src/config.py:15` rotieren
  - In AWS IAM den alten Key deaktivieren
  - Neuen Key per Secrets Manager / Env-Variable laden
  - Git-History scrubben (BFG)
  - CloudTrail auf Missbrauch prüfen
  - Geschätzter Aufwand: 2h

### P1 — Sprint-Priorität (~2 Wochen)

- [ ] **[SEC-04]** Pickle-Deserialization in `src/jobs/processor.py:120` durch JSON ersetzen
- [ ] **[SEC-05]** Fehlende CSRF-Tokens auf Web-Form-Endpoints
- [ ] **[DEP-01]** `langchain` von 0.0.140 → aktuelles Release

### P2 — Backlog (1-3 Monate)

- [ ] **[SEC-06]** Verbose Error-Responses durch generische Messages ersetzen
- [ ] **[SEC-07]** Security-Header (CSP, HSTS, X-Content-Type-Options) auf alle Responses
- [ ] **[DEP-02]** Dependency-Update-Strategie etablieren (Dependabot/Renovate)

### P3 — Hardening / Optional

- [ ] **[SEC-08]** Strukturierte Audit-Logs für Login-Versuche
- [ ] **[SEC-09]** SAST-Tool im CI integrieren (Semgrep, CodeQL)
- [ ] **[SEC-10]** SBOM-Generierung (CycloneDX) im Build-Prozess

---

## 6. Hinweise zur weiteren Untersuchung

Diese Punkte sind **keine bestätigten Befunde**, sondern Stellen, an denen ein Detection-Pattern matchte, aber Evidenz für eine konkrete Schwachstelle fehlt. Sie sollten in einem Folge-Review oder mit Domain-Wissen manuell geprüft werden.

- `src/payments/webhook.py:33` — Webhook-Endpoint hat eine Signaturprüfung, aber die Konstanten-Zeit-Vergleichsfunktion ist unklar. Bitte prüfen, ob `hmac.compare_digest` (Python) / `crypto.timingSafeEqual` (Node) verwendet wird.
- `infrastructure/terraform/main.tf:140` — S3-Bucket-Policy enthält `"Principal": "*"`, aber zusätzlich eine `Condition` mit VPC-Endpoint. Effektiv kein Public Access — aber sollte explizit kommentiert/geprüft werden.
- `src/admin/users.py:67` — Admin-Endpoint hat `@require_role('admin')`-Decorator, aber die zugrunde liegende `Role.is_admin`-Property wird durch eine Property berechnet, die auch User-Input einbezieht. Manuelle Prüfung empfohlen.

---

## 7. Dependency- und Supply-Chain-Status

### Direkte Dependencies

| Paket           | Aktuelle Version | Latest Stable | CVE-Status | Empfehlung               |
|-----------------|------------------|---------------|------------|--------------------------|
| fastapi         | 0.95.0           | 0.111.x       | OK         | Update für Bugfixes      |
| sqlalchemy      | 2.0.5            | 2.0.x         | OK         | Aktuell                  |
| langchain       | 0.0.140          | 0.x.x         | siehe DEP-01 | Update erforderlich    |

### Lock-File-Status

- ☑ `poetry.lock` vorhanden und aktuell
- ☑ Lockfile committed
- ☐ Renovate / Dependabot konfiguriert — **fehlt, empfohlen**

### Supply-Chain-Indikatoren

- ☑ Keine Dependencies aus inoffiziellen Registries
- ☑ Keine `postinstall`-Skripte mit Netzwerkzugriff
- ☐ GitHub Actions teilweise nicht SHA-pinned (siehe SEC-XX)
- ☐ SBOM-Generierung im Build — **fehlt**

---

## 8. Was geprüft wurde, was nicht

**Geprüft:**
- OWASP Top 10 (2021): A01-A10 — vollständig
- CWE Top 25 (2024): {Liste der explizit geprüften}
- OWASP API Top 10 (2023): API1-API10 — vollständig (Projekt ist API)
- Hardcoded Secrets: Pattern-Matching + Whitelist-Filter
- Dependencies: bekannte CVE-Liste

**Nicht geprüft (explizit ausgenommen):**
- Laufzeit-Verhalten / Dynamische Tests
- Penetration-Testing-Aktivitäten
- Soziale Angriffsvektoren / Operative Sicherheit
- Compliance-Mapping (PCI/HIPAA/GDPR) — auf Anfrage möglich

**Nicht geprüft (technische Limitierung):**
- Geschäftslogik-Schwachstellen ohne offensichtliche Pattern
- Zero-Days in Dependencies (nur bekannte CVEs)
- Race-Conditions ohne offensichtliches Code-Pattern

---

## 9. Scan-Metadaten

- **Datum:** YYYY-MM-DD
- **Geprüfte Dateien:** {Anzahl}
- **Sprachen:** {Liste}
- **Frameworks erkannt:** {Liste}
- **Skill-Version:** security-review v1.0
- **Dauer:** ~{Minuten}

---

## Anhang: Self-Check (Anti-Halluzinations-Verifikation)

Vor Abgabe dieses Berichts wurde folgende Checkliste durchlaufen:

- [x] Jeder Befund hat einen via `view` verifizierten Datei-Pfad + Zeilennummer
- [x] Jedes Code-Snippet ist wörtlich aus der Datei kopiert (kein paraphrasierter Code)
- [x] Keine Befunde mit "könnte" / "möglicherweise" / "eventuell" in der Befundliste (nur in "Hinweise")
- [x] Alle CVE-Nummern, falls genannt, sind belegt (keine erfundenen IDs)
- [x] CVSS-Scores sind mit vollständigem Vektor angegeben (oder weggelassen)
- [x] CWE-IDs sind nur bei klarer Zuordnung gesetzt
- [x] Konfidenz-Level für jeden Befund transparent angegeben
- [x] Bei Konfidenz "Possible": "What I checked / What I couldn't check"-Notiz vorhanden
- [x] Keine Behauptung über ungeprüfte Dateien

---

*Dieser Bericht wurde mit dem Skill `security-review` für Claude Code / Cursor / VS Code / OpenCode / Claude Desktop erstellt. Alle Befunde basieren auf konkreter Code-Evidenz und haben die 7-Punkte-Anti-Halluzinations-Checkliste bestanden. Keine spekulativen Findings in der Befundliste — alles Unklare wurde in "Hinweise zur weiteren Untersuchung" verschoben.*
